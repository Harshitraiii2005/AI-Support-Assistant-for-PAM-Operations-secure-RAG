"""Security layer: secret/PII redaction and prompt-injection detection.

Redaction runs on every piece of text BEFORE it can reach the LLM (questions, pasted logs,
ingested documents) and again on the LLM output. Detection is layered:

1. Structured patterns (PEM keys, JWTs, bearer/basic auth, cloud key prefixes, URL
   credentials, ``password=`` style key/value pairs, ``-newpass`` CLI arguments).
2. Network identifiers (IPv4, full-form IPv6, FQDNs, internal ``.local``/``.corp`` names).
3. A Shannon-entropy fallback for long random-looking strings with no keyword around them.

Placeholders are numbered per value (``[PASSWORD_1]``, ``[HOST_2]``) so the model can still
reason about "the same host" without seeing it. ``Finding`` deliberately stores no values,
so findings are safe to log.

Prompt-injection detection is a regex heuristic: it catches the common phrasings and is
backed by structural controls elsewhere (secrets never reach the model, RBAC is enforced
in the vector DB, output is re-checked). It is not a complete defense on its own.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

SECRET_KINDS = frozenset({"private_key", "token", "api_key", "password", "secret"})
NETWORK_KINDS = frozenset({"ip", "hostname"})
ALL_KINDS = SECRET_KINDS | NETWORK_KINDS

_PLACEHOLDER_LABEL = {
    "private_key": "PRIVATE_KEY", "token": "TOKEN", "api_key": "API_KEY",
    "password": "PASSWORD", "secret": "SECRET", "ip": "IP", "hostname": "HOST",
}
_PW_KEYS = r"pass(?:word|wd|phrase)?|pwd|secret|client[_-]?secret|credentials?"
_KEY_KEYS = r"api[_-]?key|apikey|access[_-]?key(?:[_-]?id)?|secret[_-]?access[_-]?key"
_TOKEN_KEYS = r"(?:auth[_-]?|access[_-]?|refresh[_-]?|session[_-]?)?token|cookie"

# (kind, pattern). If a pattern has a group named "v" only that group is masked, so the
# surrounding key stays readable: "password=[PASSWORD_1]". Order = priority on overlap.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("token", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")),
    ("token", re.compile(r"(?i)\b(?:bearer|basic)\s+(?P<v>[A-Za-z0-9._~+/=-]{8,})")),
    ("api_key", re.compile(
        r"\b(?:(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}"
        r"|glpat-[A-Za-z0-9_-]{20}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}"
        r"|sk-[A-Za-z0-9_-]{20,})")),
    ("password", re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s:/@]+:(?P<v>[^\s@/]+)@")),
    ("api_key", re.compile(
        rf"(?i)\b(?:{_KEY_KEYS})[\"']?\s*[:=]\s*[\"']?(?P<v>[^\s\"',;]+)")),
    ("token", re.compile(
        rf"(?i)\b(?:{_TOKEN_KEYS})[\"']?\s*[:=]\s*[\"']?(?P<v>[^\s\"',;]+)")),
    ("password", re.compile(
        rf"(?i)\b(?:{_PW_KEYS})[\"']?\s*=\s*[\"']?(?P<v>[^\s\"',;]+)")),
    # "password: X" is also common prose ("new password: the platform's..."), so after a
    # colon the value must contain a digit or symbol to count
    ("password", re.compile(
        rf"(?i)\b(?:{_PW_KEYS})[\"']?\s*:\s*[\"']?(?P<v>(?=[^\s\"',;]*[\d!@#$%^&*_+=?~])"
        r"[^\s\"',;]+)")),
    # CLI arguments: -newpass X, --password X, /password:X
    ("password", re.compile(
        r"(?i)(?:^|\s)(?:--?|/)(?:old|new|current)?(?:pass(?:word)?|pwd)(?:[:=]|\s+)(?P<v>\S+)")),
    # prose: "with password 'X'", "password is 'X'", "the password for root is X"
    ("password", re.compile(
        rf"(?i)\b(?:{_PW_KEYS})\s*(?:\bis\b|\bwas\b)?\s*(?P<q>['\"])(?P<v>[^'\"\n]{{4,}})(?P=q)")),
    ("password", re.compile(
        rf"(?i)\b(?:{_PW_KEYS})\b[^\n.]{{0,30}}?\b(?:is|was)\s+"
        r"(?P<v>(?=\S*[\d!@#$%^&*])[^\s\"',;]{6,})")),
    ("ip", re.compile(
        r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")),
    ("ip", re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b")),
    ("hostname", re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){2,}[A-Za-z]{2,63}\b")),
    ("hostname", re.compile(
        r"(?i)\b[a-z0-9][a-z0-9-]*\.(?:local|lan|internal|intra|corp|example|localdomain)\b")),
]

_ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9+/_\-!#$%&*?@^=.~]{16,}")
_ENTROPY_MIN_BITS = 3.5  # bits per character
_PLACEHOLDER = re.compile(rf"\[(?:{'|'.join(_PLACEHOLDER_LABEL.values())})_\d+\]")


@dataclass(frozen=True)
class Finding:
    kind: str
    placeholder: str
    start: int  # span in the ORIGINAL text, for before/after highlighting
    end: int


@dataclass(frozen=True)
class Redacted:
    text: str
    findings: list[Finding]

    def counts(self) -> dict[str, int]:
        return dict(Counter(f.kind for f in self.findings))


def shannon_entropy(s: str) -> float:
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def _looks_random(s: str) -> bool:
    return (
        any(c.isalpha() for c in s)
        and any(c.isdigit() for c in s)
        and shannon_entropy(s) >= _ENTROPY_MIN_BITS
    )


def redact(text: str, kinds: frozenset[str] = ALL_KINDS) -> Redacted:
    """Mask secrets and network identifiers. Same value -> same placeholder."""
    spans: list[tuple[int, int, str]] = []
    for kind, pattern in _PATTERNS:
        if kind not in kinds:
            continue
        for m in pattern.finditer(text):
            group = "v" if "v" in pattern.groupindex else 0
            start, end = m.start(group), m.end(group)
            if text[end - 1] == "." and end - start > 1:
                end -= 1  # sentence-ending period, not part of the value
            spans.append((start, end, kind))
    if "secret" in kinds:
        for m in _ENTROPY_CANDIDATE.finditer(text):
            if _looks_random(m.group().strip(".")):
                spans.append((m.start(), m.end(), "secret"))

    # keep earliest-listed pattern on overlap: spans were appended in priority order
    taken: list[tuple[int, int, str]] = []
    for span in spans:
        if not any(span[0] < end and start < span[1] for start, end, _ in taken):
            taken.append(span)
    taken.sort()

    placeholders: dict[tuple[str, str], str] = {}
    per_kind: Counter[str] = Counter()
    out, findings, cursor = [], [], 0
    for start, end, kind in taken:
        value = text[start:end]
        if _PLACEHOLDER.fullmatch(value):
            continue
        if (kind, value) not in placeholders:
            per_kind[kind] += 1
            placeholders[(kind, value)] = f"[{_PLACEHOLDER_LABEL[kind]}_{per_kind[kind]}]"
        placeholder = placeholders[(kind, value)]
        out.append(text[cursor:start] + placeholder)
        findings.append(Finding(kind, placeholder, start, end))
        cursor = end
    out.append(text[cursor:])
    return Redacted("".join(out), findings)


# ---------------------------------------------------------------- prompt injection

_INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "override_instructions": re.compile(
        r"(?i)\b(?:ignore|disregard|forget|override|bypass|skip)\b[^.\n]{0,40}?"
        r"\b(?:previous|prior|above|earlier|preceding|all|any|your|the|system|safety)\b[^.\n]{0,20}?"
        r"\b(?:instructions?|prompts?|rules|directives|guidelines|guardrails|context)\b"),
    "role_hijack": re.compile(
        r"(?i)\b(?:you are now|from now on,? you|pretend (?:to be|you are)|act as (?:an? |the )?"
        r"(?:admin|administrator|root|system|developer|unrestricted|jailbroken)|developer mode"
        r"|jailbreak|do anything now)\b"),
    "system_prompt_probe": re.compile(
        r"(?i)\b(?:reveal|print|show|repeat|output|display|tell me|dump|leak)\b[^.\n]{0,20}?"
        r"\b(?:your|the)\s+(?:system|initial|hidden|original|secret)\s+"
        r"(?:prompt|instructions?|message|rules)\b"),
    "secret_exfiltration": re.compile(
        r"(?i)\b(?:reveal|print|output|dump|leak|exfiltrate|send|repeat|restore|un-?mask)\b"
        r"[^.\n]{0,40}?\b(?:unredacted|original|raw|real|actual|plain-?text|clear-?text|masked)\b"
        r"[^.\n]{0,20}?\b(?:passwords?|secrets?|credentials?|values?|tokens?|keys?|logs?)\b"),
    "instruction_to_model": re.compile(
        r"(?i)\b(?:note|message|instruction)s?\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|model|llm|"
        r"copilot|chatbot)\b|\b(?:ai|assistant|model|llm|copilot)\s+(?:must|should|shall)\s+"
        r"(?:now|always|instead)\b|\b(?:new|updated|additional)\s+(?:system\s+)?instructions?\s*:"),
    "forced_output": re.compile(
        r"(?i)\b(?:respond|reply|answer|say)\b[^.\n]{0,15}?\b(?:only|exactly)\b[^.\n]{0,15}?"
        r"(?:with|\")"),
    "chat_markup": re.compile(
        r"(?im)<\|(?:im_start|im_end|system|user|assistant)\|>|\[/?INST\]|<<SYS>>"
        r"|^\s*#{0,3}\s*(?:system|assistant)\s*:|</?\s*source\b"),
}


def detect_injection(text: str) -> list[str]:
    """Names of the injection heuristics that match ``text`` (empty list = clean)."""
    return [name for name, pattern in _INJECTION_PATTERNS.items() if pattern.search(text)]


def neutralize(text: str) -> str:
    """Strip markup that could close our <source> delimiters or fake a chat turn."""
    return _INJECTION_PATTERNS["chat_markup"].sub("[markup removed]", text)
