"""Log diagnosis: redact -> strip injected lines -> classify -> runbook -> grounded fix.

Confidence comes from the deterministic classification step, never from the LLM grading
itself (LLM self-reported confidence is poorly calibrated):
- high: an error code in the log is documented in a runbook's front matter
- low:  no known code; best runbook by embedding similarity of the error lines. There is
        no "medium": on held-out simulated logs the similarity score did not separate right
        from wrong matches (wrong 0.71-0.77, right median 0.77), so a score-based tier
        would be a fake signal. Low-confidence fixes tell the operator to confirm the match.
- none: nothing similar enough -> no fix is generated, the operator is told to escalate
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Literal

from pam_copilot.kb import Runbook
from pam_copilot.rag import Citation, Copilot, Role
from pam_copilot.security import Finding, detect_injection, neutralize, redact

CODE_RE = re.compile(r"\bSIM-(?:CPM|PSM|PVWA|VLT)-\d{4}\b")
REMOVED_LINE = "[line removed: possible prompt injection]"
Confidence = Literal["high", "low", "none"]

DIAGNOSE_TEMPLATE = """An operator pasted this log. It has already been redacted.
<log>
{log}
</log>
Classification: {basis}.

Using only the sources above, write:
1. **Likely cause** - one or two sentences.
2. **Fix** - numbered steps for a first-level operator.
3. **Verify** - how to confirm the fix worked.
4. **Escalate if** - when to escalate and to whom.
Cite the sources like [1] after every step. If the sources do not cover this error, \
reply exactly INSUFFICIENT_CONTEXT."""

NO_MATCH = ("No approved runbook matches this log closely enough, so no fix is suggested. "
            "Escalate to PAM L2 with the redacted log extract (see RB-019).")
ADMIN_ONLY = ("{code} is handled by PAM admins ({rb_id} {title}). Do not attempt a fix at "
              "first level: escalate to PAM L2 with the component, error code, time window "
              "and the redacted log extract shown here (see RB-019).")


@dataclass
class Diagnosis:
    request_id: str
    error_code: str | None
    runbook_id: str | None
    runbook_title: str | None
    confidence: Confidence
    score: float
    basis: str
    answer: str
    refused: bool
    reason: str | None
    escalate: bool
    redacted_input: str
    redactions: list[Finding]
    injection_flags: list[str]
    removed_lines: list[int]
    citations: list[Citation] = field(default_factory=list)


def _error_codes(lines: list[str]) -> list[str]:
    on_error_lines = [c for line in lines if "ERROR" in line.upper() for c in CODE_RE.findall(line)]
    return on_error_lines or [c for line in lines for c in CODE_RE.findall(line)]


def classify(cp: Copilot, lines: list[str], role: Role
             ) -> tuple[str | None, Runbook | None, Confidence, float, str]:
    """Map redacted log lines to (code, runbook, confidence, score, human-readable basis)."""
    codes = _error_codes(lines)
    code = codes[0] if codes else None
    rb: Runbook | None = cp.runbook_for_code.get(code) if code else None
    if rb:
        return code, rb, "high", 1.0, f"exact error code {code}, documented in {rb.id} ({rb.title})"
    # no known code: rank runbooks by similarity to the error lines (role-filtered, so an
    # operator can't be matched to admin-only content)
    error_lines = [ln for ln in lines if re.search(r"ERROR|FAIL|WARN", ln)] or lines
    hits = [h for h in cp.retriever.search("\n".join(error_lines)[:2000], role)
            if h.metadata.get("runbook_id")]
    score = hits[0].score if hits else 0.0
    if not hits or score < cp.settings.min_score:
        return code, None, "none", score, "no known error code and no similar runbook"
    rb = cp.runbooks[hits[0].metadata["runbook_id"]]
    unknown = f"code {code} is not in the knowledge base; " if code else "no error code; "
    return (code, rb, "low", score,
            f"{unknown}closest runbook by similarity is {rb.id} (score {score:.2f}); "
            "confirm it matches before acting")


def diagnose(cp: Copilot, log: str, *, role: Role, user: str) -> Diagnosis:
    started = time.perf_counter()
    red = redact(log)
    lines, removed, flags = red.text.splitlines(), [], set()
    for i, line in enumerate(lines):
        if found := detect_injection(line):
            flags.update(found)
            removed.append(i + 1)
            lines[i] = REMOVED_LINE
    clean = neutralize("\n".join(lines))

    code, rb, confidence, score, basis = classify(cp, lines, role)
    result = Diagnosis(
        uuid.uuid4().hex[:12], code, rb.id if rb else None, rb.title if rb else None,
        confidence, round(score, 4), basis, "", True, None, True, red.text, red.findings,
        sorted(flags), removed,
    )
    if rb is None:
        result.reason, result.answer = "no_matching_runbook", NO_MATCH
    elif rb.audience == "admin" and role != "admin":
        result.reason = "admin_only_runbook"
        result.answer = ADMIN_ONLY.format(code=code or "This error", rb_id=rb.id, title=rb.title)
    else:
        hits = cp.retriever.runbook_chunks(rb.id, role)
        result.answer, result.citations, result.reason = cp.generate(
            DIAGNOSE_TEMPLATE.format(log=clean, basis=basis), hits,
            originals=[log[f.start:f.end] for f in red.findings])
        result.refused = result.reason is not None
        if result.refused:
            result.answer = NO_MATCH
        result.escalate = result.refused
    cp.record("diagnose", result, role=role, user=user, started=started)
    return result
