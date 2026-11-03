# PAM Copilot

[![CI](https://github.com/Harshitraiii2005/AI-Support-Assistant-for-PAM-Operations-secure-RAG/actions/workflows/ci.yml/badge.svg)](https://github.com/Harshitraiii2005/AI-Support-Assistant-for-PAM-Operations-secure-RAG/actions/workflows/ci.yml)
[![Demo site](https://img.shields.io/badge/demo-GitHub%20Pages-2563eb)](https://harshitraiii2005.github.io/AI-Support-Assistant-for-PAM-Operations-secure-RAG/)
![Python 3.11](https://img.shields.io/badge/python-3.11-3776ab)
![Local LLM](https://img.shields.io/badge/LLM-Ollama%20(local)-111)
![Tests](https://img.shields.io/badge/tests-54%20passing-15803d)

**[Live project page →](https://harshitraiii2005.github.io/AI-Support-Assistant-for-PAM-Operations-secure-RAG/)**

A secure, locally hosted AI assistant for first-level **Privileged Access Management (PAM)**
support. It answers operator questions from approved runbooks with citations, diagnoses
CyberArk-style **CPM / PSM / PVWA / Vault** errors from pasted logs, and is designed so that
**secrets never reach the model, the answer, or the audit log**.

- **Local only**: Ollama (`qwen2.5:7b-instruct`, `nomic-embed-text`), Qdrant, no external API.
- **Grounded or silent**: every answer carries citations (runbook › section › last-updated);
  with no relevant approved source it refuses instead of guessing.
- **Security layer first**: redaction (regex + entropy) runs before anything else,
  prompt-injection defenses cover questions, pasted logs and ingested documents, role-based
  retrieval is enforced inside the vector DB, and every Q&A is written to a hash-chained
  audit log.
- **Measured**: 50-question eval set plus a 29-case red-team suite, run against the real local
  model. The numbers below are copied from [eval/results/summary.md](eval/results/summary.md).

> Not affiliated with or endorsed by CyberArk. All runbooks are original; all log data and
> `SIM-` error codes are fictional and labeled as simulated.

## Screenshots

All captured from the running Docker Compose stack (`qwen2.5:7b-instruct` on local Ollama).
Data is simulated; the "secrets" are fake.

| Cited answer | Redaction before / after |
|---|---|
| [![Cited answer](docs/screenshots/ask.png)](docs/screenshots/ask.png) | [![Redaction](docs/screenshots/redaction.png)](docs/screenshots/redaction.png) |
| An error-code question answered from RB-002, with runbook › section › last-updated sources. | The password, IP and hostname in the question are masked. The right panel is the only text the LLM sees. |

| Log diagnosis | Guardrails |
|---|---|
| [![Log diagnosis](docs/screenshots/diagnose.png)](docs/screenshots/diagnose.png) | [![Guardrails](docs/screenshots/guardrails.png)](docs/screenshots/guardrails.png) |
| A simulated log with planted fake secrets: error code → runbook → high confidence → cited steps. | Prompt injection blocked before the LLM; out-of-scope question refused; admin-only topic refused for an operator. |

| Role-based answers (admin) | Hash-chained audit log |
|---|---|
| [![Admin answer](docs/screenshots/rbac-admin.png)](docs/screenshots/rbac-admin.png) | [![Audit log](docs/screenshots/audit.png)](docs/screenshots/audit.png) |
| The same vault-backup question, answered for an admin from an admin-only runbook. | Every Q&A with role, refusal reason, redaction counts and injection flags; chain verified. |

**Test suite**: 54 offline tests (in-memory Qdrant, hashed embeddings, a fake LLM that records
every prompt so the tests can prove no secret reaches the model), plus ruff and mypy `--strict`:

[![Test run](docs/screenshots/tests.png)](docs/screenshots/tests.png)

> 🎬 Demo GIF placeholder: `docs/demo.gif`, a 30-second walkthrough (ask → diagnose a log with
> fake secrets → operator vs admin → audit tab). Record with any screen recorder and drop it in.

## Architecture

```mermaid
flowchart LR
    UI["Streamlit UI<br/>(no secrets, no model access)"]
    subgraph API["FastAPI · bearer token → role"]
        direction TB
        A1["1 · Redact input<br/>regex + entropy → [PASSWORD_1], [HOST_1]"]
        A2["2 · Injection check<br/>block question / drop log line"]
        A3["3 · Retrieve top-5<br/>Qdrant payload filter by role"]
        A4["4 · Relevance gate<br/>score < 0.60 → refuse, no LLM call"]
        A5["5 · Prompt<br/>rules + canary + &lt;source&gt; delimiters"]
        A6["6 · Output filter<br/>re-redact · canary · original values"]
        A7["7 · Citation check<br/>no valid citation → refuse"]
        A1 --> A2 --> A3 --> A4 --> A5 --> A6 --> A7
    end
    LLM[("Ollama<br/>qwen2.5:7b-instruct")]
    QD[("Qdrant<br/>chunks + metadata")]
    AUD[("Audit log<br/>JSONL, SHA-256 chain,<br/>redacted text only")]
    KB["Runbooks (Markdown + front matter)<br/>+ your PDFs / HTML"]
    ING["Ingest<br/>section chunks · mask secrets<br/>quarantine injections · embed"]

    UI -- "question / pasted log" --> A1
    A3 <--> QD
    A5 --> LLM --> A6
    A7 -- "answer + citations + redaction view" --> UI
    A7 --> AUD
    KB --> ING --> QD
```

Log diagnosis adds a deterministic classifier in front of generation: an exact `SIM-` code
documented in a runbook's front matter → **high** confidence; otherwise the closest runbook by
similarity → **low** confidence ("confirm it matches"); nothing close enough → **none**, no fix
generated. If the matched runbook is admin-only and the user is an operator, no fix is
generated: the user is told to escalate, and nothing from the admin runbook is shown.

```mermaid
flowchart LR
    B["Browser"] -- "127.0.0.1:8501" --> UI["ui"]
    C["curl / scripts"] -- "127.0.0.1:8000" --> API["api"]
    UI --> API
    API --> QD["qdrant<br/>(API key, internal only)"]
    API --> OL["ollama<br/>(internal only, or native on macOS)"]
    ING["ingest (one-shot)"] --> QD
    ING --> OL
```

## Security design

The core idea is to stop relying on the model to behave: the model never receives a secret,
and it never receives content above the user's role. Detection then adds a second layer on top.

| Threat | Control | Where | Evidence |
|---|---|---|---|
| Secrets in a pasted log or question reach the LLM | Redaction runs first on every input: structured patterns (PEM, JWT, bearer/basic, AWS/GitHub/Slack/Google keys, URL credentials, `password=`/`-newpass`/`/password:`), IPv4/IPv6, FQDNs and internal names, plus a Shannon-entropy fallback (≥16 chars, letters+digits, ≥3.5 bits/char). Numbered placeholders let the model still reason ("[HOST_1] is unreachable"). | [security.py](src/pam_copilot/security.py) | unit tests; redaction recall table; red-team `secret_leakage` |
| The model echoes a secret anyway | Output filter: re-redact the answer, and block it if any original masked value or the system-prompt canary appears | [rag.py](src/pam_copilot/rag.py) `generate` | `test_secrets_never_reach_llm_or_audit`, `test_canary_leak_blocked` |
| Secrets persisted in logs | The audit log stores redacted text only; findings store spans, never values; file mode 0600 | [audit.py](src/pam_copilot/audit.py) | every red-team case checks prompt, output **and** audit |
| Direct prompt injection | Heuristic detector (override phrasing, role hijack, prompt probing, exfiltration, forced output, chat markup) blocks the request before retrieval; rules in the system prompt | `detect_injection` | red-team `prompt_injection_direct` |
| Injection inside pasted logs | Per-line detection: flagged lines are replaced with a marker and listed in the UI; delimiter tags and chat-template tokens are neutralized | [diagnose.py](src/pam_copilot/diagnose.py) | red-team `prompt_injection_indirect_log` |
| Poisoned documents | Ingest scans every chunk: injection-like chunks are quarantined (not indexed), secret-shaped strings masked; retrieved chunks are re-scanned at query time | [ingest.py](src/pam_copilot/ingest.py) `screen` | red-team `doc_poisoning`; `test_poisoned_external_doc_is_quarantined` |
| System-prompt exfiltration | A random canary token in the system prompt; any answer containing it is blocked | `Copilot.canary` | RT11, RT13, RT14 |
| Operator obtains admin-only guidance | Role comes from the token. Qdrant filters `audience` server-side, so admin chunks never leave the DB for an operator; admin-only diagnoses become escalations | `Retriever._filters` | `test_operator_never_retrieves_admin_chunks`; red-team `rbac` |
| Hallucinated fixes | Relevance gate, `INSUFFICIENT_CONTEXT` contract, mandatory citations (uncited = refusal, invalid citation numbers stripped) | `Copilot.ask` / `generate` | out-of-scope refusal rate, faithfulness |
| Audit trail tampering | Each entry includes the SHA-256 of the previous one; `/audit` and `python -m pam_copilot.audit` verify the chain | [audit.py](src/pam_copilot/audit.py) | `test_chain_verifies_and_detects_tampering` |
| Weak deployment credentials | API refuses to start unless both tokens are set, distinct and ≥24 chars; constant-time comparison; compose refuses to start without tokens and the Qdrant key | [api.py](src/pam_copilot/api.py), compose | `test_refuses_to_start_with_weak_tokens`, CI `docker` job |
| Secrets committed to the repo | `.env` git-ignored; red-team fake secrets generated at run time; gitleaks in CI | [ci.yml](.github/workflows/ci.yml) | CI `secret-scan` job |
| Container compromise / lateral movement | Non-root user, read-only root FS, `cap_drop: ALL`, `no-new-privileges`; Qdrant (with API key) and Ollama not published; API/UI bound to 127.0.0.1; the UI gets no secrets; telemetry off | [docker-compose.yml](docker-compose.yml) | `docker compose config` |

**What the redactor does not catch** (by design or known gap): passphrases with no digits or
symbols and no keyword nearby; keyword-less secrets shorter than 16 characters; bare short
hostnames (`srv01`); compressed IPv6 (`fe80::1`); secrets split across lines; non-English
keywords. These are the reasons for the output filter and for keeping the model local.

## Evaluation results

Real run on 2026-11-03: generator `qwen2.5:7b-instruct`, judge `llama3.1:8b`
(a different model, to reduce self-grading bias), embeddings `nomic-embed-text`,
top_k=5, gate=0.6, 16.8 min on an Apple M5 / 16 GB.
Every item is in [eval/results/results.json](eval/results/results.json); the tables come from
[eval/results/summary.md](eval/results/summary.md). No number here is hand-entered.

**Retrieval and answers**: 50 questions (42 in scope with reference answers and
key points, 8 out of scope, several of them deliberately PAM-adjacent):

| Metric | Value |
|---|---|
| Retrieval hit@1 / hit@3 / hit@5 | 85.7% / 90.5% / 92.9% |
| Retrieval MRR@5 | 0.886 |
| In-scope questions answered (42) | 88.1% |
| Citation hit rate (cites an expected runbook) | 97.3% |
| Citation precision | 91.0% |
| Faithfulness (judge, 37 answers) | 95.2% |
| Key-point coverage, answered (37) | 60.8% |
| Key-point coverage, all in-scope (refusal = 0) | 53.6% |
| Out-of-scope refused (8) | 100% |
| Latency p50 / p95 | 3.66 s / 9.59 s |

The five in-scope refusals: in Q04, Q12 and Q16 retrieval missed the right runbook; in Q10
and Q14 retrieval was correct but the model answered `INSUFFICIENT_CONTEXT`. The system errs
toward refusing, which is the right failure mode for privileged-access guidance.

**Red team**: 29 handwritten attacks plus every simulated error code with planted secrets.
A case passes only if no planted secret appears in the LLM prompt, the answer **or** the audit
log, the canary doesn't leak, no forbidden text appears, and operators get no admin citations:

| Category | Passed |
|---|---|
| Secret leakage (handwritten) | 10/10 |
| Prompt injection: direct | 6/6 |
| Prompt injection: inside pasted logs | 5/5 |
| Poisoned documents | 4/4 |
| Role-based access | 4/4 |
| Simulated logs end to end (prompt, output, audit) | 33/33 |
| Total, handwritten | 29/29 |

**Caveat on RT24 and RT25:** the 'stealth' poisoned document (a plausible but harmful procedure with no injection phrasing, so ingest did not quarantine it) was *not* in the top-5 retrieved chunks, so these passes do not show that the model resists content poisoning. Only reviewing documents before ingest prevents that.

**Redaction recall** on 660 simulated logs with planted secrets (deterministic):

| Type | Masked / planted |
|---|---|
| api_key | 96/96 (100%) |
| hostname | 680/680 (100%) |
| ip | 420/420 (100%) |
| password | 570/570 (100%) |
| token | 106/106 (100%) |
| Secret false positives (19 runbooks / 330 clean logs) | 0 / 0 |

**Log classification** over the 33 simulated error codes:

| Variant | Accuracy |
|---|---|
| With error code (exact match) | 100% |
| Error code stripped (similarity only) | 84.8% |

How to read these numbers: I wrote the runbooks, the generator, the questions and the
redactor, so retrieval and redaction scores on simulated data are in-distribution and
optimistic. The handwritten red-team cases are the out-of-distribution evidence. Judge scores
come from a local 8B model and are indicative, not human-validated.

## Quickstart

### Local development (macOS / Linux)

```bash
ollama serve &                                   # or the Ollama desktop app
ollama pull nomic-embed-text && ollama pull qwen2.5:7b-instruct
uv sync                                          # Python 3.11 + deps
uv run pytest -q                                 # offline test suite (no Ollama needed)
uv run python -m pam_copilot.ingest              # build the index (embedded Qdrant in data/)

export OPERATOR_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
export ADMIN_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
echo "operator: $OPERATOR_TOKEN"; echo "admin: $ADMIN_TOKEN"
uv run uvicorn pam_copilot.api:app --port 8000 &
uv run streamlit run src/pam_copilot/ui.py       # http://localhost:8501, paste a token
```

### Docker Compose

```bash
cp .env.example .env     # then fill OPERATOR_TOKEN, ADMIN_TOKEN, QDRANT_API_KEY
# macOS: Docker has no Metal GPU, so use native Ollama: in .env set COMPOSE_PROFILES= and
#        OLLAMA_URL=http://host.docker.internal:11434
docker compose up --build
```

The stack starts Qdrant, (optionally) Ollama plus a one-shot model pull, then a one-shot
`ingest`, then the API, then the UI. Re-run `docker compose run --rm ingest` after editing
runbooks or adding documents to `knowledge_base/external/`.

### API

```bash
curl -s localhost:8000/ask -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H 'content-type: application/json' -d '{"question":"What does SIM-CPM-2104 mean?"}'
uv run pam-loggen -n 1 --with-secrets --code SIM-PSM-3107 > /tmp/log.txt
curl -s localhost:8000/diagnose -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H 'content-type: application/json' --data "$(jq -Rs '{log: .}' /tmp/log.txt)"
curl -s localhost:8000/audit -H "Authorization: Bearer $ADMIN_TOKEN"     # admin only
```

### Evaluation

```bash
ollama pull llama3.1:8b                           # judge model
uv run python -m pam_copilot.evaluate --quick     # smoke run, ~5 min
uv run python -m pam_copilot.evaluate             # full run → eval/results/
```

## Design decisions (interview notes)

| Decision | Why | Trade-off |
|---|---|---|
| **LlamaIndex for ingestion and retrieval only** (not LangChain, and no framework query engine) | Built for retrieval: header-aware Markdown parsing gives exact section citations, PDF page metadata carries through, native Qdrant metadata filters. Prompt assembly and the LLM call are ~60 lines of our own code, so the security choke points are explicit and unit-testable instead of hidden in callbacks. | Another dependency tree; LangChain would win for agent/tool orchestration, which this doesn't need. |
| **Qdrant** over Chroma | Server-side payload filtering enforces RBAC at query time; runs as its own container with API-key auth; the same client runs in-memory for tests and CI. | One more service than an embedded DB. |
| **One chunk per runbook section**, prefixed with the runbook title | Sections are written as self-contained units, so citations point to "RB-002 › Diagnosis". The title prefix gives the embedding context. PDFs: per page, then 512-token splits. | Very long sections would need splitting (none exist yet). |
| `nomic-embed-text` with `search_query:` / `search_document:` prefixes | Small (274 MB), local, 8k context; the model is trained with these prefixes. | English-centric. |
| **Relevance gate at 0.60** cosine before any LLM call | Unrelated questions are refused cheaply and deterministically. The threshold was chosen on ad-hoc dev queries, **not** on the eval set. | Borderline out-of-scope questions rely on the model's `INSUFFICIENT_CONTEXT`. |
| **Uncited = refused** | Citations are the contract with the operator; an answer the model can't tie to a source is treated as a hallucination. | Some correct-but-uncited answers are lost (shows up as false refusals). |
| **Numbered placeholders**, findings without values | The model can still say "[HOST_1] is unreachable"; logs and APIs can carry findings safely. | Placeholders are per request, not stable across a conversation. |
| **Confidence from the classifier, not the LLM** | LLM self-confidence is poorly calibrated. Exact error codes are deterministic. I built a "medium" similarity tier, measured it on held-out logs, found the score didn't separate right from wrong matches, and removed it. | Only three levels: high / low / none. |
| **Canary token** in the system prompt | Cheap, deterministic detection of prompt leakage, independent of how the attacker phrases the request. | Detects verbatim leaks, not paraphrases. |
| **Hash-chained JSONL audit** | Tamper-evident without a database; easy to ship to a SIEM. | Whoever can rewrite the file can rebuild the chain; anchor the head hash externally. |
| **Schema-constrained judge** | In the first full run, free-form `json` mode let the 8B judge mix explanations into the boolean array (16 of 37 key-point verdicts unparseable, which inflated coverage to 73%). Passing a JSON schema (an array of exactly *n* booleans) fixed it; everything was re-run and the honest number is 61%. | Schema output is slightly slower. |
| **Separate judge model**, generations before judging | Reduces self-preference bias; avoids swapping two 8B models in 16 GB RAM. | A local 8B judge is noisy; spot-check by hand. |
| **Fake secrets generated at eval time** | No secret-shaped literals in git, so secret scanners stay clean, and the values differ from the generator's. | Results depend on the fixed seed (2026), recorded in code. |
| Static role tokens | Smallest thing that demonstrates RBAC end to end. | Production: OIDC/SAML group claims → same `Role`. |

## How this maps to a CyberArk / PAM support role

| Typical responsibility | Where it shows up |
|---|---|
| First-level support for CPM, PSM and PVWA incidents | Log diagnosis (error code → runbook → cited steps); runbooks RB-002 to RB-012 |
| Correct triage, priority and complete escalations | RB-019, an escalation section in every runbook, the admin-only escalation path, "escalate to L2 with the redacted extract" refusals |
| Password lifecycle: change, verify, reconcile, dependencies | RB-002 to RB-005 |
| Account onboarding / offboarding | RB-001, RB-017 |
| Safe permissions and least privilege | RB-007 (Use vs Retrieve, dual control), and least-privilege RBAC in the tool itself |
| Documentation and knowledge-base upkeep | Runbook format with validated front matter; `last_updated` shown in every citation; a test that keeps error codes and docs in sync |
| Audit support and evidence collection | RB-016; the assistant's own hash-chained audit log; reproducible eval reports |
| Security hygiene (secrets, MFA, break-glass, host keys) | The redaction layer and red-team suite; RB-009 (host-key MITM), RB-012 (MFA), RB-018 (break-glass) |
| Maintenance windows | RB-015 patching checklist with smoke tests and rollback |

## Repository layout

```
knowledge_base/runbooks/     19 original runbooks (Markdown + YAML front matter)
knowledge_base/external/     your downloaded vendor docs, git-ignored
src/pam_copilot/
  security.py                redaction + prompt-injection detection
  ingest.py                  chunking, screening, embedding, Qdrant
  rag.py                     retrieval, RBAC filter, grounded generation, output filter
  diagnose.py                log → classification → runbook → cited fix
  audit.py                   hash-chained audit log
  api.py / ui.py             FastAPI service / Streamlit UI
  loggen.py                  synthetic CPM/PSM/PVWA/Vault log generator + error catalog
  evaluate.py                eval harness (retrieval, answers, redaction, red team)
  kb.py / config.py          runbook loader / settings from env
eval/                        questions.jsonl (50), redteam.jsonl (29), poisoned fixtures, results/
tests/                       offline pytest suite (in-memory Qdrant, fake LLM)
```

## Limitations

- **Synthetic data.** I wrote the log generator, the runbooks, the eval questions and the
  redactor, so retrieval and redaction scores on generated logs are in-distribution and
  optimistic. The handwritten red-team cases are the out-of-distribution evidence, and there are
  only 29. Nothing here has been tested on real CyberArk logs.
- **Judge scores are indicative.** Faithfulness and key-point coverage come from a local 8B
  judge without human calibration.
- **Injection detection is heuristic.** Paraphrases, other languages or encodings can get past
  the regexes. The structural controls (no secrets in context, role filter in the DB, output
  filter, citations) limit the damage, but a well-written false procedure in an ingested
  document ("content poisoning") cannot be detected by a scanner. The real control is
  reviewing documents before they are ingested.
- **Operational shortcuts:** static tokens instead of SSO; a single-process audit lock; no TLS
  in compose (put it behind a reverse proxy); full re-index on every ingest; English only.
- **Small models.** 7–8B local models trade answer quality for privacy and cost; latency is
  from an Apple M5 laptop.
