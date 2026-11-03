# Knowledge base

## `runbooks/` (committed)

Original runbooks written for this project. They describe generic PAM practice using
CyberArk-style vocabulary (Vault, Safes, CPM, PSM, PVWA). They are **not** vendor
documentation. Environment names (`corp.example`), Safe names and all `SIM-` error codes
are fictional.

Each file starts with YAML front matter, validated by `pam_copilot.kb` and the test suite:

| Field | Meaning |
|---|---|
| `id` | `RB-NNN`, unique, used in citations; the filename starts with it |
| `title` | Human-readable title |
| `component` | `CPM`, `PSM`, `PVWA`, `Vault` or `General` |
| `audience` | `operator` = visible to operators and admins; `admin` = admins only |
| `last_updated` | ISO date, shown next to citations so stale guidance is visible |
| `error_codes` | `SIM-` codes this runbook resolves; must match the generator catalog exactly |
| `tags` | Free-form keywords |

Body convention: one `#` title, then `##` sections (Purpose, When to use, Diagnosis,
Resolution, Verification, Escalation, Security notes). Ingestion chunks on these headings.

## `external/` (git-ignored)

Put public vendor documentation that you downloaded yourself (PDF/HTML) here. It is
ingested locally with source and page metadata for citations, and is never committed or
redistributed. Check the vendor's terms of use before downloading.
