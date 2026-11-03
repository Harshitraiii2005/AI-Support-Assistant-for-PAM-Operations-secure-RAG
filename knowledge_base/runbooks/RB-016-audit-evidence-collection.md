---
id: RB-016
title: Audit Evidence Collection
component: General
audience: operator
last_updated: 2026-10-10
error_codes: []
tags: [audit, compliance, evidence, reporting]
---

# Audit Evidence Collection

## Purpose
Collect consistent, complete evidence when internal or external auditors ask for proof that privileged access is controlled.

## When to use
- Audit request tickets (internal audit, SOX, ISO 27001, PCI DSS reviews).
- Quarterly access recertification support.

## Typical requests and their evidence
| Request | Evidence |
|---|---|
| "Who can access privileged accounts on system X?" | Safe membership report for the Safes holding X's accounts, plus directory membership of the member groups |
| "Are passwords rotated per policy?" | Account compliance report with last change date and status for the in-scope Safes |
| "Are privileged sessions recorded?" | Session history for the sample period, plus 2–3 sample recordings shown to the auditor in a supervised session |
| "Is access approved?" | Dual-control request history with requester, approver, reason and timestamps |
| "Did leavers lose access?" | HR leaver list compared with vault users and group membership on the leaving date |
| "Are PAM configuration changes controlled?" | Change records for platform and Safe changes, matched to vault audit entries |

## Procedure
1. Log the request: auditor, scope (systems, Safes, period), deadline and sample size if given.
2. Generate PVWA reports for exactly the requested scope and period. Do not widen the scope "to be safe" — over-sharing is a data leak.
3. Export in the approved format (CSV or PDF). Name files `<audit-id>_<evidence>_<YYYYMMDD>.<ext>`.
4. Calculate and record a SHA-256 hash for each file in the evidence log.
5. Have a second person (PAM L2 or team lead) review the evidence for completeness and for sensitive data.
6. Deliver through the approved audit portal, not by email.

## What must never be in evidence
- Passwords, credential files, API keys or tokens.
- Screenshots showing the password reveal dialog.
- Full system logs, unless specifically requested and reviewed — they can contain secrets.

## Verification
- Every item in the request maps to a delivered file in the evidence log.
- The auditor confirms receipt.

## Escalation
If the evidence shows a control failure (for example a leaver who still has access), do not alter any data. Report it to the PAM owner and let the auditor see the finding as it is.
