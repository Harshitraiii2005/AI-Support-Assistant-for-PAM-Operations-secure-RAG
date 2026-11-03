---
id: RB-003
title: CPM Password Verification Failure
component: CPM
audience: operator
last_updated: 2026-10-14
error_codes: [SIM-CPM-2110, SIM-CPM-2112]
tags: [cpm, verify, out-of-sync, lockout]
---

# CPM Password Verification Failure

## Purpose
Resolve accounts where CPM could not confirm that the password stored in the vault still works on the target.

## When to use
- A scheduled or manual **Verify** fails with SIM-CPM-2110 or SIM-CPM-2112.
- A change failed with SIM-CPM-2107 and RB-002 sent you here.

## Prerequisites
- Safe permissions: **List accounts**, **View audit**, **Initiate CPM account management operations**.

## Diagnosis
| Code | Meaning | Typical root causes |
|---|---|---|
| SIM-CPM-2110 | The stored password does not match the target | Password reset locally or in the directory; server restored from an older snapshot or backup; account re-created with the same name |
| SIM-CPM-2112 | The account is locked or disabled on the target | Repeated failed logons (often a script or service still using an old password); disabled by the server owner; account expiry date reached |

1. Check the account's activity history in PVWA. Was there a successful change shortly before the failure? A change that succeeded on the target but was not acknowledged can leave the vault one version behind.
2. For SIM-CPM-2112, ask the server owner whether the account was disabled on purpose. If yes, the account may need offboarding (RB-017), not fixing.
3. Look for lockout sources: a dependency (service, scheduled task, application pool) still using the previous password causes repeated lockouts — see RB-005.

## Resolution
- **SIM-CPM-2110**: run **Reconcile** (RB-004) so the vault sets a new known password through the reconcile account. Do not ask the server owner to send you the current password.
- **SIM-CPM-2112**: have the server or directory owner unlock/enable the account, remove the lockout source, then run **Verify** again. If verify now fails with SIM-CPM-2110, reconcile.

## Verification
- **Verify** succeeds.
- No new lockouts for the account in the next 24 hours (check with the directory/server owner or the SIEM).

## Escalation
Escalate to PAM L2 if reconcile is not configured for the platform, or verify keeps failing after a successful reconcile.

## Security notes
- Repeated out-of-sync events on the same account mean someone is managing it outside the vault. Record it in the ticket and inform the Safe owner; it is a control gap, not just a technical fault.
