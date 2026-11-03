---
id: RB-004
title: CPM Password Reconciliation
component: CPM
audience: operator
last_updated: 2026-10-15
error_codes: [SIM-CPM-2201, SIM-CPM-2203]
tags: [cpm, reconcile, out-of-sync, linked-accounts]
---

# CPM Password Reconciliation

## Purpose
Bring an out-of-sync account back under control by having CPM reset its password with a separate, more privileged **reconcile account**.

## When to use
- Verify failed with SIM-CPM-2110 (RB-003).
- A change failed with SIM-CPM-2107 (RB-002).
- Reconcile itself fails with SIM-CPM-2201 or SIM-CPM-2203.

## How reconciliation works
CPM logs on to the target with the reconcile account (for example a domain account with reset-password rights, or root for Unix accounts), sets a new random password for the managed account and stores it in the vault. The managed account's old password is not needed.

## Prerequisites
- Safe permissions: **List accounts**, **Initiate CPM account management operations**.
- A reconcile account linked to the account or defined on the platform. Linking needs **Update account properties** on both Safes; if you lack it, ask the Safe owner.

## Procedure
1. Open the account → **Reconcile**, and enter the ticket number as the reason.
2. Wait for the CPM cycle (usually a few minutes), then refresh the account page.
3. If reconcile succeeds, run **Verify** to confirm.

## Error code reference
| Code | Meaning | Action |
|---|---|---|
| SIM-CPM-2201 | No reconcile account is linked to the account or its platform | Identify the correct reconcile account for the target (same domain, or the root account of that Unix host) and link it under **Linked accounts → Reconcile account**. If none exists, onboard one first (RB-001). |
| SIM-CPM-2203 | The reconcile account logged on but lacks rights to reset the password | Ask the directory/server owner to grant reset-password rights to the reconcile account (for example delegated "Reset password" on the OU, or sudo rights for `passwd` on Unix). Never use a personal admin account as a reconcile account. |

## Verification
- Reconcile completes and is followed by a successful **Verify**.
- Dependencies (services, tasks) using the account are updated — see RB-005 if the account has dependencies.

## Escalation
Escalate to PAM L2 if the reconcile account itself fails verification; fixing it may need a manual, dual-controlled reset by an admin.

## Security notes
- Reconcile accounts are among the most powerful credentials in the vault. Keep them in a dedicated Safe where no human has **Retrieve** permission.
- A reconcile is an audited privileged action. Always reference the ticket in the reason.
