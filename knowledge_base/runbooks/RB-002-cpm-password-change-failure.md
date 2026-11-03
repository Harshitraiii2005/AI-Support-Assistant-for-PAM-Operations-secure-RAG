---
id: RB-002
title: CPM Password Change Failure
component: CPM
audience: operator
last_updated: 2026-10-14
error_codes: [SIM-CPM-2101, SIM-CPM-2104, SIM-CPM-2107]
tags: [cpm, password-rotation, change]
---

# CPM Password Change Failure

## Purpose
Triage and fix accounts where the Central Policy Manager (CPM) could not rotate the password on the target system.

## When to use
- The account shows a failed **Change** with one of the codes below.
- A compliance report lists the account as "password older than policy".
- An application owner reports that a scheduled rotation did not happen.

## Prerequisites
- Safe permissions: **List accounts**, **View audit**, **Initiate CPM account management operations**.
- Read access to CPM error details in PVWA, or a log extract from L2.
- Access to the CMDB or monitoring to check whether the target is alive.

## Diagnosis
1. Open the account in PVWA and note the error code, the time of the failure and how many attempts have run.
2. Check the blast radius before touching a single account:
   - Same code on **many accounts on one target** → target-side issue (network, local policy, server rebuilt).
   - Same code on **many targets on one platform** → platform or CPM-side issue; go to RB-006 and escalate.
3. Use the row for the error code:

| Code | Likely cause | First checks |
|---|---|---|
| SIM-CPM-2101 | Target unreachable: host down, DNS record changed, firewall rule removed, server decommissioned | Port check from monitoring; confirm the account address matches the CMDB FQDN; look for recent firewall or decommission changes |
| SIM-CPM-2104 | Target rejected the new password: the platform's password policy conflicts with the target's local policy (length, history, forbidden characters) | Compare the platform's generated-password rules with the target policy; check for a recent group policy or PAM module change on the target |
| SIM-CPM-2107 | The password stored in the vault no longer works: changed outside the vault, server restored from a snapshot, or account locked | Run **Verify** (RB-003). If verify fails, reconcile (RB-004) |

## Resolution
- **SIM-CPM-2101**: fix the address or network path with the server/network owner. If the server was decommissioned, follow RB-017 instead of retrying. After the fix, trigger **Change** manually.
- **SIM-CPM-2104**: ask PAM admins to align the platform password policy with the target's. Do not ask the server team to weaken the target policy. Once the platform is updated, trigger **Change**.
- **SIM-CPM-2107**: treat it as an out-of-sync password. Verify first, then reconcile. Record in the ticket who or what changed the password outside the vault, if known — that is an audit finding.

## Verification
- A manual **Change** completes and is followed by a successful **Verify**.
- The failure flag on the account clears and the next scheduled change date is in the future.

## Escalation
Escalate to PAM L2 with the account object name, Safe, code, timestamp and your blast-radius findings if:
- the same code persists after the fix, or
- more than 10 accounts fail with the same code within an hour.

## Security notes
- Never disable automatic password management just to clear an alert; that leaves a static privileged password in place.
- Do not retrieve the password to test it by hand on the target. If an interactive check is unavoidable, connect through PSM so the session is recorded.
- Never paste raw CPM logs into tickets or chat without removing passwords, tokens and connection strings — debug-level logs can contain them (see RB-019).
