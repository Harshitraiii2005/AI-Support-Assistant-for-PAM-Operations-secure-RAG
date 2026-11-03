---
id: RB-005
title: CPM Dependency (Usage) Update Failure
component: CPM
audience: operator
last_updated: 2026-09-29
error_codes: [SIM-CPM-2301, SIM-CPM-2302]
tags: [cpm, dependencies, service-accounts, windows]
---

# CPM Dependency (Usage) Update Failure

## Purpose
Handle cases where CPM changed a service account's password but failed to push the new password to the places that use it: Windows services, scheduled tasks, IIS application pools, configuration files.

## When to use
- SIM-CPM-2301 or SIM-CPM-2302 after a successful change.
- An application team reports a service failing to start right after a scheduled rotation.

## Key fact
The vault holds the **correct, new** password. The dependency still holds the **old** one. Rolling the password back is never the fix.

## Prerequisites
- Safe permissions: **List accounts**, **View audit**, **Initiate CPM account management operations**.
- The application owner's contact (from the CMDB) — dependency failures are often outages.

## Diagnosis
| Code | Meaning | Common causes |
|---|---|---|
| SIM-CPM-2301 | The Windows service was updated but could not restart with the new credentials | Service account lacks "Log on as a service" on the host; a service it depends on is stopped; wrong account format (`DOMAIN\user` vs `user@domain`) |
| SIM-CPM-2302 | The scheduled task could not be updated | The account CPM uses on the host lacks local admin rights; the task is owned and protected by another user; host unreachable on management ports |

1. Open the managed account → **Dependencies**. Confirm the host and the service/task still exist.
2. Check whether one host or all hosts fail. One host → host-side cause. All hosts → likely the rights of the account CPM uses for updates.

## Resolution
1. Fix the host-side cause with the server owner (rights, stopped dependency, removed service).
2. Remove dependency entries for services or hosts that no longer exist — stale entries fail on every rotation.
3. Trigger **Change** again, or the dependency-only update if the platform supports it. Confirm with the application owner that the service is running.

## Verification
- The next change completes with no dependency errors.
- The application owner confirms the service is healthy.

## Escalation
If the service is down and the fix is not immediate, raise a P2 to PAM L2 and the application owner together. L2 can push the current vault password to the dependency manually under change control.

## Security notes
- Do not "temporarily" run the service as LocalSystem or as a personal account to restore it.
- Do not disable rotation for the account because of a dependency problem without an approved exception.
