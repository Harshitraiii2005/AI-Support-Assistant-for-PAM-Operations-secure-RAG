---
id: RB-001
title: Onboarding a Privileged Account
component: PVWA
audience: operator
last_updated: 2026-10-06
error_codes: [SIM-PVWA-4201, SIM-PVWA-4202]
tags: [onboarding, accounts, safes, platforms]
---

# Onboarding a Privileged Account

## Purpose
Bring a new privileged account (local admin, root, service account, database owner) under vault management so its password is stored, rotated by CPM, and only reachable through approved access paths.

## When to use
- A request ticket asks to onboard an account into a Safe.
- An account found by a discovery scan must be brought under management.
- `SIM-PVWA-4201` or `SIM-PVWA-4202` is shown when adding an account.

## Prerequisites
- Approved request ticket naming: account name, target address, platform, target Safe, business owner.
- Your PVWA user is a member of the target Safe with **Add accounts** and **Update account content**. If not, see RB-007.
- The target platform exists and is active.
- The account's current password, supplied by the owner through the approved secure channel — never through the ticket, chat or email.

## Procedure
1. Confirm the request is approved and the Safe follows the naming standard `<TECH>-<Function>-<ENV>` (for example `LNX-Root-PRD`).
2. In PVWA open **Accounts → Add account**.
3. Select the platform that matches the target type: `UnixSSH` for Linux/Unix, `WinServerLocal` for a local Windows admin, `WinDomain` for a domain account, `MSSql` for SQL logins.
4. Select the target Safe.
5. Enter the address as an FQDN (not an IP, so re-addressing does not break rotation), the username and, for domain accounts, the logon domain.
6. Paste the current password into the password field. Do not store it anywhere else.
7. Leave **Automatic password management** enabled unless the ticket documents an exception approved by the PAM owner.
8. If the account cannot change its own password, link a **reconcile account** and, where required, a **logon account** (see RB-004).
9. Save. From the account page run **Verify**; once it succeeds run **Change** to perform the first managed rotation.

## Error code reference
| Code | Meaning | Action |
|---|---|---|
| SIM-PVWA-4201 | An account with the same address and username already exists in the Safe | Search all Safes for the address/username. Do not create a duplicate. If the existing object is stale, ask the Safe owner to decide which one stays. |
| SIM-PVWA-4202 | The selected platform is inactive or not allowed for this Safe | Pick the correct active platform. If the right platform is inactive, escalate to PAM admins — operators do not activate platforms. |

## Verification
- The account shows a successful **Verify** and a successful **Change** within the last hour.
- The account exists in the correct Safe only.
- The ticket is updated with the account object name (never the password).

## Escalation
Escalate to PAM L2 if the first change fails twice. Follow RB-002 before escalating.

## Security notes
- The onboarding password is the most exposed value in the account's life. Once CPM has changed it, the old value is useless — make sure the first change runs the same day.
- Never onboard into a personal or "temporary" Safe.
