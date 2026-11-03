---
id: RB-008
title: PSM Session Not Launching
component: PSM
audience: operator
last_updated: 2026-10-20
error_codes: [SIM-PSM-3101, SIM-PSM-3104, SIM-PSM-3107]
tags: [psm, sessions, connect, connection-component]
---

# PSM Session Not Launching

## Purpose
Fix privileged sessions that fail before reaching the target: the user clicks **Connect** and the session window never appears, closes immediately, or shows a PSM error.

## When to use
- SIM-PSM-3101, SIM-PSM-3104 or SIM-PSM-3107.
- "Connect does nothing", "the RDP window opens and closes", "PSM error on connect".
- For errors after PSM reaches the target (timeouts, rejected credentials, host key warnings) use RB-009.

## Prerequisites
- Safe permissions: **List accounts**, **View audit**.
- Access to PSM session history / monitoring in PVWA.

## Triage: where is it failing?
1. **User side** — Does the RDP file download and open? Corporate browsers sometimes block `.rdp` downloads. If an HTML5 gateway is available, ask the user to try it.
2. **PSM server side** — codes 3101 and 3104 are raised on the PSM server.
3. **Vault side** — code 3107 means PSM could not fetch the account's credentials.

## Error code reference
| Code | Meaning | Action |
|---|---|---|
| SIM-PSM-3101 | The connection component's client application failed to start, usually blocked by application control on the PSM server after a client upgrade or path change | Note which connection component (for example PSM-SSMS) and whether others work. If only one component fails after a recent change, escalate to PAM admins to update the application control allow-list. |
| SIM-PSM-3104 | The PSM server has no free remote desktop session (session limit or licences exhausted, or stuck disconnected sessions) | Ask the user to retry — the load balancer may pick another server. Report the PSM server name to L2 so they can clear orphaned sessions and check licensing. |
| SIM-PSM-3107 | PSM could not retrieve the target account's credentials | Check the account is still in the Safe and not disabled, that the PSM component user is still a Safe member with the rights it needs, and that CPM is not in the middle of changing the password. |

## Verification
- The user opens a session and reaches the target's login prompt or desktop.
- The session appears in session history with a recording.

## Escalation
Escalate to PAM L2 with: user, account, Safe, connection component, PSM server name, time and code. Several users failing on the same PSM server is a P2.

## Security notes
- Never give the user the password (Retrieve) as a workaround for a broken PSM session; that bypasses session recording. If access is business-critical, use break-glass (RB-018).
- Do not ask users to disable local security tools to make the RDP file open.
