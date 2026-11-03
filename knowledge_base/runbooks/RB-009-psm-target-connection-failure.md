---
id: RB-009
title: PSM Target Connection Failure
component: PSM
audience: operator
last_updated: 2026-10-20
error_codes: [SIM-PSM-3201, SIM-PSM-3203, SIM-PSM-3205]
tags: [psm, sessions, network, nla, host-key]
---

# PSM Target Connection Failure

## Purpose
Fix sessions where PSM started correctly but could not establish or authenticate the connection to the target server.

## When to use
- SIM-PSM-3201, SIM-PSM-3203 or SIM-PSM-3205.
- The session window opens, then shows a timeout, a logon failure, or a host key/certificate warning.

## Diagnosis
1. Note the target address and protocol from the session error.
2. Check whether other accounts on the same target work through PSM. None work → network or target issue. Only this account fails → credential or account-rights issue.
3. Check recent changes on the target (patching, rebuild, firewall).

## Error code reference
| Code | Meaning | Action |
|---|---|---|
| SIM-PSM-3201 | The connection from PSM to the target timed out | Check the target is up and that the firewall allows the PSM servers (not user workstations) to reach the target port (RDP 3389, SSH 22, SQL 1433). Recent firewall changes are the most common cause. |
| SIM-PSM-3203 | The target rejected the account's credentials, including network level authentication failures | The stored password may be out of sync: run **Verify** (RB-003). If verify succeeds, check the account is allowed to log on remotely on the target (local policy, SSH AllowUsers). |
| SIM-PSM-3205 | The target presented a host key or certificate that does not match the trusted one | **Stop.** Confirm with the server owner whether the server was rebuilt or its certificate replaced. If yes, PAM admins update the trusted key under a change. If nobody can explain it, treat it as a possible man-in-the-middle and raise a security incident. |

## Verification
- A new session reaches the target and authenticates.
- For 3205, the change record for the key or certificate update is linked in the ticket.

## Escalation
Escalate to PAM L2 for firewall rule requests from the PSM subnets, and for any 3205 event not explained by a documented rebuild.

## Security notes
- Never accept or bypass a changed host key just to get the user connected.
- Never request a firewall rule from the user's workstation to the target — privileged access goes through PSM.
