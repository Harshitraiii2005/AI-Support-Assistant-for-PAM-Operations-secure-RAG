---
id: RB-011
title: PVWA Login Failure
component: PVWA
audience: operator
last_updated: 2026-10-17
error_codes: [SIM-PVWA-4101, SIM-PVWA-4104, SIM-PVWA-4106]
tags: [pvwa, authentication, ldap, lockout]
---

# PVWA Login Failure

## Purpose
Help a user who cannot log in to the PVWA web portal with directory (LDAP) credentials.

## When to use
- SIM-PVWA-4101, SIM-PVWA-4104 or SIM-PVWA-4106.
- "I can't log in to the vault portal" with username and password.
- For RADIUS MFA or SAML single sign-on problems, use RB-012.

## Prerequisites
- Read access to PVWA authentication logs, or a log extract from L2.
- Ability to check user and group status in the directory.

## First questions to the user
1. Which login method did you choose (LDAP, RADIUS, SAML)?
2. Can you log in to your workstation with the same password right now?
3. What is the exact error text, and when did it happen?

Never ask the user for their password.

## Error code reference
| Code | Meaning | Action |
|---|---|---|
| SIM-PVWA-4101 | PVWA could not bind to the directory server | If many users fail at once, it is a platform issue: the directory server is unreachable or the LDAP bind account's password expired. Escalate to PAM L2 as a P2. If only one user fails, re-check the error — it is unlikely to be this code. |
| SIM-PVWA-4104 | The vault user is suspended after too many failed logons | Verify the user's identity through the standard identity verification process, then request activation through L2 or a user manager. Ask whether they recently changed their directory password (an old password saved in the browser keeps failing). |
| SIM-PVWA-4106 | Directory login succeeded but the user is not mapped to any vault user or group | The user is not in a directory group mapped to the vault. They need to request the correct PAM access group through the access request process. |

## Verification
- The user logs in and sees the Safes they are expected to see — no more, no fewer.

## Escalation
- Several users with 4101 → P2 to PAM L2 immediately.
- Repeated 4104 suspensions for the same user without explanation → inform security operations (possible password guessing).

## Security notes
- Identity verification comes before activating anyone. A locked privileged-access user is a classic social-engineering target.
