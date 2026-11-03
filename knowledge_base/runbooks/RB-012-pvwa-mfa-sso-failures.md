---
id: RB-012
title: PVWA MFA and Single Sign-On Failures
component: PVWA
audience: operator
last_updated: 2026-10-17
error_codes: [SIM-PVWA-4110, SIM-PVWA-4120, SIM-PVWA-4122]
tags: [pvwa, authentication, mfa, radius, saml]
---

# PVWA MFA and Single Sign-On Failures

## Purpose
Resolve PVWA login failures for RADIUS-based MFA and SAML single sign-on.

## When to use
- SIM-PVWA-4110 (RADIUS timeout), SIM-PVWA-4120 (SAML assertion outside its validity window) or SIM-PVWA-4122 (SAML signature mismatch).
- For plain LDAP username/password failures, use RB-011.

## Diagnosis
1. One user or many? One user → user side (device, enrolment, timing). Many → service side.
2. Intermittent? Intermittent failures behind a load balancer usually mean one PVWA server differs from the others (time, certificate, configuration).

## Error code reference
| Code | Meaning | Action |
|---|---|---|
| SIM-PVWA-4110 | PVWA got no response from the RADIUS/MFA server in time | Ask whether the user received the push or OTP prompt. No prompt and many users affected → MFA server or network issue, escalate as P2. Prompt received but approved late → retry and approve within the time window. |
| SIM-PVWA-4120 | The SAML assertion was rejected because its timestamps are outside the allowed window | Almost always clock drift between the identity provider and the PVWA servers. Escalate to PAM L2 to check time sync (NTP) on every PVWA server; one drifting server causes intermittent failures. |
| SIM-PVWA-4122 | The SAML response signature does not match the identity provider certificate configured in PVWA | Usually the identity provider rotated its signing certificate. Escalate to PAM admins to update the certificate under change. If no rotation was planned, raise it with security — it can indicate a spoofed identity provider response. |

## Verification
- The user completes MFA/SSO and lands in PVWA.
- For 4120 and 4122, test the login through each PVWA server.

## Escalation
Many users affected → P2 to PAM L2 and the identity team.

## Security notes
- Never offer to switch a user to password-only login "temporarily". MFA is a mandatory control for privileged access.
- An MFA push the user did not initiate is a security incident — report it.
