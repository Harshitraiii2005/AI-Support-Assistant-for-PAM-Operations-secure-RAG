---
id: RB-019
title: Escalation and Ticket Hygiene for PAM Support
component: General
audience: operator
last_updated: 2026-10-21
error_codes: []
tags: [escalation, tickets, triage, data-handling, redaction]
---

# Escalation and Ticket Hygiene for PAM Support

## Purpose
Make every escalation from first-level PAM support complete, quick to act on, and free of secrets.

## Priority guide
| Priority | Examples |
|---|---|
| P1 | Vault unavailable; PVWA down for all users; suspected compromise of a privileged account |
| P2 | One component server down (a CPM or PSM); many users unable to log in; recordings failing; MFA failing for many users |
| P3 | A single account failing rotation; a single user's session failing |
| P4 | Questions, documentation, report requests |

Suspected security events (an unexplained host key change, an MFA push the user did not start, out-of-sync passwords on critical accounts) go to security operations regardless of priority.

## What to include in an escalation
- Component (CPM, PSM, PVWA, Vault) and error code (`SIM-...`).
- Account object name and Safe — never the password.
- Target address, time window with timezone, and the number of affected users or accounts.
- What you already checked and which runbook you followed.
- A **redacted** log extract with only the relevant lines.

## Redaction before you paste
Before pasting logs into a ticket, chat or AI assistant, remove or mask:
- passwords, including old/new password arguments,
- API keys, bearer tokens and session cookies,
- connection strings,
- credential file contents.

Hostnames and IP addresses are internal information: mask them whenever the ticket is visible outside the PAM team.

## Closing a ticket
- State the root cause in one sentence and the fix applied.
- Link the runbook used, and propose a runbook update if steps were missing or wrong.
