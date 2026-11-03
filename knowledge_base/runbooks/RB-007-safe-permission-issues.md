---
id: RB-007
title: Safe Permission Issues
component: Vault
audience: operator
last_updated: 2026-10-09
error_codes: [SIM-PVWA-4301, SIM-PVWA-4302]
tags: [safes, permissions, access-request, dual-control]
---

# Safe Permission Issues

## Purpose
Diagnose "not authorized" and "pending approval" problems when a user tries to see, use or retrieve a privileged account.

## When to use
- SIM-PVWA-4301: the user is not authorized for an action on an account.
- SIM-PVWA-4302: access requires dual-control approval that is still pending.
- A user says "I can't see the account" or "the Connect button is missing".

## Background: common Safe permissions
| Permission | What it allows |
|---|---|
| List accounts | See that the account exists |
| Use accounts | Connect through PSM without seeing the password |
| Retrieve accounts | Show or copy the password |
| Add / Update accounts | Onboard and edit account objects |
| Initiate CPM operations | Trigger change, verify, reconcile |
| Authorize account requests | Approve dual-control requests |
| Manage Safe members | Change who has access (Safe owners only) |
| View audit | See the Safe's activity history |

Least privilege: prefer **Use** over **Retrieve**. Membership is granted to directory groups, not to individual users.

## Diagnosis
1. Ask for the exact message, account name, Safe and the action attempted. Do not ask for screenshots that could show a password.
2. Compare the user's directory group membership with the Safe's member list (PVWA → Safe → Members).
3. For SIM-PVWA-4301, identify which permission is missing for the requested action (see the table above).
4. For SIM-PVWA-4302, find the request and its approvers. Approvers need **Authorize account requests** on the Safe.

## Resolution
- **Missing permission (4301)**: the user requests access through the access request process, approved by the Safe owner. Operators do not add Safe members directly, even if their role technically allows it.
- **Group not yet applied**: if the user was added to the right group recently, ask them to log out and back in; group membership is evaluated at logon.
- **Pending approval (4302)**: contact the listed approvers. If no approver is reachable and there is a declared P1 incident, the incident manager can invoke break-glass (RB-018). Never approve your own request, and never ask a colleague to "just approve it" without reviewing the reason.

## Verification
- The user can perform the intended action — and only that action.
- The ticket records the approved access request ID.

## Escalation
Access decisions go to the Safe owner. Escalate to PAM L2 if group membership looks correct but authorization still fails.

## Security notes
- "Give them Retrieve so they can get in quickly" is the most common way PAM controls are weakened. Push back and offer **Use** through PSM.
- Every permission change is audited; each one must map to an approved request.
