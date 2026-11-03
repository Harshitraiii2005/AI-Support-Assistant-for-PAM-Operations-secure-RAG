---
id: RB-017
title: Offboarding and Decommissioning Privileged Accounts
component: General
audience: operator
last_updated: 2026-10-06
error_codes: []
tags: [offboarding, decommission, accounts, lifecycle]
---

# Offboarding and Decommissioning Privileged Accounts

## Purpose
Remove privileged accounts from vault management cleanly when the target is decommissioned or the account is no longer needed, without losing audit history.

## When to use
- A server decommission ticket lists targets with vaulted accounts.
- CPM fails repeatedly with "target unreachable" (SIM-CPM-2101) and the CMDB shows the server as retired.
- An application is retired and its service accounts are being deleted in the directory.

## Prerequisites
- Approved decommission or change ticket.
- Safe permission **Delete accounts**, or a request to the Safe owner.

## Procedure
1. Confirm in the CMDB that the target is retired, or that the account owner approved removal.
2. Check for dependencies (RB-005): a "retired" service account still used elsewhere causes an outage when it is deleted in the directory.
3. Check linked usage: is this account the **reconcile** or **logon** account for others? If yes, re-link those accounts first.
4. Disable automatic management on the account with the ticket number as the reason.
5. Delete the account object. The vault keeps its audit history according to the retention policy; deleting the object does not delete the history.
6. If the Safe is now empty and has no other purpose, raise a Safe deletion request to the Safe owner.

## Verification
- The account no longer appears in searches.
- No CPM errors for the retired target in the next cycle.
- The decommission ticket lists the removed account objects.

## Escalation
If an account is listed for removal but is still in use (sessions or retrievals in the last 30 days), stop and ask the Safe owner to confirm.

## Security notes
- Decommissioned does not mean harmless: if the server comes back (restored VM, re-used hostname), an unmanaged privileged account with a known password comes back with it. Make sure the account is also deleted on the target, not just in the vault.
