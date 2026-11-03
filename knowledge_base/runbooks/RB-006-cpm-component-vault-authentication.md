---
id: RB-006
title: CPM Component Cannot Authenticate to the Vault
component: CPM
audience: admin
last_updated: 2026-10-02
error_codes: [SIM-CPM-2001, SIM-CPM-2002]
tags: [cpm, component-health, credential-file, vault]
---

# CPM Component Cannot Authenticate to the Vault

## Purpose
Restore a CPM server that has lost its connection to the vault. While this lasts, no password in any Safe managed by that CPM is rotated, verified or reconciled.

## When to use
- SIM-CPM-2001 or SIM-CPM-2002 in the CPM log.
- Many accounts across many platforms stop showing CPM activity at the same time.
- The RB-002 blast-radius check pointed to a CPM-side issue.

## Prerequisites
- Admin access to the CPM server through PSM, not direct RDP.
- Vault administrator rights to view and activate component users.
- An approved change or incident record.

## Diagnosis
| Code | Meaning | Common causes |
|---|---|---|
| SIM-CPM-2001 | The vault rejected the CPM component user's credential file | Credential file regenerated on another server or copied; server IP or hostname changed and the file is bound to the old values; component user password rotated without updating the file |
| SIM-CPM-2002 | The CPM component user is suspended in the vault | Too many failed authentications after a 2001 condition; manual suspension during an incident |

1. Confirm the CPM service state and the last successful vault connection time in the CPM log.
2. Check the network path from CPM to the vault (firewall change, vault failover to DR).
3. In the vault administration tool, check the component user's status and last failed logon reason.

## Resolution
1. Stop the CPM service.
2. If the user is suspended (2002), activate it — only after you understand why it was suspended.
3. Regenerate the credential file on the CPM server itself with the vault's credential-file utility, bound to the server's current address and the expected application path. Never copy credential files between servers.
4. Start the CPM service and watch the log for a successful vault logon.
5. Trigger a manual **Verify** on one known-good account to prove the end-to-end path.

## Verification
- The CPM log shows a successful vault logon and normal processing cycles.
- Accounts that queued during the outage start processing; spot-check three.

## Escalation
If authentication still fails after regenerating the credential file, open a vendor support case with redacted component and vault logs and a timeline of changes.

## Security notes
- A credential file is a secret. Do not attach it to tickets or vendor cases; restrict file permissions to the service account and administrators.
- A sudden 2001 on a server that has not changed can indicate tampering with the credential file. Check the server's change history before simply regenerating it.
