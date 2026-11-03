---
id: RB-013
title: Vault Backup Operations and Failures
component: Vault
audience: admin
last_updated: 2026-09-18
error_codes: [SIM-VLT-5201, SIM-VLT-5203]
tags: [vault, backup, replication, recovery]
---

# Vault Backup Operations and Failures

## Purpose
Run, monitor and troubleshoot the scheduled vault backup, which replicates vault data to a dedicated backup server from where enterprise backup copies it to long-term storage.

## When to use
- The daily backup report shows a failure.
- SIM-VLT-5201 (backup user rejected) or SIM-VLT-5203 (backup destination low on disk).
- Before patching or upgrades — a fresh, verified backup is a prerequisite (RB-015).

## Prerequisites
- Admin access to the backup server.
- Vault admin rights to check the backup user.
- The backup user's credential file exists only on the backup server.

## Normal operation
1. The replication job runs nightly on the backup server and pulls vault data and metadata.
2. Enterprise backup copies the replicated folder after the job finishes — never while it runs.
3. A restore test to an isolated server runs at least quarterly and is recorded.

## Error code reference
| Code | Meaning | Action |
|---|---|---|
| SIM-VLT-5201 | The backup utility's vault user was rejected | Check whether the backup user is suspended or its credential file is outdated (server rename or IP change). Regenerate the credential file on the backup server; activate the user only once you know why it was suspended. |
| SIM-VLT-5203 | The backup destination volume does not have enough free space | Check that enterprise backup is collecting and rotating old copies. Expand the volume under change. Never delete the last good replica to make room. |

## Verification
- The next run completes; the job log shows success and the replicated data size is in line with previous runs (a much smaller size is suspicious).
- Enterprise backup confirms the copy.

## Escalation
Two consecutive failed nights → notify the PAM owner. Without a valid backup there is no safe recovery point; postpone risky changes.

## Security notes
- The backup contains the encrypted vault data. Treat the backup server as a tier-0 asset with the same hardening and access restrictions as the vault.
- Backup credentials and encryption keys must never be stored on the same media as the backup.
