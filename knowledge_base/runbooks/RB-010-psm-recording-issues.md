---
id: RB-010
title: PSM Session Recording Upload and Storage Issues
component: PSM
audience: admin
last_updated: 2026-09-25
error_codes: [SIM-PSM-3301, SIM-PSM-3302]
tags: [psm, recordings, disk-space, audit]
---

# PSM Session Recording Upload and Storage Issues

## Purpose
Keep session recordings flowing from PSM servers into the vault. Recordings are audit evidence; losing them is an audit finding.

## When to use
- SIM-PSM-3301: a recording upload to the vault failed and the file is queued locally.
- SIM-PSM-3302: the recordings folder on a PSM server is low on disk space.
- Auditors or reviewers report missing recordings for known sessions.

## Prerequisites
- Admin access to the PSM server through the PSM admin path, not direct RDP from a workstation.
- Vault admin rights to check the recordings Safe quota.

## Diagnosis
| Code | Meaning | Common causes |
|---|---|---|
| SIM-PSM-3301 | Upload of a completed recording to the vault failed; the file stays in the local queue | Recordings Safe at quota; vault unreachable; PSM component user lacks **Add** rights on the recordings Safe |
| SIM-PSM-3302 | The local recordings folder is below the free-space threshold | Upload backlog from a 3301 condition; folder on the system drive; unusually long sessions with video recording |

1. Check the size and age of the local queue.
2. Check the recordings Safe quota and recent upload errors in the PSM log.
3. Confirm vault connectivity from the PSM server.

## Resolution
1. Fix the upload blocker first: quota increase under change, Safe permission for the PSM component user, or network path.
2. Let the PSM service drain the queue and check that the queue shrinks.
3. If the disk is critically low, drain the server in the load balancer (no new sessions) instead of deleting files.
4. Long term: move the recordings folder to a dedicated volume and alert at 30% free.

## Verification
- The local queue is empty or steadily shrinking.
- Recordings for sessions during the incident are visible in the vault.

## Escalation
If recordings were lost, inform the PAM owner and the compliance team the same day with the affected time window and session list.

## Security notes
- **Never delete queued recordings to free disk space.** They may be the only copy.
- Recording gaps must be documented, not hidden.
