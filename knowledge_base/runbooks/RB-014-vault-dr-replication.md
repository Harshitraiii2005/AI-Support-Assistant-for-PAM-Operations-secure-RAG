---
id: RB-014
title: Disaster Recovery Vault Replication
component: Vault
audience: admin
last_updated: 2026-09-18
error_codes: [SIM-VLT-5301, SIM-VLT-5303]
tags: [vault, disaster-recovery, replication, failover]
---

# Disaster Recovery Vault Replication

## Purpose
Keep the DR vault in sync with production so a failover loses as little data as possible.

## When to use
- SIM-VLT-5301: replication lag above threshold.
- SIM-VLT-5303: the DR vault cannot reach the production vault.
- Before a planned DR test.

## Diagnosis
1. Read the DR replication log for the last successfully replicated transaction and its time.
2. Compare it with production's current state.
3. Check site-to-site network monitoring for the same window.

## Error code reference
| Code | Meaning | Action |
|---|---|---|
| SIM-VLT-5301 | The DR vault is replicating but is behind production by more than the threshold (60 minutes in this environment) | Check bandwidth between sites and whether a bulk operation is running (mass onboarding, many recordings). Lag that keeps growing after the bulk job ends needs L3 or vendor attention. |
| SIM-VLT-5303 | The DR vault cannot connect to production | Check the firewall path between sites and the DR replication user's status. Confirm production is actually up — if production is down, this is a DR decision, not a replication fix. |

## Resolution
- Fix the connectivity or user issue, then confirm replication resumes and the lag decreases.
- Do **not** start the DR vault as active to "test" during a replication problem — two active vaults cause split-brain.

## Verification
- Lag stays under the threshold for at least two monitoring intervals.

## Escalation
A 5303 lasting more than one hour → PAM owner and infrastructure on-call. Failover decisions belong to the incident manager, not to the operator.

## Security notes
- DR vault access must be as restricted as production. A DR site with weaker controls is the easiest way to the vault data.
