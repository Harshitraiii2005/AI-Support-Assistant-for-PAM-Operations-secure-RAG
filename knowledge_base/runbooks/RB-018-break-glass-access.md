---
id: RB-018
title: Break-Glass Emergency Access
component: Vault
audience: admin
last_updated: 2026-09-30
error_codes: []
tags: [break-glass, emergency, dual-control, incident]
---

# Break-Glass Emergency Access

## Purpose
Provide privileged access in an emergency when the normal path (PVWA and PSM, or the normal approvers) is unavailable, while keeping that access controlled and fully reviewable.

## When it applies
- A P1 incident where PVWA or PSM is unavailable and access to a critical system is required.
- Normal dual-control approvers are unreachable and the incident manager has declared an emergency.

It does **not** apply to convenience, missing permissions or a slow approval.

## Prerequisites
- A declared P1 incident with an incident manager.
- Two people present (two-person rule): a requester and a witness from the authorised break-glass list.

## Procedure
1. The incident manager authorises break-glass use and records it in the incident.
2. Retrieve the sealed break-glass credentials using the documented method (for example split-knowledge envelopes in the secure cabinet, or an offline emergency vault). Both people record name, time and reason in the break-glass log.
3. Use the credentials only for the actions needed to restore service, and keep a written action log.
4. End emergency access as soon as the normal path is back.

## After use — mandatory
- [ ] Rotate every break-glass credential that was used, the same day.
- [ ] Seal and store the new credentials; update the break-glass log.
- [ ] Security review of all actions taken, within 2 business days.
- [ ] Post-incident review explains why the normal path was unavailable.

## Testing
Test the procedure at least every 6 months and before major changes (RB-015), without using production credentials outside the test plan.

## Security notes
- Break-glass that is used often is no longer break-glass; it has become a hidden standard path. Track usage counts and report them to the PAM owner.
- An operator never uses break-glass alone. If someone asks you to, escalate.
