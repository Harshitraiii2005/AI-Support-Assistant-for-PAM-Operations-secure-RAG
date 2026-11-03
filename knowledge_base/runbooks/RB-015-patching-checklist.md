---
id: RB-015
title: Patching Checklist for PAM Components
component: General
audience: admin
last_updated: 2026-10-01
error_codes: []
tags: [patching, change-management, maintenance]
---

# Patching Checklist for PAM Components

## Purpose
Apply operating system and component patches to PVWA, PSM and CPM servers (and the vault, only where the vendor allows it) without losing privileged access or audit data.

## Before the window
- [ ] Approved change record with a rollback plan and a named implementer.
- [ ] A verified vault backup from the last 24 hours (RB-013).
- [ ] DR replication healthy (RB-014).
- [ ] Vendor compatibility checked for the OS patch level and for client applications used by PSM connection components.
- [ ] Break-glass access tested within the last 30 days (RB-018).
- [ ] Users notified; servers patched so that each high-availability pair always keeps one server up.

## During the window — one server at a time
1. Remove the server from its load balancer pool (PVWA, PSM) or stop the CPM service.
2. Wait for active PSM sessions to end; do not kill sessions without warning users.
3. Take a VM snapshot if the change record allows it.
4. Apply patches and reboot.
5. Confirm services are running and the component reconnects to the vault (check its log).
6. Run the smoke test below, then put the server back into the pool.
7. Move to the next server only after the previous one is healthy.

## Smoke test after each server
- PVWA: log in with LDAP and with MFA; browse a Safe.
- PSM: open an RDP and an SSH session; confirm the recording is visible afterwards.
- CPM: run **Verify** on a test account for each major platform; run one **Change**.

## After the window
- [ ] Delete VM snapshots within the agreed retention — snapshots of PAM servers contain sensitive data.
- [ ] Update the change record with evidence (smoke-test screenshots with no passwords visible).
- [ ] Watch CPM and PSM error rates for 24 hours.

## Rollback
If a smoke test fails and cannot be fixed within the window, revert the server (snapshot or patch uninstall), keep it out of the pool and record the failure in the change.

## Security notes
- Patching sessions go through PSM admin access and are recorded like any other privileged session.
- Never disable application control or endpoint protection on PSM servers "for the duration of patching".
