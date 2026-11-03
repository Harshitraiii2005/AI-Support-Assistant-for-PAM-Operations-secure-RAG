"""Synthetic CPM / PSM / PVWA / Vault-style error log generator.

Everything produced here is SIMULATED. Error codes use the ``SIM-`` prefix and do not
correspond to any vendor product; hostnames use the reserved ``.example`` TLD; IPs are
private 10.0.0.0/8 addresses; secrets are random strings generated at runtime.

``CATALOG`` is the single source of truth for error code -> runbook ground truth. A test
cross-checks it against runbook front matter so eval labels cannot drift from the docs.

With ``with_secrets=True`` each sample gets a DEBUG line that leaks fake credentials, the
way real debug logs do. Every sensitive value placed in the text is recorded in
``LogSample.sensitive`` so the redaction filter can be scored, not eyeballed.
"""

from __future__ import annotations

import argparse
import json
import random
import string
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import NamedTuple


@dataclass(frozen=True)
class ErrorSpec:
    code: str
    runbook_id: str
    category: str
    message: str  # str.format template over the sample context
    preamble: tuple[str, ...] | None = None  # overrides the component default

    @property
    def component(self) -> str:
        return _COMPONENT_BY_PREFIX[self.code.split("-")[1]]


@dataclass(frozen=True)
class LogSample:
    id: str
    error_code: str
    component: str
    category: str
    runbook_id: str
    log: str
    sensitive: list[dict[str, str]]  # [{"type": "password", "value": "..."}]
    simulated: bool = True


_COMPONENT_BY_PREFIX = {"CPM": "CPM", "PSM": "PSM", "PVWA": "PVWA", "VLT": "Vault"}
_NODE_PREFIX = {"CPM": "CPM", "PSM": "PSM", "PVWA": "PVWA", "Vault": "REPL"}

_CPM_STARTUP = ("Starting CPM processing cycle", "Logging on to Vault {vault_host}")

CATALOG: tuple[ErrorSpec, ...] = (
    # RB-001 onboarding
    ErrorSpec("SIM-PVWA-4201", "RB-001", "pvwa_duplicate_account",
              "Add account failed: an account with address '{host}' and username '{account}' "
              "already exists in Safe '{safe}'"),
    ErrorSpec("SIM-PVWA-4202", "RB-001", "pvwa_platform_inactive",
              "Add account failed: platform '{platform}' is inactive or not allowed for "
              "Safe '{safe}'"),
    # RB-002 password change
    ErrorSpec("SIM-CPM-2101", "RB-002", "cpm_target_unreachable",
              "Change password failed for account '{account}' (Safe: {safe}): target {host} "
              "({ip}:{cpm_port}) unreachable, connection timed out after 30s"),
    ErrorSpec("SIM-CPM-2104", "RB-002", "cpm_password_policy_rejected",
              "Change password failed for account '{account}' on {host}: target rejected the new "
              "password (complexity/history requirements not met)"),
    ErrorSpec("SIM-CPM-2107", "RB-002", "cpm_current_password_invalid",
              "Change password failed for account '{account}' on {host}: logon with current "
              "password was rejected by the target"),
    # RB-003 verify
    ErrorSpec("SIM-CPM-2110", "RB-003", "cpm_verify_mismatch",
              "Verify password failed for account '{account}' on {host}: password stored in "
              "vault does not match the target"),
    ErrorSpec("SIM-CPM-2112", "RB-003", "cpm_account_locked",
              "Verify password failed for account '{account}' on {host}: account is locked or "
              "disabled on the target"),
    # RB-004 reconcile
    ErrorSpec("SIM-CPM-2201", "RB-004", "cpm_no_reconcile_account",
              "Reconcile password failed for account '{account}' (Safe: {safe}): no reconcile "
              "account is linked to the account or platform '{platform}'"),
    ErrorSpec("SIM-CPM-2203", "RB-004", "cpm_reconcile_insufficient_rights",
              "Reconcile password failed for account '{account}' on {host}: reconcile account "
              "has insufficient privileges to reset the password"),
    # RB-005 dependencies
    ErrorSpec("SIM-CPM-2301", "RB-005", "cpm_service_dependency_failed",
              "Password changed for account '{account}' but dependency update failed on {host}: "
              "Windows service '{service}' could not be restarted with the new credentials"),
    ErrorSpec("SIM-CPM-2302", "RB-005", "cpm_task_dependency_failed",
              "Password changed for account '{account}' but dependency update failed on {host}: "
              "scheduled task '{task}' could not be updated (access denied)"),
    # RB-006 CPM <-> vault
    ErrorSpec("SIM-CPM-2001", "RB-006", "cpm_vault_auth_failed",
              "CPM component user failed to authenticate to Vault {vault_host}: credential file "
              "was rejected", _CPM_STARTUP),
    ErrorSpec("SIM-CPM-2002", "RB-006", "cpm_component_user_suspended",
              "CPM component user is suspended in Vault {vault_host}; password management tasks "
              "are halted", _CPM_STARTUP),
    # RB-007 safe permissions
    ErrorSpec("SIM-PVWA-4301", "RB-007", "pvwa_safe_permission_denied",
              "User '{user}' is not authorized to perform '{safe_action}' on account '{account}' "
              "in Safe '{safe}'"),
    ErrorSpec("SIM-PVWA-4302", "RB-007", "pvwa_dual_control_pending",
              "Access to account '{account}' in Safe '{safe}' requires dual-control approval; "
              "request {request} is pending"),
    # RB-008 PSM session launch
    ErrorSpec("SIM-PSM-3101", "RB-008", "psm_component_blocked",
              "Connection component '{conn_component}' failed to initialize for user '{user}': "
              "client application was blocked by application control policy"),
    ErrorSpec("SIM-PSM-3104", "RB-008", "psm_no_session_available",
              "Session for user '{user}' could not start: no remote desktop session available "
              "on {node} (session limit reached)"),
    ErrorSpec("SIM-PSM-3107", "RB-008", "psm_credential_retrieval_failed",
              "Session for user '{user}' aborted: PSM could not retrieve credentials for account "
              "'{account}' in Safe '{safe}'"),
    # RB-009 PSM target connection
    ErrorSpec("SIM-PSM-3201", "RB-009", "psm_target_timeout",
              "Connection to target {host} ({ip}:{port}) timed out for session of user '{user}'"),
    ErrorSpec("SIM-PSM-3203", "RB-009", "psm_target_auth_rejected",
              "Target {host} rejected credentials for account '{account}' (network level "
              "authentication failed)"),
    ErrorSpec("SIM-PSM-3205", "RB-009", "psm_host_key_mismatch",
              "Target {host} presented an unexpected host key/certificate fingerprint; "
              "connection refused by policy"),
    # RB-010 recordings
    ErrorSpec("SIM-PSM-3301", "RB-010", "psm_recording_upload_failed",
              "Failed to upload recording for session {session} to Vault {vault_host}; file kept "
              "in local queue (attempt {attempt})"),
    ErrorSpec("SIM-PSM-3302", "RB-010", "psm_recording_disk_low",
              "Recordings folder on {node} is below the free-space threshold ({free_pct}% free); "
              "new sessions may be refused"),
    # RB-011 PVWA login
    ErrorSpec("SIM-PVWA-4101", "RB-011", "pvwa_ldap_bind_failed",
              "LDAP authentication failed for user '{user}': bind to directory server {dc_host} "
              "failed"),
    ErrorSpec("SIM-PVWA-4104", "RB-011", "pvwa_user_suspended",
              "User '{user}' is suspended after {attempt} consecutive failed logon attempts"),
    ErrorSpec("SIM-PVWA-4106", "RB-011", "pvwa_user_not_mapped",
              "User '{user}' authenticated via LDAP but is not mapped to any vault user or group; "
              "access denied"),
    # RB-012 MFA / SSO
    ErrorSpec("SIM-PVWA-4110", "RB-012", "pvwa_radius_timeout",
              "RADIUS authentication for user '{user}' timed out after 10s waiting for the "
              "RADIUS server"),
    ErrorSpec("SIM-PVWA-4120", "RB-012", "pvwa_saml_clock_skew",
              "SAML response for user '{user}' rejected: assertion outside validity window "
              "(clock skew {skew}s)"),
    ErrorSpec("SIM-PVWA-4122", "RB-012", "pvwa_saml_signature_invalid",
              "SAML response for user '{user}' rejected: signature does not match the configured "
              "identity provider certificate"),
    # RB-013 backup
    ErrorSpec("SIM-VLT-5201", "RB-013", "vault_backup_auth_failed",
              "Backup replication from Vault {vault_host} failed: backup user was rejected "
              "(credential file invalid or user suspended)"),
    ErrorSpec("SIM-VLT-5203", "RB-013", "vault_backup_disk_low",
              "Backup replication aborted: destination volume on {backup_host} has insufficient "
              "free space ({free_pct}% free)"),
    # RB-014 DR replication
    ErrorSpec("SIM-VLT-5301", "RB-014", "vault_dr_lag",
              "DR replication lag is {lag} minutes (threshold 60); last replicated transaction "
              "{txn}"),
    ErrorSpec("SIM-VLT-5303", "RB-014", "vault_dr_unreachable",
              "DR Vault cannot connect to production Vault {vault_host} ({ip})"),
)

# Each component writes a different line layout, as real PAM components do.
_LINE_FORMAT = {
    "CPM": "{ts:%d/%m/%Y %H:%M:%S} {node} [{level}] {text}",
    "PSM": "{ts:%Y-%m-%dT%H:%M:%S}.{ms:03d}Z {node} [Session:{session}] {level} {text}",
    "PVWA": "{ts:%Y-%m-%d %H:%M:%S},{ms:03d} {level:<5} [PVWA.WebServices] [req={request}] {text}",
    "Vault": "{ts:%d/%m/%Y %H:%M:%S} {node} {level} {text}",
}
_PREAMBLE = {
    "CPM": ("Processing account '{account}' (Safe: {safe}, Platform: {platform})",
            "Resolved {host} to {ip}",
            "Opening connection to {host}:{cpm_port}"),
    "PSM": ("Session {session} requested by '{user}' for account '{account}' on {host} "
            "via {conn_component}",
            "Fetching connection details from Vault {vault_host}"),
    "PVWA": ("Request {request} received from user '{user}' (client {ip})",),
    "Vault": ("Scheduled replication job {request} started",),
}
_FOLLOW_UP = {
    "CPM": "Will retry in {retry} minutes (attempt {attempt} of 5)",
    "PSM": "Session {session} ended with status FAILED",
    "PVWA": "Request {request} completed with result FAILED",
    "Vault": "Job {request} finished with status FAILED; next run in {retry} minutes",
}
_LEAKS = {
    "CPM": ("Change script arguments: -address {host} -user {account} -oldpass {password} "
            "-newpass {new_password}",
            "Connection string: Server={host};User Id={account};Password={password};"),
    "PSM": ("Connection parameters: target={host} user={account} password={password}",
            "Vault REST call with header Authorization: Bearer {token}"),
    "PVWA": ("Ticketing integration call with header x-api-key: {api_key}",
             "LDAP bind as 'svc_pam_ldap' with password '{password}'"),
    "Vault": ("Backup utility started with arguments /user:backup_svc /password:{password}",
              "Monitoring webhook called with token={token}"),
}
# context key -> redaction type the Phase 4 filter must catch
_SENSITIVE = {
    "password": "password", "new_password": "password", "token": "token",
    "api_key": "api_key", "ip": "ip", "host": "hostname", "vault_host": "hostname",
    "dc_host": "hostname", "backup_host": "hostname",
}


class _Target(NamedTuple):
    account: str
    platform: str
    safe: str
    host_prefix: str
    cpm_port: int  # port CPM uses to manage the password
    port: int  # port PSM uses for the session
    conn_component: str


_TARGETS = (
    _Target("root", "UnixSSH", "LNX-Root-PRD", "srv-lnx", 22, 22, "PSM-SSH"),
    _Target("oracle", "UnixSSH", "LNX-App-PRD", "srv-ora", 22, 22, "PSM-SSH"),
    _Target("Administrator", "WinServerLocal", "WIN-LocalAdmin-PRD", "srv-win", 445, 3389,
            "PSM-RDP"),
    _Target("svc_backup", "WinDomain", "WIN-Service-Accounts", "srv-app", 445, 3389, "PSM-RDP"),
    _Target("sa", "MSSql", "DB-MSSQL-PRD", "srv-sql", 1433, 1433, "PSM-SSMS"),
    _Target("netadmin", "CiscoSSH", "NET-Devices-PRD", "rtr-core", 22, 22, "PSM-SSH"),
)
_USERS = ("jdoe", "asmith", "mkhan", "lchen", "rpatel", "ops_oncall")
_SERVICES = ("BackupAgentSvc", "AppSchedulerSvc", "ReportingEngine")
_TASKS = ("Nightly-DataExport", "Ops-LogCleanup", "Weekly-Reindex")
_SAFE_ACTIONS = ("Retrieve", "Use", "List", "Initiate CPM change")
_PASSWORD_CHARS = string.ascii_letters + string.digits + "!#$%&*+-=?@^_"
_B64URL = string.ascii_letters + string.digits + "-_"
_JWT_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"  # base64url of {"alg":"HS256","typ":"JWT"}
_BASE_TIME = datetime(2026, 10, 1)


def _rand(rng: random.Random, chars: str, length: int) -> str:
    return "".join(rng.choice(chars) for _ in range(length))


def _context(rng: random.Random, component: str) -> dict[str, str | int]:
    t = rng.choice(_TARGETS)
    n = rng.randint
    return {
        "account": t.account, "safe": t.safe, "platform": t.platform,
        "port": t.port, "cpm_port": t.cpm_port, "conn_component": t.conn_component,
        "host": f"{t.host_prefix}-{n(1, 60):02d}.corp.example",
        "ip": f"10.{n(0, 255)}.{n(0, 255)}.{n(1, 254)}",
        "vault_host": f"vault-{n(1, 2):02d}.pam.corp.example",
        "dc_host": f"dc-{n(1, 4):02d}.corp.example",
        "backup_host": f"bkp-{n(1, 2):02d}.pam.corp.example",
        "node": f"{_NODE_PREFIX[component]}{n(1, 3):02d}",
        "user": rng.choice(_USERS),
        "session": f"{rng.getrandbits(32):08x}",
        "request": f"{rng.getrandbits(32):08x}",
        "txn": n(100_000, 999_999),
        "service": rng.choice(_SERVICES),
        "task": rng.choice(_TASKS),
        "safe_action": rng.choice(_SAFE_ACTIONS),
        "attempt": n(2, 5),
        "retry": rng.choice((60, 240, 1440)),
        "free_pct": n(1, 9),
        "skew": n(301, 900),
        "lag": n(61, 480),
        "password": _rand(rng, _PASSWORD_CHARS, n(14, 20)),
        "new_password": _rand(rng, _PASSWORD_CHARS, n(14, 20)),
        "token": f"{_JWT_HEADER}.{_rand(rng, _B64URL, 48)}.{_rand(rng, _B64URL, 43)}",
        "api_key": _rand(rng, string.ascii_letters + string.digits, 40),
    }


def _sample(index: int, spec: ErrorSpec, rng: random.Random, with_secrets: bool) -> LogSample:
    component = spec.component
    ctx = _context(rng, component)
    entries = [("INFO", t) for t in spec.preamble or _PREAMBLE[component]]
    if with_secrets:
        entries.append(("DEBUG", rng.choice(_LEAKS[component])))
    entries += [("ERROR", f"{spec.code}: {spec.message}"), ("INFO", _FOLLOW_UP[component])]

    ts = _BASE_TIME + timedelta(seconds=rng.randint(0, 30 * 86_400))
    lines = []
    for level, template in entries:
        ts += timedelta(milliseconds=rng.randint(20, 1500))
        text = template.format(**ctx)
        lines.append(
            _LINE_FORMAT[component].format(
                ts=ts, ms=ts.microsecond // 1000, level=level, text=text, **ctx
            )
        )
    log = "\n".join(lines)
    sensitive = [
        {"type": kind, "value": str(ctx[key])}
        for key, kind in _SENSITIVE.items()
        if str(ctx[key]) in log
    ]
    return LogSample(
        id=f"sim-{index:04d}",
        error_code=spec.code,
        component=component,
        category=spec.category,
        runbook_id=spec.runbook_id,
        log=log,
        sensitive=sensitive,
    )


def generate(
    count: int, *, seed: int | None = None, with_secrets: bool = False, code_prefix: str = ""
) -> list[LogSample]:
    """Generate ``count`` samples, cycling through matching codes so every code is covered."""
    specs = [s for s in CATALOG if s.code.startswith(code_prefix.upper())]
    if not specs:
        raise ValueError(f"no error codes start with {code_prefix!r}")
    rng = random.Random(seed)
    order = rng.sample(specs, len(specs))
    return [_sample(i, order[i % len(order)], rng, with_secrets) for i in range(count)]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="pam-loggen",
        description="Generate SIMULATED CPM/PSM/PVWA/Vault-style error logs (fictional data).",
    )
    parser.add_argument("-n", "--count", type=int, default=5, help="number of samples")
    parser.add_argument("--seed", type=int, help="RNG seed for reproducible output")
    parser.add_argument("--with-secrets", action="store_true",
                        help="plant fake credentials in DEBUG lines (for redaction tests)")
    parser.add_argument("--code", default="",
                        help="only codes starting with this prefix, e.g. SIM-PSM or SIM-CPM-2104")
    parser.add_argument("--jsonl", type=Path,
                        help="write labeled samples to this JSONL file instead of printing")
    args = parser.parse_args(argv)

    try:
        samples = generate(args.count, seed=args.seed, with_secrets=args.with_secrets,
                           code_prefix=args.code)
    except ValueError as exc:
        parser.error(str(exc))

    if args.jsonl:
        args.jsonl.parent.mkdir(parents=True, exist_ok=True)
        with args.jsonl.open("w", encoding="utf-8") as fh:
            for s in samples:
                fh.write(json.dumps(asdict(s)) + "\n")
        print(f"wrote {len(samples)} simulated samples to {args.jsonl}", file=sys.stderr)
    else:
        for s in samples:
            print(f"# SIMULATED LOG ({s.id}) - fictional data, not from a real system\n{s.log}\n")


if __name__ == "__main__":
    main()
