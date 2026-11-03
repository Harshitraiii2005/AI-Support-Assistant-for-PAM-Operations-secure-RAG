import json
import stat
from pathlib import Path

from pam_copilot.audit import AuditLog, verify


def test_chain_verifies_and_detects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(3):
        log.append(kind="ask", input=f"question {i}")
    assert verify(path) == (True, 3)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    AuditLog(path).append(kind="ask", input="after restart")  # chain resumes from disk
    assert verify(path) == (True, 4)

    lines = path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["input"] = "edited"
    lines[1] = json.dumps(entry, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    assert verify(path) == (False, 2)

    path.write_text("\n".join(lines[:1] + lines[2:]) + "\n")  # deleted entry
    assert verify(path)[0] is False
