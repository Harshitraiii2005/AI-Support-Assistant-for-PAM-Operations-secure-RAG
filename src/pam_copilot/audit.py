"""Append-only, hash-chained audit log of every question and answer (JSONL).

Each entry stores the SHA-256 of the previous entry, so editing or deleting a line breaks
the chain and ``verify`` reports the first bad line. Only redacted text is ever written.
Limitation: someone with write access can rewrite the whole chain; ship the latest hash
to a SIEM / WORM store periodically to anchor it.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(entry: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        # ponytail: in-process lock, single API worker; use a DB / log shipper for multi-worker
        self._lock = threading.Lock()
        entries = self.tail(1)
        self._last = entries[-1]["hash"] if entries else GENESIS

    def append(self, **event: Any) -> dict[str, Any]:
        with self._lock:
            entry = {"ts": datetime.now(UTC).isoformat(), **event, "prev_hash": self._last}
            entry["hash"] = _digest(entry)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
            self._last = entry["hash"]
            return entry

    def tail(self, n: int) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines[-n:] if line]


def verify(path: Path) -> tuple[bool, int]:
    """Return (ok, n): n = entries checked if ok, else the 1-based line that breaks the chain."""
    prev = GENESIS
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    for lineno, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False, lineno
        claimed = entry.pop("hash", None)
        if entry.get("prev_hash") != prev or claimed != _digest(entry):
            return False, lineno
        prev = claimed
    return True, len(lines)


if __name__ == "__main__":
    from pam_copilot.config import load_settings

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else load_settings().audit_path
    ok, n = verify(target)
    print(f"{target}: {'OK, ' + str(n) + ' entries' if ok else 'BROKEN at line ' + str(n)}")
    sys.exit(0 if ok else 1)
