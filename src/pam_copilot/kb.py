"""Load and validate the Markdown runbook knowledge base.

Each runbook is a Markdown file with YAML front matter. Front matter is parsed with
``yaml.safe_load`` only: ingested files are untrusted input and ``yaml.load`` can
construct arbitrary Python objects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import yaml

RUNBOOK_DIR = Path(__file__).resolve().parents[2] / "knowledge_base" / "runbooks"
AUDIENCES = ("operator", "admin")  # operator: visible to everyone; admin: admins only
COMPONENTS = ("CPM", "PSM", "PVWA", "Vault", "General")
_ID_RE = re.compile(r"RB-\d{3}")
_REQUIRED = ("id", "title", "component", "audience", "last_updated", "error_codes", "tags")


@dataclass(frozen=True)
class Runbook:
    id: str
    title: str
    component: str
    audience: str
    last_updated: date
    error_codes: tuple[str, ...]
    tags: tuple[str, ...]
    body: str
    path: Path


def parse_runbook(path: Path) -> Runbook:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        raise ValueError(f"{path.name}: missing YAML front matter")
    header, body = text[4:].split("\n---\n", 1)
    try:
        meta = yaml.safe_load(header)
    except yaml.YAMLError as exc:
        raise ValueError(f"{path.name}: invalid YAML front matter: {exc}") from exc
    if not isinstance(meta, dict):
        raise ValueError(f"{path.name}: front matter must be a mapping")

    missing = [key for key in _REQUIRED if key not in meta]
    if missing:
        raise ValueError(f"{path.name}: missing front matter keys {missing}")
    if not _ID_RE.fullmatch(str(meta["id"])):
        raise ValueError(f"{path.name}: id must look like RB-001, got {meta['id']!r}")
    if meta["audience"] not in AUDIENCES:
        raise ValueError(f"{path.name}: audience must be one of {AUDIENCES}")
    if meta["component"] not in COMPONENTS:
        raise ValueError(f"{path.name}: component must be one of {COMPONENTS}")
    if not isinstance(meta["last_updated"], date):
        raise ValueError(f"{path.name}: last_updated must be an ISO date (YYYY-MM-DD)")
    for key in ("error_codes", "tags"):
        if not isinstance(meta[key], list) or not all(isinstance(v, str) for v in meta[key]):
            raise ValueError(f"{path.name}: {key} must be a list of strings")

    return Runbook(
        id=meta["id"],
        title=str(meta["title"]),
        component=meta["component"],
        audience=meta["audience"],
        last_updated=meta["last_updated"],
        error_codes=tuple(meta["error_codes"]),
        tags=tuple(meta["tags"]),
        body=body.strip(),
        path=path,
    )


def load_runbooks(directory: Path = RUNBOOK_DIR) -> list[Runbook]:
    runbooks = [parse_runbook(p) for p in sorted(directory.glob("*.md"))]
    ids = [rb.id for rb in runbooks]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ValueError(f"duplicate runbook ids: {duplicates}")
    return runbooks
