"""Runtime settings, read from environment variables (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    ollama_url: str
    chat_model: str
    embed_model: str
    qdrant_url: str | None  # None -> embedded on-disk store at qdrant_path
    qdrant_api_key: str | None
    qdrant_path: Path
    collection: str
    kb_dir: Path
    top_k: int
    min_score: float  # below this top-1 similarity we refuse without calling the LLM
    audit_path: Path
    operator_token: str | None
    admin_token: str | None


def load_settings() -> Settings:
    env = os.environ.get
    data = Path(env("DATA_DIR", str(ROOT / "data")))
    return Settings(
        ollama_url=env("OLLAMA_URL", "http://localhost:11434"),
        chat_model=env("CHAT_MODEL", "qwen2.5:7b-instruct"),
        embed_model=env("EMBED_MODEL", "nomic-embed-text"),
        qdrant_url=env("QDRANT_URL") or None,
        qdrant_api_key=env("QDRANT_API_KEY") or None,
        qdrant_path=data / "qdrant",
        collection=env("QDRANT_COLLECTION", "pam_kb"),
        kb_dir=Path(env("KB_DIR", str(ROOT / "knowledge_base"))),
        top_k=int(env("TOP_K", "5")),
        min_score=float(env("MIN_SCORE", "0.60")),
        audit_path=Path(env("AUDIT_PATH", str(data / "audit.jsonl"))),
        operator_token=env("OPERATOR_TOKEN") or None,
        admin_token=env("ADMIN_TOKEN") or None,
    )
