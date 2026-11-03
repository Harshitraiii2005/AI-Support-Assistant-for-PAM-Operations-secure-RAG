"""Offline fixtures: in-memory Qdrant + deterministic embedding + recording fake LLM."""

from __future__ import annotations

import dataclasses
import math
import re
import zlib
from pathlib import Path

import pytest
from llama_index.core.base.embeddings.base import BaseEmbedding
from qdrant_client import QdrantClient

from pam_copilot.audit import AuditLog
from pam_copilot.config import Settings, load_settings
from pam_copilot.ingest import IngestReport, build_index
from pam_copilot.rag import Copilot, Retriever


class HashEmbedding(BaseEmbedding):
    """Bag-of-words hashed into 512 dims: deterministic, no model, good enough to rank."""

    def _vec(self, text: str) -> list[float]:
        v = [0.0] * 512
        for tok in re.findall(r"[a-z0-9]+", text.lower()):
            v[zlib.crc32(tok.encode()) % 512] += 1.0
        norm = math.sqrt(sum(x * x for x in v)) or 1.0
        return [x / norm for x in v]

    def _get_query_embedding(self, query: str) -> list[float]:
        return self._vec(query)

    def _get_text_embedding(self, text: str) -> list[float]:
        return self._vec(text)

    async def _aget_query_embedding(self, query: str) -> list[float]:
        return self._vec(query)


class FakeChat:
    def __init__(self, reply: str = "Follow the documented resolution steps [1].") -> None:
        self.reply = reply
        self.prompts: list[str] = []

    def __call__(self, system: str, user: str) -> str:
        self.prompts.append(system + "\n" + user)
        return self.reply


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return dataclasses.replace(
        load_settings(), qdrant_url=None, collection="test", audit_path=tmp_path / "audit.jsonl",
        min_score=0.1, operator_token="o" * 32, admin_token="a" * 32,
    )


@pytest.fixture
def index(settings: Settings, tmp_path: Path) -> tuple[QdrantClient, HashEmbedding, IngestReport]:
    client, embed = QdrantClient(location=":memory:"), HashEmbedding()
    report = build_index(settings, client, embed, external_dir=tmp_path / "no-external")
    return client, embed, report


@pytest.fixture
def chat() -> FakeChat:
    return FakeChat()


@pytest.fixture
def copilot(
    settings: Settings, index: tuple[QdrantClient, HashEmbedding, IngestReport], chat: FakeChat
) -> Copilot:
    client, embed, _ = index
    retriever = Retriever(settings, client, embed)
    return Copilot(settings, retriever, chat, AuditLog(settings.audit_path))
