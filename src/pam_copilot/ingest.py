"""Ingestion: chunk runbooks + user-supplied docs, embed locally, store in Qdrant.

Chunking strategy:
- Runbooks: one chunk per ``##`` section (MarkdownNodeParser). Sections are written as
  self-contained units (Diagnosis, Resolution, ...), so they are the natural retrieval
  unit and give exact "RB-002 > Diagnosis" citations. Each chunk is prefixed with the
  runbook title so the embedding knows its context; title-only chunks are dropped.
- External PDFs: one document per page (keeps the page number for citations), then
  SentenceSplitter at 512 tokens / 64 overlap. HTML/TXT/MD: same splitter, no page.

Every chunk is scanned before indexing: secret-shaped strings are masked and chunks that
look like prompt injection are quarantined (not indexed) and reported.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from datetime import date
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from llama_index.core import Document
from llama_index.core.base.embeddings.base import BaseEmbedding
from llama_index.core.ingestion import IngestionPipeline
from llama_index.core.node_parser import MarkdownNodeParser, SentenceSplitter
from llama_index.core.schema import TextNode
from llama_index.embeddings.ollama import OllamaEmbedding
from llama_index.vector_stores.qdrant import QdrantVectorStore
from qdrant_client import QdrantClient

from pam_copilot.config import ROOT, Settings, load_settings
from pam_copilot.kb import load_runbooks
from pam_copilot.security import SECRET_KINDS, detect_injection, redact

# metadata the LLM/citations need but that would only add noise to the embedding
_NOT_EMBEDDED = ["source", "source_type", "runbook_id", "last_updated", "audience", "page", "order"]
_EXTERNAL_SUFFIXES = {".pdf", ".html", ".htm", ".md", ".txt"}


@dataclass
class IngestReport:
    indexed: int = 0
    quarantined: list[dict[str, str]] = field(default_factory=list)
    redacted_secrets: int = 0


def make_embedding(settings: Settings) -> BaseEmbedding:
    # nomic-embed-text is trained with task prefixes; omitting them costs recall
    return OllamaEmbedding(
        model_name=settings.embed_model,
        base_url=settings.ollama_url,
        query_instruction="search_query:",
        text_instruction="search_document:",
    )


def make_client(settings: Settings) -> QdrantClient:
    if settings.qdrant_url:
        return QdrantClient(url=settings.qdrant_url, api_key=settings.qdrant_api_key)
    settings.qdrant_path.mkdir(parents=True, exist_ok=True)
    return QdrantClient(path=str(settings.qdrant_path))


def _rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return path.name


def runbook_nodes(runbook_dir: Path) -> list[TextNode]:
    nodes: list[TextNode] = []
    parser = MarkdownNodeParser()
    for rb in load_runbooks(runbook_dir):
        doc = Document(text=rb.body)
        order = 0
        for section_node in parser.get_nodes_from_documents([doc]):
            heading, _, body = section_node.get_content().partition("\n")
            if not heading.startswith("## ") or not body.strip():
                continue  # title-only chunk
            section = heading[3:].strip()
            nodes.append(TextNode(
                text=f"{rb.title} - {section}\n{body.strip()}",
                metadata={
                    "source": _rel(rb.path), "source_type": "runbook", "runbook_id": rb.id,
                    "title": rb.title, "section": section, "page": None,
                    "last_updated": rb.last_updated.isoformat(), "audience": rb.audience,
                    "component": rb.component, "error_codes": list(rb.error_codes),
                    "order": order,
                },
            ))
            order += 1
    return nodes


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style", "noscript"):
            self._skip += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "noscript") and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip and data.strip():
            self.parts.append(data.strip())


def _external_documents(path: Path) -> list[Document]:
    base: dict[str, Any] = {
        "source": _rel(path), "source_type": "external", "runbook_id": None,
        "title": path.stem, "last_updated": date.fromtimestamp(path.stat().st_mtime).isoformat(),
        "audience": "operator", "component": "General", "error_codes": [],
    }
    if path.suffix.lower() == ".pdf":
        from pypdf import PdfReader

        return [
            Document(text=page.extract_text() or "",
                     metadata={**base, "page": i, "section": f"page {i}"})
            for i, page in enumerate(PdfReader(path).pages, start=1)
        ]
    raw = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() in (".html", ".htm"):
        extractor = _TextExtractor()
        extractor.feed(raw)
        raw = "\n".join(extractor.parts)
    return [Document(text=raw, metadata={**base, "page": None, "section": ""})]


def external_nodes(external_dir: Path) -> list[TextNode]:
    splitter = SentenceSplitter(chunk_size=512, chunk_overlap=64)
    docs = [
        doc
        for path in sorted(external_dir.glob("**/*"))
        if path.suffix.lower() in _EXTERNAL_SUFFIXES and path.name != "README.md"
        for doc in _external_documents(path)
    ]
    nodes = [n for n in splitter.get_nodes_from_documents(docs) if isinstance(n, TextNode)]
    for order, node in enumerate(nodes):
        node.metadata["order"] = order
    return nodes


def screen(nodes: list[TextNode], report: IngestReport) -> list[TextNode]:
    """Mask secret-shaped strings and quarantine chunks that look like prompt injection."""
    clean = []
    for node in nodes:
        reasons = detect_injection(node.text)
        if reasons:
            report.quarantined.append({
                "source": node.metadata["source"], "section": node.metadata["section"],
                "reasons": ", ".join(reasons),
            })
            continue
        masked = redact(node.text, SECRET_KINDS)
        report.redacted_secrets += len(masked.findings)
        node.text = masked.text
        node.excluded_embed_metadata_keys = _NOT_EMBEDDED
        node.excluded_llm_metadata_keys = list(node.metadata)
        clean.append(node)
    return clean


def build_index(
    settings: Settings,
    client: QdrantClient,
    embed_model: BaseEmbedding,
    external_dir: Path | None = None,
) -> IngestReport:
    """Rebuild the collection from scratch: runbooks + optional external docs."""
    # ponytail: full re-index each run (~150 chunks, seconds); use IngestionPipeline
    # docstore upserts if the corpus grows large enough for this to hurt.
    report = IngestReport()
    nodes = runbook_nodes(settings.kb_dir / "runbooks")
    ext = external_dir if external_dir is not None else settings.kb_dir / "external"
    if ext.is_dir():
        nodes += external_nodes(ext)
    nodes = screen(nodes, report)

    if client.collection_exists(settings.collection):
        client.delete_collection(settings.collection)
    store = QdrantVectorStore(collection_name=settings.collection, client=client)
    IngestionPipeline(transformations=[embed_model], vector_store=store).run(nodes=nodes)
    report.indexed = len(nodes)
    return report


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="pam-ingest", description=__doc__.splitlines()[0])
    parser.add_argument("--external", type=Path, help="external docs dir (default: kb/external)")
    args = parser.parse_args(argv)
    settings = load_settings()
    report = build_index(settings, make_client(settings), make_embedding(settings), args.external)
    print(f"indexed {report.indexed} chunks into '{settings.collection}', "
          f"masked {report.redacted_secrets} secret-like strings")
    for q in report.quarantined:
        print(f"QUARANTINED {q['source']} [{q['section']}]: {q['reasons']}", file=sys.stderr)


if __name__ == "__main__":
    main()
