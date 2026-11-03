"""FastAPI service: /ask, /diagnose, /audit, behind bearer-token role authentication.

Roles come from two static tokens (OPERATOR_TOKEN, ADMIN_TOKEN) compared in constant time.
In production the role would come from OIDC/SAML group claims; the RBAC enforcement
downstream (Qdrant payload filter) does not change.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from pam_copilot.audit import verify
from pam_copilot.config import Settings, load_settings
from pam_copilot.diagnose import Diagnosis, diagnose
from pam_copilot.rag import Answer, Copilot, LLMUnavailable, Role, build_copilot

_MIN_TOKEN_LEN = 24


@lru_cache
def get_settings() -> Settings:
    return load_settings()


@lru_cache
def get_copilot() -> Copilot:
    return build_copilot(get_settings())


def check_tokens(settings: Settings) -> None:
    tokens = [settings.operator_token, settings.admin_token]
    if any(t is None or len(t) < _MIN_TOKEN_LEN for t in tokens) or len(set(tokens)) != 2:
        raise RuntimeError(
            f"OPERATOR_TOKEN and ADMIN_TOKEN must be set, distinct, and at least "
            f"{_MIN_TOKEN_LEN} characters. Generate one with: "
            "python -c 'import secrets; print(secrets.token_urlsafe(32))'")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    check_tokens(get_settings())  # refuse to start with missing or weak credentials
    yield


app = FastAPI(title="PAM Copilot", version="1.0.0", lifespan=lifespan)


@dataclass(frozen=True)
class Identity:
    user: str
    role: Role


def identity(authorization: Annotated[str, Header()] = "") -> Identity:
    settings = get_settings()
    token = authorization.removeprefix("Bearer ").strip().encode()
    roles: tuple[tuple[Role, str | None], ...] = (
        ("admin", settings.admin_token), ("operator", settings.operator_token))
    for role, expected in roles:
        if expected and secrets.compare_digest(token, expected.encode()):
            return Identity(user=role, role=role)
    raise HTTPException(401, "invalid or missing bearer token")


def admin(who: Annotated[Identity, Depends(identity)]) -> Identity:
    if who.role != "admin":
        raise HTTPException(403, "admin role required")
    return who


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2_000)


class DiagnoseRequest(BaseModel):
    log: str = Field(min_length=1, max_length=20_000)


@app.exception_handler(LLMUnavailable)
async def llm_down(_: Request, exc: LLMUnavailable) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": str(exc)})


@app.get("/health")
def health() -> dict[str, Any]:
    cp = get_copilot()
    client = cp.retriever.store.client
    collection = cp.settings.collection
    chunks = client.count(collection).count if client.collection_exists(collection) else 0
    return {"status": "ok" if chunks else "empty_index", "chunks": chunks,
            "model": cp.settings.chat_model}


@app.get("/whoami")
def whoami(who: Annotated[Identity, Depends(identity)]) -> Identity:
    return who


@app.post("/ask")
def ask(req: AskRequest, who: Annotated[Identity, Depends(identity)]) -> Answer:
    return get_copilot().ask(req.question, role=who.role, user=who.user)


@app.post("/diagnose")
def diagnose_log(req: DiagnoseRequest, who: Annotated[Identity, Depends(identity)]) -> Diagnosis:
    return diagnose(get_copilot(), req.log, role=who.role, user=who.user)


@app.get("/audit")
def audit(_: Annotated[Identity, Depends(admin)],
          limit: Annotated[int, Query(ge=1, le=500)] = 50) -> dict[str, Any]:
    log = get_copilot().audit
    ok, n = verify(log.path)
    return {"chain_ok": ok, "checked": n, "entries": log.tail(limit)}
