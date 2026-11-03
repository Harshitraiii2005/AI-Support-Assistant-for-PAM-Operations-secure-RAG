from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from pam_copilot import api
from pam_copilot.rag import Copilot

OP, ADMIN = {"Authorization": "Bearer " + "o" * 32}, {"Authorization": "Bearer " + "a" * 32}


@pytest.fixture
def client(copilot: Copilot, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("OPERATOR_TOKEN", "o" * 32)
    monkeypatch.setenv("ADMIN_TOKEN", "a" * 32)
    api.get_settings.cache_clear()
    monkeypatch.setattr(api, "get_copilot", lambda: copilot)
    with TestClient(api.app) as c:
        yield c
    api.get_settings.cache_clear()


def test_auth_and_roles(client: TestClient) -> None:
    assert client.post("/ask", json={"question": "hi"}).status_code == 401
    assert client.post("/ask", json={"question": "hi"},
                       headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/whoami", headers=OP).json() == {"user": "operator", "role": "operator"}
    assert client.get("/audit", headers=OP).status_code == 403


def test_ask_diagnose_and_audit(client: TestClient) -> None:
    r = client.post("/ask", json={"question": "What does SIM-CPM-2104 mean?"}, headers=OP)
    assert r.status_code == 200 and r.json()["citations"]
    r = client.post("/diagnose", json={"log": "ERROR SIM-PSM-3104: no session"}, headers=OP)
    assert r.json()["runbook_id"] == "RB-008"
    audit = client.get("/audit", headers=ADMIN).json()
    assert audit["chain_ok"] and [e["kind"] for e in audit["entries"]] == ["ask", "diagnose"]


def test_input_limits(client: TestClient) -> None:
    assert client.post("/ask", json={"question": "x" * 2001}, headers=OP).status_code == 422
    assert client.post("/ask", json={"question": ""}, headers=OP).status_code == 422


def test_refuses_to_start_with_weak_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATOR_TOKEN", "short")
    monkeypatch.setenv("ADMIN_TOKEN", "a" * 32)
    api.get_settings.cache_clear()
    with pytest.raises(RuntimeError), TestClient(api.app):
        pass
    api.get_settings.cache_clear()
