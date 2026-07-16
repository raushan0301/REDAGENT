"""Tests for the scope-management API and the report-export endpoint."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import agent.scope as scope
from agent.tools.schema import Finding
from api.main import app, ENGAGEMENTS


def _fake_runner(target: str) -> list[Finding]:
    return [Finding(tool="cve_rag", phase="scanning", target=target,
                    title="CVE-2011-2523", detail="vsftpd backdoor",
                    cve="CVE-2011-2523", cvss=10.0, severity="Critical")]


class FakeLLM:
    def invoke(self, messages):
        class _Msg:
            content = "Narrative text."
        return _Msg()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("REDAGENT_SCOPE", raising=False)
    scope._RUNTIME_SCOPE.clear()
    app.state.runner = _fake_runner
    app.state.report_llm = FakeLLM()
    ENGAGEMENTS.clear()
    with TestClient(app) as c:
        yield c
    scope._RUNTIME_SCOPE.clear()


# --- scope management ------------------------------------------------------

def test_scope_starts_empty(client):
    assert client.get("/scope").json()["scope"] == []


def test_add_private_scope_entry(client):
    r = client.post("/scope", json={"entry": "10.0.0.0/24"})
    assert r.status_code == 200
    assert "10.0.0.0/24" in r.json()["scope"]
    # and it takes effect immediately on the gate
    assert client.post("/engagements", json={"target": "10.0.0.5"}).status_code == 200


def test_public_scope_entry_rejected(client):
    r = client.post("/scope", json={"entry": "8.8.8.0/24"})
    assert r.status_code == 400


def test_malformed_scope_entry_rejected(client):
    assert client.post("/scope", json={"entry": "not-a-network"}).status_code == 400


def test_remove_scope_entry(client):
    client.post("/scope", json={"entry": "10.0.0.0/24"})
    r = client.request("DELETE", "/scope", json={"entry": "10.0.0.0/24"})
    assert r.status_code == 200
    assert r.json()["scope"] == []
    assert client.request("DELETE", "/scope", json={"entry": "10.0.0.0/24"}).status_code == 404


# --- report export ---------------------------------------------------------

def test_report_404_for_unknown_engagement(client):
    assert client.post("/engagements/nope/report").status_code == 404


def test_report_exports_pdf_for_completed_engagement(client):
    client.post("/scope", json={"entry": "10.0.0.0/24"})
    eid = client.post("/engagements", json={"target": "10.0.0.5"}).json()["id"]
    # drain the WS so the background engagement completes
    with client.websocket_connect(f"/ws/{eid}") as ws:
        msg = ws.receive_json()
        while msg["state"] == "running":
            msg = ws.receive_json()

    r = client.post(f"/engagements/{eid}/report")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-"
