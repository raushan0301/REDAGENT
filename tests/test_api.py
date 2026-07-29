"""FastAPI route + WebSocket tests via TestClient — fake runner injected, so no
Groq key and no real tool subprocesses. Scope re-validation exercised offline
(literal private IPs, no DNS)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agent.tools.schema import Finding
from api.main import app, ENGAGEMENTS


def _fake_runner(target: str) -> list[Finding]:
    return [Finding(tool="nmap", phase="recon", target=target,
                    title="Open port 21/tcp — vsftpd 2.3.4", detail="ftp"),
            Finding(tool="nuclei", phase="scanning", target=target,
                    title="vsftpd backdoor [CVE-2011-2523]", detail="critical",
                    cve="CVE-2011-2523", cvss=10.0, severity="Critical")]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("REDAGENT_SCOPE", "10.0.0.0/24")
    app.state.runner = _fake_runner
    c = TestClient(app, headers={"X-API-Key": "redagent-dev-key"})
    yield c
    ENGAGEMENTS.clear()


def test_health_reports_scope(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_out_of_scope_target_refused(client):
    r = client.post("/engagements", json={"target": "10.9.9.9"})
    assert r.status_code == 403
    assert "not in scope" in r.json()["detail"]


def test_public_target_refused(client):
    r = client.post("/engagements", json={"target": "8.8.8.8"})
    assert r.status_code == 403


def test_unknown_engagement_404(client):
    assert client.get("/engagements/does-not-exist").status_code == 404


def test_engagement_lifecycle_via_websocket(client):
    r = client.post("/engagements", json={"target": "10.0.0.5"})
    assert r.status_code == 200
    eid = r.json()["id"]
    assert r.json()["state"] == "running"

    # WebSocket streams typed frames; collect status frames until "done".
    with client.websocket_connect(f"/ws/{eid}?token=redagent-dev-key") as ws:
        msgs = []
        while True:
            frame = ws.receive_json()
            msgs.append(frame)
            if frame.get("type") == "status" and frame.get("state") == "done":
                break
    assert msgs[-1]["state"] == "done"
    assert any(f["cve"] == "CVE-2011-2523" for f in msgs[-1]["findings"])

    # And GET now reflects the completed engagement.
    got = client.get(f"/engagements/{eid}").json()
    assert got["state"] == "done"
    assert len(got["findings"]) == 2


def test_auth_rejection_without_key():
    unauth_client = TestClient(app)
    r = unauth_client.get("/health")
    assert r.status_code == 401


def test_ws_auth_rejection_without_token():
    client = TestClient(app)
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/nope") as ws:
            ws.receive_json()


def test_ws_unknown_engagement_reports_error(client):
    with client.websocket_connect("/ws/nope?token=redagent-dev-key") as ws:
        assert ws.receive_json() == {"error": "unknown engagement"}


def test_ws_streams_reasoning_events(client):
    # A runner that accepts on_event emits per-step reason/act/observe frames.
    def emitting_runner(target, on_event=None):
        if on_event:
            on_event({"type": "reason", "step": 0, "text": "Selected nmap_scan"})
            on_event({"type": "act", "step": 0, "text": "Executing nmap_scan"})
            on_event({"type": "observe", "step": 1, "text": "nmap_scan returned 1 finding(s)"})
        return _fake_runner(target)

    app.state.runner = emitting_runner
    eid = client.post("/engagements", json={"target": "10.0.0.5"}).json()["id"]

    types: list[str] = []
    with client.websocket_connect(f"/ws/{eid}?token=redagent-dev-key") as ws:
        try:
            while True:
                types.append(ws.receive_json().get("type"))
        except Exception:
            pass
            
    assert "reason" in types
    assert "act" in types
    assert "observe" in types
    assert "status" in types


def test_rate_limit_exceeded():
    client = TestClient(app, headers={"X-API-Key": "redagent-dev-key"})
    for _ in range(5):
        client.post("/engagements", json={"target": "10.0.0.5"})
    r = client.post("/engagements", json={"target": "10.0.0.5"})
    assert r.status_code == 429
