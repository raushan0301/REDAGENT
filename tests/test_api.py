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
    ENGAGEMENTS.clear()
    with TestClient(app) as c:
        yield c


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

    # WebSocket streams initial status, then final "done" with findings.
    with client.websocket_connect(f"/ws/{eid}") as ws:
        first = ws.receive_json()
        assert first["id"] == eid
        # Drain until we see the terminal state (initial may already be done).
        final = first
        while final["state"] == "running":
            final = ws.receive_json()
    assert final["state"] == "done"
    assert any(f["cve"] == "CVE-2011-2523" for f in final["findings"])

    # And GET now reflects the completed engagement.
    got = client.get(f"/engagements/{eid}").json()
    assert got["state"] == "done"
    assert len(got["findings"]) == 2


def test_ws_unknown_engagement_reports_error(client):
    with client.websocket_connect("/ws/nope") as ws:
        assert ws.receive_json() == {"error": "unknown engagement"}
