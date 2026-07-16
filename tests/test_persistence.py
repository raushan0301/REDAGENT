"""Persistence round-trip tests against stdlib sqlite3 (portable SQL, no mocks)."""

from __future__ import annotations

import sqlite3

import pytest

from agent.memory import persist_findings, load_findings
from agent.tools.schema import Finding
from api.db import FindingStore


@pytest.fixture
def store():
    conn = sqlite3.connect(":memory:")
    s = FindingStore(conn, placeholder="?")
    s.init_schema()
    yield s
    conn.close()


def _findings(target="10.0.0.5"):
    return [
        Finding(tool="nmap", phase="recon", target=target,
                title="Open port 21/tcp — vsftpd 2.3.4", detail="ftp",
                service="vsftpd", version="2.3.4"),
        Finding(tool="nuclei", phase="scanning", target=target,
                title="vsftpd backdoor [CVE-2011-2523]", detail="critical",
                cve="CVE-2011-2523", cvss=10.0, severity="Critical",
                raw='{"template-id":"x"}'),
    ]


def test_save_returns_count_and_round_trips(store):
    n = store.save("sess-1", _findings())
    assert n == 2
    loaded = store.load("sess-1")
    assert [f.tool for f in loaded] == ["nmap", "nuclei"]      # insertion order preserved
    assert loaded[1].cve == "CVE-2011-2523" and loaded[1].cvss == 10.0
    assert loaded[1].raw == '{"template-id":"x"}'             # full fidelity via JSON column


def test_sessions_are_isolated(store):
    store.save("sess-a", _findings("10.0.0.5"))
    store.save("sess-b", _findings("10.0.0.6"))
    a = store.load("sess-a")
    assert {f.target for f in a} == {"10.0.0.5"}
    assert len(store.load("sess-b")) == 2


def test_empty_save_is_noop(store):
    assert store.save("sess-x", []) == 0
    assert store.load("sess-x") == []


def test_load_unknown_session_empty(store):
    assert store.load("nope") == []


def test_memory_helpers_use_injected_store(store):
    # persist_findings / load_findings must not require PostgreSQL when a store is passed.
    assert persist_findings("sess-m", _findings(), store=store) == 2
    loaded = load_findings("sess-m", store=store)
    assert len(loaded) == 2 and loaded[0].tool == "nmap"
