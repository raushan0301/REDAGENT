"""search_cve_database tool tests with an injected fake store (no ChromaDB)."""

from __future__ import annotations

import pytest

from agent.tools import cve_rag_tool
from agent.tools.cve_rag_tool import search_cve_database, set_store


class FakeStore:
    def __init__(self, rows):
        self.rows = rows
        self.last_min_cvss = None

    def query(self, text, top_n=5, min_cvss=7.0):
        self.last_min_cvss = min_cvss
        return self.rows


@pytest.fixture(autouse=True)
def reset_store():
    yield
    cve_rag_tool._store = None   # avoid leaking a fake into other tests


def test_maps_rows_to_findings():
    set_store(FakeStore([
        {"id": "CVE-2011-2523", "cvss": 10.0, "severity": "Critical",
         "description": "vsftpd 2.3.4 backdoor", "distance": 0.02},
    ]))
    findings = search_cve_database.invoke({"query": "vsftpd 2.3.4"})
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "cve_rag" and f.phase == "scanning"
    assert f.cve == "CVE-2011-2523" and f.cvss == 10.0 and f.severity == "Critical"
    assert f.target == "vsftpd 2.3.4"


def test_empty_results_returns_status_finding():
    set_store(FakeStore([]))
    findings = search_cve_database.invoke({"query": "nothing here"})
    assert len(findings) == 1
    assert findings[0].title == "No CVEs found"
    assert findings[0].cve is None


def test_min_cvss_passed_through():
    store = FakeStore([])
    set_store(store)
    search_cve_database.invoke({"query": "apache 2.4.49", "min_cvss": 9.0})
    assert store.last_min_cvss == 9.0
