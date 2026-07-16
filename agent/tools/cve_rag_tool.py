"""CVE RAG tool — queries ChromaDB (NOT a subprocess), so it does NOT follow the
subprocess wrapper contract and the redagent-tool-wrapper skill does not apply.

The agent calls this after every Nmap service/version detection to pick the right
exploit. The backing store is a module-level singleton (lazily the real ChromaDB
store); `set_store()` lets tests inject a fake — no ChromaDB / embeddings needed.
"""

from __future__ import annotations

from langchain_core.tools import tool

from agent.tools.schema import Finding

TOOL_NAME = "cve_rag"
PHASE = "scanning"

_store = None


def _get_store():
    global _store
    if _store is None:
        from agent.rag.store import CveStore
        _store = CveStore.default()
    return _store


def set_store(store) -> None:
    """Test/override hook — inject any object with `.query(text, top_n, min_cvss)`."""
    global _store
    _store = store


def _to_finding(query: str, row: dict) -> Finding:
    return Finding(
        tool=TOOL_NAME,
        phase=PHASE,
        target=query,
        title=row["id"],
        detail=(row.get("description") or "")[:200],
        cve=row["id"],
        cvss=row.get("cvss"),
        severity=row.get("severity"),
        evidence=f"RAG match for '{query}' (distance={row.get('distance')})",
    )


@tool
def search_cve_database(query: str, min_cvss: float = 7.0) -> list[Finding]:
    """Look up CVEs for a detected service+version string (e.g. 'vsftpd 2.3.4')
    via local ChromaDB similarity search. Returns top matches at or above
    min_cvss (default 7.0 — High and Critical only). Call after every Nmap
    service-version detection to choose an exploit."""
    rows = _get_store().query(query, top_n=5, min_cvss=min_cvss)
    if not rows:
        return [Finding(tool=TOOL_NAME, phase=PHASE, target=query,
                        title="No CVEs found",
                        detail=f"No CVEs at/above CVSS {min_cvss} for '{query}'.")]
    return [_to_finding(query, r) for r in rows]
