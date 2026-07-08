"""CVE RAG tool — queries ChromaDB (NOT a subprocess), so it does NOT follow the
subprocess wrapper contract and the redagent-tool-wrapper skill does not apply.

Agent calls this after every Nmap service/version detection to pick the right
exploit. STUB (Month 3, Week 10) — see agent/rag/ for the pipeline + store.
"""

from __future__ import annotations

from langchain_core.tools import tool

from agent.tools.schema import Finding, severity_from_cvss

TOOL_NAME = "cve_rag"
PHASE = "scanning"


@tool
def search_cve_database(query: str, min_cvss: float = 7.0) -> list[Finding]:
    """Look up CVEs for a detected service+version string (e.g. 'vsftpd 2.3.4')
    via local ChromaDB similarity search. Returns top matches at or above
    min_cvss (default 7.0 — High and Critical only). Call after every Nmap
    service-version detection to choose an exploit."""
    # TODO: embed query (all-MiniLM-L6-v2) -> ChromaDB cosine search on `nvd_cves`
    #       -> top-N filtered by min_cvss -> Findings with cve/cvss/severity set.
    _ = severity_from_cvss  # used once the store is wired
    return [Finding(tool=TOOL_NAME, phase=PHASE, target=query,
                    title="Not implemented",
                    detail="search_cve_database stub — wire ChromaDB store (Week 10).")]
