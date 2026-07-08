"""Report engine — CVSS 3.1 scoring + LLM-written narrative + PDF.

STUB (Month 2, Week 8). Auto-fills findings from PostgreSQL, uses the primary LLM
for the executive summary + remediation, maps each action to MITRE ATT&CK, and
exports a PDF. Raw tool output goes in the appendix (Finding.raw), never the loop.
"""

from __future__ import annotations

from agent.tools.schema import Finding


def generate_report(session_id: str, findings: list[Finding], out_path: str) -> str:
    """Render a professional pentest report to `out_path` (PDF). STUB (Week 8)."""
    raise NotImplementedError("generate_report stub — CVSS + LLM narrative + PDF (Week 8).")
