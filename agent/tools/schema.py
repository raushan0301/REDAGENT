"""Shared findings schema for RedAgent.

Every tool wrapper emits this one shape. The agent reasons over `Finding`s only —
it must never see raw tool output (that lives in `raw`, for the report appendix).
Defined once here; import it everywhere. See the `redagent-tool-wrapper` skill.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class Finding(BaseModel):
    tool: str                          # e.g. "nmap"
    phase: str                         # recon | scanning | exploitation | post-exploit
    target: str
    title: str                         # short human label
    detail: str                        # normalized description (keep concise — token lever)
    service: Optional[str] = None      # e.g. "vsftpd"
    version: Optional[str] = None      # e.g. "2.3.4"
    cve: Optional[str] = None
    cvss: Optional[float] = None
    severity: Optional[str] = None     # Low | Medium | High | Critical
    evidence: Optional[str] = None     # trimmed raw snippet / PoC pointer
    mitre: Optional[str] = None        # ATT&CK technique id, e.g. "T1190"
    raw: Optional[str] = None          # full raw output — report appendix only, NOT the agent loop


PHASES = ("recon", "scanning", "exploitation", "post-exploit")


def severity_from_cvss(cvss: Optional[float]) -> Optional[str]:
    """Map a CVSS 3.1 base score to a severity band."""
    if cvss is None:
        return None
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0.0:
        return "Low"
    return "None"
