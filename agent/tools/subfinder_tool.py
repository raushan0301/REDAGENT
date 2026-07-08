"""Subfinder wrapper — recon. Subdomain enumeration -> Findings (phase=recon).

STUB (Month 1, Week 3). Follow the five-stage contract; scope gate mandatory.
See the redagent-tool-wrapper skill.
"""

from __future__ import annotations

from langchain_core.tools import tool

from agent.scope import in_scope
from agent.tools.schema import Finding

TOOL_NAME = "subfinder"
PHASE = "recon"
TIMEOUT_S = 300


@tool
def subfinder_scan(target: str) -> list[Finding]:
    """Enumerate subdomains of an in-scope lab target. Use during recon to widen
    the attack surface before scanning."""
    if not in_scope(target):
        return [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                        title="Out of scope",
                        detail="Target not in operator scope list; not executed.")]
    # TODO: subprocess ["subfinder", "-d", target, "-silent"] + one Finding per subdomain.
    return [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                    title="Not implemented",
                    detail="subfinder_scan stub — implement (Week 3).")]
