"""Nuclei wrapper — scanning. Template-based vuln detection, one Finding per hit.

STUB (Month 1, Week 2): implement using `-jsonl` output; parse one Finding per
template match. Follow the five-stage contract — scope gate is mandatory.
See the redagent-tool-wrapper skill.
"""

from __future__ import annotations

from langchain_core.tools import tool

from agent.scope import in_scope
from agent.tools.schema import Finding

TOOL_NAME = "nuclei"
PHASE = "scanning"
TIMEOUT_S = 600


@tool
def nuclei_scan(target: str) -> list[Finding]:
    """Run Nuclei template-based vulnerability detection against an in-scope lab
    target. Use during scanning after recon has identified live services."""
    if not in_scope(target):
        return [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                        title="Out of scope",
                        detail="Target not in operator scope list; not executed.")]
    # TODO: subprocess ["nuclei", "-u", target, "-jsonl", ...] + parse to Findings.
    return [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                    title="Not implemented",
                    detail="nuclei_scan stub — implement -jsonl parsing (Week 2).")]
