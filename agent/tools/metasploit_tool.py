"""Metasploit wrapper — exploitation. Via XMLRPC, NOT shelling out.

STUB (Month 2, Week 5). Async session handling: poll for completion. Default to
`check` before `exploit` where the module supports it. Destructive by nature —
requires explicit operator opt-in through the API. See the redagent-tool-wrapper skill.
"""

from __future__ import annotations

from langchain_core.tools import tool

from agent.scope import in_scope
from agent.tools.schema import Finding

TOOL_NAME = "metasploit"
PHASE = "exploitation"


@tool
def metasploit_run(target: str, module: str, run_exploit: bool = False) -> list[Finding]:
    """Run a Metasploit module against an in-scope lab target via XMLRPC. Defaults
    to `check` only; `run_exploit=True` is a destructive operator opt-in."""
    if not in_scope(target):
        return [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                        title="Out of scope",
                        detail="Target not in operator scope list; not executed.")]
    # TODO: connect msfrpc, set RHOSTS/module opts, `check` (or `exploit` if opt-in), poll session.
    return [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                    title="Not implemented",
                    detail=f"metasploit_run stub for module={module} (Week 5).")]
