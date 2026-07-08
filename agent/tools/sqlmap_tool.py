"""SQLMap wrapper — exploitation. Detection ONLY by default (safe mode).

NON-NEGOTIABLE (CLAUDE.md): default is detection (`--batch`, no `--dump`).
Destructive extraction requires an explicit operator opt-in arg passed through
the API — never hardcoded. STUB (Month 1, Week 3).
See the redagent-tool-wrapper skill.
"""

from __future__ import annotations

from langchain_core.tools import tool

from agent.scope import in_scope
from agent.tools.schema import Finding

TOOL_NAME = "sqlmap"
PHASE = "exploitation"
TIMEOUT_S = 900


@tool
def sqlmap_scan(target: str, allow_dump: bool = False) -> list[Finding]:
    """Test an in-scope lab URL for SQL injection. Detection only by default;
    `allow_dump=True` is a destructive operator opt-in and must not be defaulted on."""
    if not in_scope(target):
        return [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                        title="Out of scope",
                        detail="Target not in operator scope list; not executed.")]
    # TODO: ["sqlmap", "-u", target, "--batch"] (+ "--dump" ONLY if allow_dump).
    return [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                    title="Not implemented",
                    detail="sqlmap_scan stub — detection-only default (Week 3).")]
