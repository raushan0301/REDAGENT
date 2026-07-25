"""Shared subprocess-failure guard for tool wrappers.

Per the redagent-tool-wrapper skill contract: a wrapper must return a status
`Finding` on error, never raise and crash the agent loop. `_run()` methods can
raise FileNotFoundError (binary not on PATH), subprocess.TimeoutExpired, or
PermissionError — this turns any of those into a normalized status Finding so
one missing/misbehaving tool degrades gracefully instead of ending the
engagement.
"""

from __future__ import annotations

import subprocess

from agent.tools.schema import Finding

EXEC_ERRORS = (FileNotFoundError, subprocess.TimeoutExpired, PermissionError, OSError)


def exec_error_finding(tool_name: str, phase: str, target: str, exc: Exception) -> Finding:
    if isinstance(exc, FileNotFoundError):
        detail = f"'{tool_name}' binary not found on PATH. Install it to enable this tool."
    elif isinstance(exc, subprocess.TimeoutExpired):
        detail = f"{tool_name} timed out after {exc.timeout}s."
    elif isinstance(exc, PermissionError):
        detail = f"{tool_name} could not be executed (permission denied)."
    else:
        detail = f"{tool_name} failed to execute: {exc}"
    return Finding(tool=tool_name, phase=phase, target=target,
                   title="Tool unavailable", detail=detail)
