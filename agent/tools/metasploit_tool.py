"""Metasploit wrapper — exploitation. Via XMLRPC, NOT shelling out.

Safety (CLAUDE.md): default to `check` before `exploit`. `run_exploit` is an
explicit operator opt-in; even then we never fire if `check` reports the target
is safe. Async session handling: after execute we poll for a new session.

The RPC client is injectable (module-level singleton with `set_client()`), so the
logic is tested with a fake client — no live Metasploit. `default_client()` wires
the real pymetasploit3 client lazily.
"""

from __future__ import annotations

import time

from langchain_core.tools import tool

from agent.scope import in_scope
from agent.tools.schema import Finding

TOOL_NAME = "metasploit"
PHASE = "exploitation"

SAFE_VERDICT = "safe"
VULN_VERDICTS = ("vulnerable", "appears")
POLL_ATTEMPTS = 5
POLL_SLEEP_S = 2.0

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = default_client()
    return _client


def set_client(client) -> None:
    """Test/override hook — inject a client implementing the minimal protocol."""
    global _client
    _client = client


def _poll_new_session(client, before: set[str]) -> list[str]:
    """Poll for sessions that appeared after execute()."""
    for _ in range(POLL_ATTEMPTS):
        new = set(client.session_ids()) - before
        if new:
            return sorted(new)
        if POLL_SLEEP_S:
            time.sleep(POLL_SLEEP_S)
    return sorted(set(client.session_ids()) - before)


@tool
def metasploit_run(target: str, module: str, run_exploit: bool = False,
                   payload: str | None = None) -> list[Finding]:
    """Run a Metasploit exploit module against an in-scope lab target via XMLRPC.
    Defaults to `check` only. Set run_exploit=True only with explicit operator
    authorization; it will still not fire if `check` reports the target is safe."""
    if not in_scope(target):
        return [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                        title="Out of scope",
                        detail="Target not in operator scope list; not executed.")]

    client = _get_client()
    mod = client.use_exploit(module)
    mod.set("RHOSTS", target)
    verdict = (mod.check() or "unknown").lower()

    findings: list[Finding] = []
    if verdict in VULN_VERDICTS:
        findings.append(Finding(
            tool=TOOL_NAME, phase=PHASE, target=target,
            title=f"Vulnerable to {module}",
            detail=f"Metasploit check: target {verdict} vulnerable to {module}.",
            severity="High", mitre="T1210", evidence=f"check={verdict}"))
    elif verdict == SAFE_VERDICT:
        return [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                        title="Not vulnerable",
                        detail=f"Metasploit check: target safe against {module}.",
                        evidence=f"check={verdict}")]
    else:
        findings.append(Finding(
            tool=TOOL_NAME, phase=PHASE, target=target,
            title=f"Check inconclusive for {module}",
            detail=f"Metasploit check returned '{verdict}'.",
            evidence=f"check={verdict}"))

    # Exploit only on explicit opt-in and only when check did not say 'safe'.
    if run_exploit and verdict != SAFE_VERDICT:
        before = set(client.session_ids())
        mod.execute(payload=payload)
        for sid in _poll_new_session(client, before):
            findings.append(Finding(
                tool=TOOL_NAME, phase="post-exploit", target=target,
                title=f"Session opened via {module}",
                detail=f"Meterpreter/shell session {sid} obtained on {target}.",
                severity="Critical", mitre="T1210",
                evidence=f"session_id={sid}, payload={payload}"))
    return findings


# --- Real client adapter (lazy; integration only) --------------------------

class _RealModule:
    def __init__(self, mod):
        self._mod = mod

    def set(self, key, value):
        self._mod[key] = value

    def check(self) -> str:
        res = self._mod.check() or {}
        return res.get("code", "unknown")

    def execute(self, payload=None):
        return self._mod.execute(payload=payload) if payload else self._mod.execute()


class _RealMsfClient:
    def __init__(self, rpc):
        self._rpc = rpc

    def use_exploit(self, name):
        return _RealModule(self._rpc.modules.use("exploit", name))

    def session_ids(self):
        return [str(k) for k in self._rpc.sessions.list.keys()]


def default_client():
    """Build the real pymetasploit3 XMLRPC client from env. Lazy import."""
    import os
    from pymetasploit3.msfrpc import MsfRpcClient  # pip install pymetasploit3

    rpc = MsfRpcClient(
        os.environ.get("MSF_RPC_PASSWORD", "redagent"),
        server=os.environ.get("MSF_RPC_HOST", "127.0.0.1"),
        port=int(os.environ.get("MSF_RPC_PORT", "55553")),
        ssl=os.environ.get("MSF_RPC_SSL", "false").lower() == "true",
    )
    return _RealMsfClient(rpc)
