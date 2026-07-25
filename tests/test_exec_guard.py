"""Tests for graceful degradation when a tool binary is missing/times out —
discovered via a live run where a missing `nuclei` binary crashed the agent
loop instead of returning a status Finding, violating the wrapper contract."""

from __future__ import annotations

import subprocess

import pytest

from agent.tools.exec_guard import exec_error_finding
from agent.tools.nmap_tool import nmap_scan
from agent.tools.nuclei_tool import nuclei_scan
from agent.tools.sqlmap_tool import sqlmap_scan
from agent.tools.subfinder_tool import subfinder_scan


@pytest.fixture(autouse=True)
def scoped(monkeypatch):
    monkeypatch.setenv("REDAGENT_SCOPE", "10.0.0.0/24")
    import importlib
    import agent.scope
    importlib.reload(agent.scope)
    for mod in ("agent.tools.nmap_tool", "agent.tools.nuclei_tool",
                "agent.tools.sqlmap_tool", "agent.tools.subfinder_tool"):
        importlib.import_module(mod).in_scope = agent.scope.in_scope


def test_exec_error_finding_missing_binary():
    f = exec_error_finding("nuclei", "scanning", "10.0.0.5", FileNotFoundError())
    assert f.title == "Tool unavailable"
    assert "not found on PATH" in f.detail


def test_exec_error_finding_timeout():
    exc = subprocess.TimeoutExpired(cmd="nmap", timeout=300)
    f = exec_error_finding("nmap", "recon", "10.0.0.5", exc)
    assert "timed out after 300s" in f.detail


@pytest.mark.parametrize("tool_fn,module_path,run_name,call_args", [
    (nmap_scan, "agent.tools.nmap_tool", "_run", {"target": "10.0.0.5"}),
    (nuclei_scan, "agent.tools.nuclei_tool", "_run", {"target": "10.0.0.5"}),
    (sqlmap_scan, "agent.tools.sqlmap_tool", "_run", {"target": "10.0.0.5"}),
    (subfinder_scan, "agent.tools.subfinder_tool", "_run", {"target": "10.0.0.5"}),
])
def test_missing_binary_returns_status_finding_not_raise(monkeypatch, tool_fn, module_path,
                                                          run_name, call_args):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(f"{module_path}.{run_name}", fake_run)
    findings = tool_fn.invoke(call_args)   # must NOT raise
    assert len(findings) == 1
    assert findings[0].title == "Tool unavailable"
