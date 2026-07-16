"""ReAct loop orchestration tests — driven by a scripted fake LLM and fake tools,
so no Groq key and no real tool subprocesses are needed.

Covers: reason->act->observe wiring, DONE termination, seen_actions blocking
retries, hallucinated-tool guard, and the hard max_steps cap.
"""

from __future__ import annotations

from langchain_core.messages import AIMessage
from langchain_core.tools import tool

from agent.graph import build_graph, run_engagement
from agent.tools.schema import Finding


# --- Fake tools (no subprocess) --------------------------------------------

@tool
def nmap_scan(target: str) -> list[Finding]:
    """Fake nmap."""
    return [Finding(tool="nmap", phase="recon", target=target,
                    title="Open port 21/tcp — vsftpd 2.3.4", detail="ftp",
                    service="vsftpd", version="2.3.4")]


@tool
def nuclei_scan(target: str) -> list[Finding]:
    """Fake nuclei."""
    return [Finding(tool="nuclei", phase="scanning", target=target,
                    title="vsftpd backdoor [CVE-2011-2523]", detail="critical",
                    cve="CVE-2011-2523", cvss=10.0, severity="Critical")]


FAKE_TOOLS = [nmap_scan, nuclei_scan]


# --- Scripted LLM ----------------------------------------------------------

def _call(name, target="10.0.0.5"):
    return AIMessage(content="", tool_calls=[
        {"name": name, "args": {"target": target}, "id": name}
    ])


def _done():
    return AIMessage(content="DONE")


class ScriptedLLM:
    """Returns pre-scripted AIMessages in order; ignores the prompt."""
    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        msg = self.script[min(self.calls, len(self.script) - 1)]
        self.calls += 1
        return msg


def _run(script, **kw):
    return run_engagement("10.0.0.5", llm=ScriptedLLM(script), tools=FAKE_TOOLS,
                          step_sleep_s=0, **kw)


# --- Tests -----------------------------------------------------------------

def test_full_chain_nmap_then_nuclei_then_done():
    findings = _run([_call("nmap_scan"), _call("nuclei_scan"), _done()])
    tools_used = [f.tool for f in findings]
    assert tools_used == ["nmap", "nuclei"]
    assert any(f.cve == "CVE-2011-2523" for f in findings)


def test_done_immediately_yields_no_findings():
    assert _run([_done()]) == []


def test_seen_actions_blocks_identical_retry():
    # nmap, then propose the SAME nmap call again -> loop must stop (no retry).
    findings = _run([_call("nmap_scan"), _call("nmap_scan"), _call("nmap_scan")])
    assert len([f for f in findings if f.tool == "nmap"]) == 1


def test_hallucinated_tool_terminates():
    findings = _run([_call("bogus_tool")])
    assert findings == []


def test_max_steps_cap_enforced():
    # LLM would keep scanning different targets forever; cap at 3 steps.
    script = [_call("nmap_scan", target=f"10.0.0.{i}") for i in range(10)]
    findings = run_engagement("10.0.0.5", llm=ScriptedLLM(script), tools=FAKE_TOOLS,
                              step_sleep_s=0, max_steps=3)
    assert len(findings) == 3   # exactly max_steps tool executions


def test_seen_actions_allows_same_tool_different_target():
    findings = _run([_call("nmap_scan", "10.0.0.5"),
                     _call("nmap_scan", "10.0.0.6"),
                     _done()])
    targets = {f.target for f in findings}
    assert targets == {"10.0.0.5", "10.0.0.6"}
