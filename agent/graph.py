"""LangGraph state machine — the RedAgent brain (ReAct loop).

STUB (Month 1, Week 2). Builds the Reason -> Act -> Observe graph, binds the
tool belt, and enforces loop safety (seen_actions set + MAX_STEPS). Feed the
agent the compact running state from memory.py, never the raw transcript.
"""

from __future__ import annotations

from typing import Annotated, TypedDict

from agent.config import MAX_STEPS
from agent.tools.schema import Finding


class AgentState(TypedDict, total=False):
    target: str
    findings: list[Finding]
    seen_actions: set[str]   # never retry a failed technique (safety + token lever)
    step: int                # hard-capped by MAX_STEPS


def build_graph():
    """Construct and compile the LangGraph ReAct agent. TODO (Week 2):
    - bind tools: nmap_scan, nuclei_scan, subfinder_scan, sqlmap_scan,
      metasploit_run, search_cve_database
    - reason node (get_llm) -> tool node -> observe node -> loop
    - terminate on MAX_STEPS or when the planner signals done.
    """
    raise NotImplementedError(f"build_graph stub — implement ReAct loop, cap {MAX_STEPS} steps (Week 2).")
