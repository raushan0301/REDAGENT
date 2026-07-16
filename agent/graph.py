"""LangGraph state machine — the RedAgent brain (ReAct loop).

Reason -> Act -> Observe, repeated until the agent says DONE, proposes an
already-tried action, or hits the MAX_STEPS cap.

Token discipline (CLAUDE.md): each reason step builds a FRESH prompt from the
compact `summarize_state` output — we do NOT accumulate/resend the full message
transcript. Loop safety: a `seen_actions` set blocks retrying a failed technique,
and MAX_STEPS guarantees graceful termination.

The LLM and tool list are injectable so the graph can be driven by a scripted
fake model in tests (no Groq key, no real tool subprocesses needed).
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional, TypedDict

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph

from agent.config import MAX_STEPS, STEP_SLEEP_S
from agent.memory import summarize_state
from agent.tools.nmap_tool import nmap_scan
from agent.tools.nuclei_tool import nuclei_scan
from agent.tools.schema import Finding

DEFAULT_TOOLS = [nmap_scan, nuclei_scan]

SYSTEM_PROMPT = (
    "You are RedAgent, an autonomous penetration-testing agent operating ONLY "
    "against in-scope lab targets. Work in phases: recon -> scanning -> "
    "exploitation. Given the current state, call the single most useful tool to "
    "advance the engagement. Do not repeat a tool call you have already tried. "
    "When no further useful action remains, reply with the word DONE and no tool call."
)


class AgentState(TypedDict, total=False):
    target: str
    findings: list[Finding]
    seen_actions: set[str]     # never retry a failed technique (safety + token lever)
    step: int                  # hard-capped by max_steps
    pending: Optional[AIMessage]  # last reasoning output awaiting execution


def _action_key(name: str, args: dict[str, Any]) -> str:
    """Stable identity for a tool call, so identical calls are de-duplicated."""
    return f"{name}:{json.dumps(args, sort_keys=True, default=str)}"


def build_graph(
    llm=None,
    tools: Optional[list] = None,
    max_steps: int = MAX_STEPS,
    step_sleep_s: float = STEP_SLEEP_S,
):
    """Compile the ReAct graph. `llm` must support `.bind_tools()` + `.invoke()`.
    If omitted, the configured Groq model is used (requires GROQ_API_KEY)."""
    if llm is None:
        from agent.config import get_llm
        llm = get_llm()
    tools = tools if tools is not None else DEFAULT_TOOLS
    tools_by_name = {t.name: t for t in tools}
    model = llm.bind_tools(tools)

    def reason(state: AgentState) -> dict:
        summary = summarize_state(state.get("findings", []), state.get("seen_actions", set()))
        prompt = [
            SystemMessage(SYSTEM_PROMPT),
            HumanMessage(f"Target: {state['target']}\nCurrent state:\n{summary}"),
        ]
        ai: AIMessage = model.invoke(prompt)
        return {"pending": ai}

    def act(state: AgentState) -> dict:
        ai = state["pending"]
        call = ai.tool_calls[0]
        name, args = call["name"], call.get("args", {})
        tool = tools_by_name[name]
        result = tool.invoke(args)
        findings = list(state.get("findings", [])) + list(result)
        seen = set(state.get("seen_actions", set())) | {_action_key(name, args)}
        if step_sleep_s:
            time.sleep(step_sleep_s)  # stay under Groq's 12K TPM
        return {"findings": findings, "seen_actions": seen, "step": state.get("step", 0) + 1}

    def route(state: AgentState) -> str:
        if state.get("step", 0) >= max_steps:
            return END
        ai = state.get("pending")
        if not ai or not getattr(ai, "tool_calls", None):
            return END  # agent said DONE
        call = ai.tool_calls[0]
        key = _action_key(call["name"], call.get("args", {}))
        if key in state.get("seen_actions", set()):
            return END  # proposed an already-tried action -> stop, don't loop
        if call["name"] not in tools_by_name:
            return END  # hallucinated tool
        return "act"

    graph = StateGraph(AgentState)
    graph.add_node("reason", reason)
    graph.add_node("act", act)
    graph.set_entry_point("reason")
    graph.add_conditional_edges("reason", route, {"act": "act", END: END})
    graph.add_edge("act", "reason")
    return graph.compile()


def run_engagement(target: str, llm=None, tools: Optional[list] = None,
                   max_steps: int = MAX_STEPS, step_sleep_s: float = STEP_SLEEP_S) -> list[Finding]:
    """Run a full engagement against `target` and return accumulated findings."""
    app = build_graph(llm=llm, tools=tools, max_steps=max_steps, step_sleep_s=step_sleep_s)
    initial: AgentState = {"target": target, "findings": [], "seen_actions": set(), "step": 0}
    # 2 graph nodes per step; give langgraph headroom over our own max_steps cap.
    final = app.invoke(initial, config={"recursion_limit": max_steps * 2 + 5})
    return final.get("findings", [])
