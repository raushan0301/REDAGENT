"""Attack chain planner.

Builds a multi-step plan before executing and drives adaptive replanning: if an
exploit fails, pick the next candidate rather than retrying (seen_actions).

STUB (Month 2, Week 6).
"""

from __future__ import annotations

from agent.tools.schema import Finding


def plan_next(findings: list[Finding], seen_actions: set[str]) -> str | None:
    """Decide the next action given current findings. Return an action key, or
    None when the engagement is complete / no untried path remains. STUB (Week 6)."""
    raise NotImplementedError("plan_next stub — implement chain planner + fallback (Week 6).")
