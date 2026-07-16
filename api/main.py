"""FastAPI backend — routes + WebSocket. Agent orchestration entry point.

Endpoints:
  GET  /health                -> status + active scope
  POST /engagements           -> start an engagement against an in-scope target
  GET  /engagements/{id}       -> status + findings
  WS   /ws/{id}                -> live status stream (initial + final)

The engagement runner is held on `app.state.runner` (defaults to
graph.run_engagement) so tests can inject a fake runner — no Groq key, no real
tool subprocesses. Scope is re-validated server-side; never trust the client.

Run: uvicorn api.main:app --reload
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, WebSocket

from agent.graph import run_engagement
from agent.scope import in_scope, scope_summary
from api.models import EngagementRequest, EngagementStatus

app = FastAPI(title="RedAgent", version="0.1.0")

# Default engagement runner; overridable in tests via app.state.runner.
app.state.runner = run_engagement

# In-memory engagement registry (swap for PostgreSQL-backed store later).
ENGAGEMENTS: dict[str, dict] = {}


def _status(eng: dict) -> EngagementStatus:
    return EngagementStatus(
        id=eng["id"], target=eng["target"], state=eng["state"],
        findings=eng["findings"], error=eng["error"],
    )


async def _run(eng: dict, runner) -> None:
    try:
        findings = await asyncio.to_thread(runner, eng["target"])
        eng["findings"] = list(findings)
        eng["state"] = "done"
    except Exception as exc:  # noqa: BLE001 - surface failure to the operator, don't crash
        eng["state"] = "error"
        eng["error"] = str(exc)
    finally:
        eng["event"].set()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "scope": scope_summary()}


@app.post("/engagements", response_model=EngagementStatus)
async def create_engagement(req: EngagementRequest, request: Request) -> EngagementStatus:
    # Server-side scope gate — defense in depth on top of the per-tool gate.
    if not in_scope(req.target):
        raise HTTPException(status_code=403, detail=f"Target {req.target!r} not in scope; refused.")
    eid = uuid4().hex
    eng = {
        "id": eid, "target": req.target, "state": "running",
        "findings": [], "error": None, "event": asyncio.Event(),
    }
    ENGAGEMENTS[eid] = eng
    asyncio.create_task(_run(eng, request.app.state.runner))
    return _status(eng)


@app.get("/engagements/{engagement_id}", response_model=EngagementStatus)
async def get_engagement(engagement_id: str) -> EngagementStatus:
    eng = ENGAGEMENTS.get(engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Unknown engagement.")
    return _status(eng)


@app.websocket("/ws/{engagement_id}")
async def engagement_ws(websocket: WebSocket, engagement_id: str) -> None:
    await websocket.accept()
    eng = ENGAGEMENTS.get(engagement_id)
    if eng is None:
        await websocket.send_json({"error": "unknown engagement"})
        await websocket.close()
        return
    # Send current status, then the final status once the engagement completes.
    await websocket.send_json(_status(eng).model_dump())
    if eng["state"] == "running":
        await eng["event"].wait()
        await websocket.send_json(_status(eng).model_dump())
    await websocket.close()
