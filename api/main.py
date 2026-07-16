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
import os
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.responses import FileResponse

from agent.graph import run_engagement
from agent.scope import add_scope, in_scope, list_scope, remove_scope, scope_summary
from api.models import EngagementRequest, EngagementStatus, ScopeEntry, ScopeList

app = FastAPI(title="RedAgent", version="0.1.0")

# Default engagement runner; overridable in tests via app.state.runner.
app.state.runner = run_engagement
# Optional report LLM override (tests inject a fake; None -> configured Groq).
app.state.report_llm = None

REPORT_DIR = "reports/out"

# In-memory engagement registry (swap for PostgreSQL-backed store later).
ENGAGEMENTS: dict[str, dict] = {}


def _status(eng: dict) -> EngagementStatus:
    return EngagementStatus(
        id=eng["id"], target=eng["target"], state=eng["state"],
        findings=eng["findings"], error=eng["error"],
    )


def _emit(eng: dict, ev: dict) -> None:
    """Record an event and fan it out to all live WebSocket subscribers.
    Must run on the event loop thread (see _run's call_soon_threadsafe)."""
    eng["log"].append(ev)
    for q in list(eng["subscribers"]):
        q.put_nowait(ev)


def _call_runner(runner, target: str, on_event):
    """Call the engagement runner, passing on_event only if it accepts it (so
    plain test fakes taking just `target` still work)."""
    import inspect
    try:
        params = inspect.signature(runner).parameters
        if "on_event" in params or any(p.kind == p.VAR_KEYWORD for p in params.values()):
            return runner(target, on_event=on_event)
    except (TypeError, ValueError):
        pass
    return runner(target)


async def _run(eng: dict, runner) -> None:
    loop = asyncio.get_running_loop()

    def on_event(ev: dict) -> None:
        # Called from the worker thread; hop back onto the loop to touch state.
        loop.call_soon_threadsafe(_emit, eng, ev)

    try:
        findings = await asyncio.to_thread(_call_runner, runner, eng["target"], on_event)
        eng["findings"] = list(findings)
        eng["state"] = "done"
    except Exception as exc:  # noqa: BLE001 - surface failure to the operator, don't crash
        eng["state"] = "error"
        eng["error"] = str(exc)
    finally:
        eng["event"].set()
        _emit(eng, {"type": "end"})  # already on the loop thread here


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
        "log": [], "subscribers": [],
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


@app.get("/scope", response_model=ScopeList)
def get_scope() -> ScopeList:
    return ScopeList(scope=list_scope())


@app.post("/scope", response_model=ScopeList)
def add_scope_entry(body: ScopeEntry) -> ScopeList:
    # add_scope enforces lab-only (private/loopback) and rejects malformed entries.
    if not add_scope(body.entry):
        raise HTTPException(status_code=400,
                            detail=f"Invalid or non-lab scope entry: {body.entry!r}")
    return ScopeList(scope=list_scope())


@app.delete("/scope", response_model=ScopeList)
def delete_scope_entry(body: ScopeEntry) -> ScopeList:
    if not remove_scope(body.entry):
        raise HTTPException(status_code=404, detail=f"Scope entry not found: {body.entry!r}")
    return ScopeList(scope=list_scope())


@app.post("/engagements/{engagement_id}/report")
def export_report(engagement_id: str, request: Request):
    eng = ENGAGEMENTS.get(engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Unknown engagement.")
    if not eng["findings"]:
        raise HTTPException(status_code=400, detail="No findings to report yet.")
    from reports.generator import generate_report

    os.makedirs(REPORT_DIR, exist_ok=True)
    out_path = os.path.join(REPORT_DIR, f"{engagement_id}.pdf")
    generate_report(engagement_id, eng["findings"], out_path,
                    llm=request.app.state.report_llm, target=eng["target"])
    return FileResponse(out_path, media_type="application/pdf",
                        filename=f"redagent-{engagement_id}.pdf")


@app.websocket("/ws/{engagement_id}")
async def engagement_ws(websocket: WebSocket, engagement_id: str) -> None:
    await websocket.accept()
    eng = ENGAGEMENTS.get(engagement_id)
    if eng is None:
        await websocket.send_json({"error": "unknown engagement"})
        await websocket.close()
        return

    # Register + snapshot the log in one synchronous section (no await) so no
    # event can interleave and be duplicated or missed.
    q: asyncio.Queue = asyncio.Queue()
    pending = list(eng["log"])
    eng["subscribers"].append(q)
    ended = any(e.get("type") == "end" for e in pending)

    try:
        await websocket.send_json({"type": "status", **_status(eng).model_dump()})
        for ev in pending:
            if ev.get("type") != "end":
                await websocket.send_json(ev)
        if not ended:
            while True:
                ev = await q.get()
                if ev.get("type") == "end":
                    break
                await websocket.send_json(ev)
        await websocket.send_json({"type": "status", **_status(eng).model_dump()})
    finally:
        if q in eng["subscribers"]:
            eng["subscribers"].remove(q)
        await websocket.close()
