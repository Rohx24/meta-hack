"""
NetworkTriage environment server.

Follows the openenv-core wire format so the OpenEnv validator passes.
Provides both stateful REST endpoints (single shared session) and a
WebSocket /ws endpoint (multi-session, one env per connection).

Endpoints:
  GET  /health   — health check  {"status": "healthy"}
  GET  /schema   — action/observation JSON schemas
  GET  /tasks    — list all tasks
  POST /reset    — start a new episode
  POST /step     — submit an action and receive next observation + reward
  GET  /state    — current episode state
  WS   /ws       — WebSocket session (openenv-core client compatible)

Runs on port 7860 (HF Spaces default).
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from network_triage_env import NetworkTriageEnv
from network_triage_env.models import NetworkTriageAction, NetworkTriageObservation, NetworkTriageState
from network_triage_env.tasks import list_tasks

app = FastAPI(
    title="NetworkTriage",
    description="Network Alert Triage Simulator — OpenEnv compliant",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Singleton REST session ────────────────────────────────────────────────────
_env = NetworkTriageEnv()


def _obs_payload(obs: NetworkTriageObservation) -> dict[str, Any]:
    """Serialize observation following openenv-core wire format."""
    d = obs.model_dump()
    reward = d.pop("reward", None)
    done = d.pop("done", False)
    d.pop("metadata", None)
    return {"observation": d, "reward": reward, "done": done}


# ── Request schemas ───────────────────────────────────────────────────────────

class ResetRequest(BaseModel):
    task_id: str = "alert-classify"
    seed: Optional[int] = None
    episode_id: Optional[str] = None


class StepRequest(BaseModel):
    action: dict[str, Any]
    timeout_s: Optional[float] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/metadata")
def metadata() -> dict:
    return {
        "name": "NetworkTriage",
        "description": "Network Alert Triage Simulator — AI agent acts as a NOC analyst classifying and triaging network alerts across 3 tasks of increasing difficulty.",
        "version": "1.0.0",
        "tags": ["openenv", "cybersecurity", "network-operations"],
    }


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "env": "NetworkTriage", "version": "1.0.0"}


@app.get("/schema")
def schema() -> dict:
    return {
        "action": NetworkTriageAction.model_json_schema(),
        "observation": NetworkTriageObservation.model_json_schema(),
        "state": NetworkTriageState.model_json_schema(),
    }


@app.post("/mcp")
async def mcp(request: Any = None) -> dict:
    """MCP JSON-RPC stub — returns tools/list response for openenv validate."""
    from fastapi import Request
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [],
            "serverInfo": {"name": "NetworkTriage", "version": "1.0.0"},
        },
    }


@app.get("/tasks")
def tasks() -> dict:
    return {"tasks": list_tasks()}


@app.post("/reset")
def reset(req: ResetRequest) -> dict:
    try:
        obs = _env.reset(
            task_id=req.task_id,
            seed=req.seed,
            episode_id=req.episode_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _obs_payload(obs)


@app.post("/step")
def step(req: StepRequest) -> dict:
    try:
        action = NetworkTriageAction.model_validate(req.action)
        obs = _env.step(action)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _obs_payload(obs)


@app.get("/state")
def state() -> dict:
    return _env.state.model_dump()


# ── WebSocket /ws — one env per connection ────────────────────────────────────

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket) -> None:
    """
    WebSocket session following openenv-core message protocol.

    Messages sent by client:
      {"type": "reset", "task_id": "alert-classify", ...}
      {"type": "step",  "action": {...}}
      {"type": "state"}

    Responses mirror REST format: {"observation": {...}, "reward": ..., "done": ...}
    """
    await websocket.accept()
    session_env = NetworkTriageEnv()

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_json({"error": "Invalid JSON"})
                continue

            msg_type = msg.get("type", "")

            if msg_type == "reset":
                try:
                    obs = session_env.reset(
                        task_id=msg.get("task_id", "alert-classify"),
                        seed=msg.get("seed"),
                        episode_id=msg.get("episode_id"),
                    )
                    await websocket.send_json(_obs_payload(obs))
                except Exception as exc:
                    await websocket.send_json({"error": str(exc)})

            elif msg_type == "step":
                try:
                    action = NetworkTriageAction.model_validate(msg.get("action", {}))
                    obs = session_env.step(action)
                    await websocket.send_json(_obs_payload(obs))
                except Exception as exc:
                    await websocket.send_json({"error": str(exc)})

            elif msg_type == "state":
                await websocket.send_json(session_env.state.model_dump())

            else:
                await websocket.send_json({"error": f"Unknown message type: {msg_type!r}"})

    except WebSocketDisconnect:
        pass
    finally:
        session_env.close()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    port = int(os.environ.get("PORT", 7860))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
