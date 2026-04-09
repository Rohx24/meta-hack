"""
NetworkTriage baseline inference script.

Mandatory stdout format (per OpenEnv spec):
    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>

Environment variables:
    API_BASE_URL  — OpenAI-compatible API base URL (default: https://api.openai.com/v1)
    MODEL_NAME    — Model identifier (default: gpt-4o-mini)
    HF_TOKEN      — API key (also checks OPENAI_API_KEY)
    SERVER_URL    — Environment server URL (default: http://localhost:7860)
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Optional

import httpx
from openai import OpenAI

# ── Configuration ─────────────────────────────────────────────────────────────

API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o-mini")
HF_TOKEN = os.getenv("HF_TOKEN") or os.getenv("OPENAI_API_KEY")
SERVER_URL = os.getenv("SERVER_URL", "http://localhost:7860")
BENCHMARK = "network-triage"

client: Optional[OpenAI] = None
http = httpx.Client(base_url=SERVER_URL, timeout=60.0)

# ── Mandatory log helpers (exact format required by spec) ─────────────────────

def _clamp_open_score(value: float) -> float:
    """Keep task scores inside the validator-required open interval."""
    return max(0.01, min(0.99, value))


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    reward = _clamp_open_score(reward)
    error_val = error if error else "null"
    done_val = str(done).lower()
    # Truncate action string to keep line readable
    action_str = action[:120].replace("\n", " ") if action else "null"
    print(
        f"[STEP] step={step} action={action_str} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: list[float]) -> None:
    score = _clamp_open_score(score)
    rewards_str = ",".join(f"{_clamp_open_score(r):.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.2f} rewards={rewards_str}",
        flush=True,
    )


# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert Network Operations Center (NOC) analyst with 10 years of experience.

CLASSIFICATION OPTIONS:
  port_scan, normal, ddos, brute_force, malware, data_exfiltration,
  reconnaissance, lateral_movement, privilege_escalation, unknown

ACTION OPTIONS:
  block, escalate, ignore, rate_limit, monitor, investigate

RULES:
  - NEVER block legitimate/normal traffic (heavy penalty)
  - Repeated IPs across steps warrant escalated response
  - Red herrings exist: scheduled backups, CDN traffic look suspicious but are normal
  - For priority_order: CRITICAL threats first, then HIGH, then lower severity

Respond with ONLY valid JSON:
{
  "classifications": {"<alert_id>": "<type>", ...},
  "actions":         {"<alert_id>": "<action>", ...},
  "priority_order":  ["<alert_id>", ...],
  "reasoning":       "<brief explanation>"
}"""


# ── LLM call ─────────────────────────────────────────────────────────────────

def _format_alert(a: dict) -> str:
    return (
        f"[{a['alert_id']}] {a['alert_type_raw']}\n"
        f"  {a['source_ip']}:{a['source_port']} -> {a['dest_ip']}:{a['dest_port']} "
        f"({a['protocol']}) | {a['bytes_transferred']:,}B | sev={a['severity']} "
        f"threat={a['threat_score']} geo={a.get('geo_location','?')}\n"
        f"  tags: {', '.join(a.get('tags',[]))}\n"
        f"  {a['description'][:200]}"
    )


def _build_prompt(obs_data: dict) -> str:
    alerts = obs_data.get("alerts", [])
    ctx = obs_data.get("context", {})
    prev = obs_data.get("previous_actions", [])
    step = obs_data.get("step", 0)
    max_steps = obs_data.get("max_steps", 1)
    task_id = obs_data.get("task_id", "")

    parts = [
        f"TASK: {obs_data.get('task_name','')} | Step {step+1}/{max_steps}",
        obs_data.get("instructions", ""),
        "=" * 50,
        f"ALERTS ({len(alerts)}):",
    ]
    for a in alerts:
        parts.append(_format_alert(a))

    if ctx.get("repeated_ips"):
        parts.append("CONTEXT — repeated IPs:")
        for ip, cnt in ctx["repeated_ips"].items():
            parts.append(f"  {ip}: seen {cnt}x")

    if prev:
        parts.append("PRIOR DECISIONS (last 6):")
        for pa in prev[-6:]:
            parts.append(f"  {pa['alert_id']}: {pa['classification']} -> {pa['action']}")

    ids = [a["alert_id"] for a in alerts]
    parts.append(f"Classify these IDs: {ids}")
    if task_id == "triage-under-load":
        parts.append("Include 'priority_order' with ALL 20 alert IDs.")
    return "\n".join(parts)


def _call_llm(prompt: str, retries: int = 3) -> dict:
    for attempt in range(retries):
        try:
            active_client = _get_client()
            resp = active_client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                max_tokens=2048,
            )
            raw = resp.choices[0].message.content.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            return json.loads(raw)
        except json.JSONDecodeError:
            if attempt < retries - 1:
                time.sleep(1)
        except Exception:
            if attempt < retries - 1:
                time.sleep(2)
    return {"classifications": {}, "actions": {}, "priority_order": [], "reasoning": "fallback_response"}


def _get_client() -> OpenAI:
    global client
    if client is None:
        if not HF_TOKEN:
            raise RuntimeError("Missing HF_TOKEN/OPENAI_API_KEY; using fallback actions.")
        client = OpenAI(api_key=HF_TOKEN, base_url=API_BASE_URL)
    return client


def _sanitize_action_dict(raw_action: object, alert_ids: list[str], task_id: str) -> dict:
    """Coerce model output into the action schema the environment expects."""
    payload = raw_action if isinstance(raw_action, dict) else {}
    raw_classifications = payload.get("classifications", {})
    raw_actions = payload.get("actions", {})
    raw_priority = payload.get("priority_order", [])

    classifications = raw_classifications if isinstance(raw_classifications, dict) else {}
    actions = raw_actions if isinstance(raw_actions, dict) else {}

    sanitized = {
        "classifications": {aid: str(classifications.get(aid, "unknown")) for aid in alert_ids},
        "actions": {aid: str(actions.get(aid, "monitor")) for aid in alert_ids},
        "reasoning": str(payload.get("reasoning", "auto_fallback")),
    }

    if task_id == "triage-under-load":
        seen: set[str] = set()
        priority_order: list[str] = []
        if isinstance(raw_priority, list):
            for item in raw_priority:
                aid = str(item)
                if aid in alert_ids and aid not in seen:
                    priority_order.append(aid)
                    seen.add(aid)
        priority_order.extend(aid for aid in alert_ids if aid not in seen)
        sanitized["priority_order"] = priority_order
    else:
        sanitized["priority_order"] = None

    return sanitized


# ── Task runner ───────────────────────────────────────────────────────────────

def run_task(task_id: str) -> float:
    log_start(task=task_id, env=BENCHMARK, model=MODEL_NAME)

    step_rewards: list[float] = []
    steps_taken = 0
    score = 0.0
    success = False

    try:
        r = http.post("/reset", json={"task_id": task_id})
        r.raise_for_status()
        result = r.json()

        step_num = 0
        while not result.get("done", False):
            obs_data = result.get("observation", result)
            alert_ids = [a["alert_id"] for a in obs_data.get("alerts", [])]
            if not alert_ids:
                break

            step_num += 1
            prompt = _build_prompt(obs_data)
            action_dict = _sanitize_action_dict(_call_llm(prompt), alert_ids, task_id)

            sr = http.post("/step", json={"action": action_dict})
            sr.raise_for_status()
            result = sr.json()

            reward = _clamp_open_score(float(result.get("reward") or 0.0))
            done = result.get("done", False)
            step_rewards.append(reward)
            steps_taken = step_num
            score = reward  # final step reward is the cumulative score

            # Compact action summary for [STEP] line
            action_summary = json.dumps({
                "cls": action_dict.get("classifications", {}),
                "act": action_dict.get("actions", {}),
            }, separators=(",", ":"))

            log_step(step=step_num, action=action_summary, reward=reward, done=done, error=None)

            if done:
                break

        success = score >= 0.5

    except Exception as exc:
        log_step(step=steps_taken + 1, action="null", reward=0.0, done=True, error=str(exc))

    finally:
        log_end(success=success, steps=steps_taken, score=score, rewards=step_rewards)

    return _clamp_open_score(score)


# ── Entry point — run all 3 tasks ────────────────────────────────────────────

def main() -> None:
    # Verify server is up
    try:
        health = http.get("/health")
        health.raise_for_status()
    except Exception as exc:
        print(f"ERROR: Cannot reach server at {SERVER_URL}: {exc}", file=sys.stderr)
        print("Start the server with: python server.py", file=sys.stderr)
        sys.exit(1)

    tasks = ["alert-classify", "incident-response", "triage-under-load"]
    all_scores: dict[str, float] = {}

    for task_id in tasks:
        all_scores[task_id] = run_task(task_id)
        print(flush=True)

    avg = sum(all_scores.values()) / len(all_scores)
    print(f"# Average score across all tasks: {avg:.2f}", flush=True)


if __name__ == "__main__":
    main()
