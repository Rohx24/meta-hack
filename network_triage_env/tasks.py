"""Task definitions for all three difficulty levels."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .scenarios import (
    EASY_ALERTS,
    EASY_GROUND_TRUTH,
    HARD_ALERTS,
    HARD_GROUND_TRUTH,
    MEDIUM_ALERT_BATCHES,
    MEDIUM_GROUND_TRUTH,
)


@dataclass
class Task:
    task_id: str
    task_name: str
    difficulty: str          # easy / medium / hard
    description: str
    max_steps: int
    instructions: str
    # Runtime data (set by env.reset())
    alerts_by_step: list = field(default_factory=list)  # list[list[NetworkAlert]]
    ground_truth: dict = field(default_factory=dict)
    total_alerts: int = 0


TASK_REGISTRY: dict[str, Task] = {
    "alert-classify": Task(
        task_id="alert-classify",
        task_name="Alert Classification",
        difficulty="easy",
        description=(
            "You are a NOC analyst reviewing 5 incoming network alerts. "
            "Classify each alert and choose the appropriate response action."
        ),
        max_steps=1,
        instructions=(
            "You will receive 5 network alerts simultaneously. For EACH alert you must:\n"
            "  1. Classify it as one of: port_scan, normal, ddos, brute_force, malware, "
            "data_exfiltration, reconnaissance, lateral_movement, privilege_escalation, unknown\n"
            "  2. Choose an action: block, escalate, ignore, rate_limit, monitor, investigate\n\n"
            "Respond with a JSON object:\n"
            '  {"classifications": {"<alert_id>": "<type>", ...}, '
            '"actions": {"<alert_id>": "<action>", ...}, '
            '"reasoning": "<optional explanation>"}'
        ),
        alerts_by_step=[EASY_ALERTS],
        ground_truth=EASY_GROUND_TRUTH,
        total_alerts=5,
    ),
    "incident-response": Task(
        task_id="incident-response",
        task_name="Incident Response",
        difficulty="medium",
        description=(
            "You are a NOC analyst handling an active incident. Alerts arrive in batches. "
            "Some alerts are related — the correct response depends on context from earlier alerts."
        ),
        max_steps=5,
        instructions=(
            "You will receive network alerts in 5 batches (2 alerts each, 10 total). "
            "After each batch you must classify and act on those alerts before seeing the next batch.\n\n"
            "Context MATTERS: if you see the same IP in a later batch, escalate your response.\n\n"
            "Alert types: port_scan, normal, ddos, brute_force, malware, data_exfiltration, "
            "reconnaissance, lateral_movement, privilege_escalation, unknown\n"
            "Actions: block, escalate, ignore, rate_limit, monitor, investigate\n\n"
            "Respond with JSON: "
            '{"classifications": {...}, "actions": {...}, "reasoning": "..."}'
        ),
        alerts_by_step=MEDIUM_ALERT_BATCHES,
        ground_truth=MEDIUM_GROUND_TRUTH,
        total_alerts=10,
    ),
    "triage-under-load": Task(
        task_id="triage-under-load",
        task_name="Triage Under Load",
        difficulty="hard",
        description=(
            "CRITICAL INCIDENT: 20 simultaneous alerts. You have limited steps. "
            "Classify, act on ALL alerts AND provide a priority order. "
            "Some alerts are red herrings. Some are related. Efficiency matters."
        ),
        max_steps=3,
        instructions=(
            "MASS INCIDENT — 20 alerts received simultaneously.\n\n"
            "You MUST:\n"
            "  1. Classify every alert (types: port_scan, normal, ddos, brute_force, malware, "
            "data_exfiltration, reconnaissance, lateral_movement, privilege_escalation, unknown)\n"
            "  2. Choose an action for every alert (block, escalate, ignore, rate_limit, monitor, investigate)\n"
            "  3. Provide 'priority_order': a list of ALL 20 alert IDs ordered from highest to lowest priority\n\n"
            "WARNING: Some alerts are red herrings (look threatening but are legitimate). "
            "Blocking legitimate traffic carries heavy penalties.\n\n"
            "You have up to 3 steps. Handling all 20 in step 1 gives an efficiency bonus.\n\n"
            "Respond with JSON:\n"
            '{"classifications": {"H001": "...", ...}, "actions": {"H001": "...", ...}, '
            '"priority_order": ["H001", "H006", ...], "reasoning": "..."}'
        ),
        alerts_by_step=[HARD_ALERTS],   # All 20 shown at once
        ground_truth=HARD_GROUND_TRUTH,
        total_alerts=20,
    ),
}


def get_task(task_id: str) -> Task:
    if task_id not in TASK_REGISTRY:
        valid = list(TASK_REGISTRY.keys())
        raise ValueError(f"Unknown task_id '{task_id}'. Valid options: {valid}")
    return TASK_REGISTRY[task_id]


def list_tasks() -> list[dict[str, Any]]:
    return [
        {
            "task_id": t.task_id,
            "task_name": t.task_name,
            "difficulty": t.difficulty,
            "max_steps": t.max_steps,
            "total_alerts": t.total_alerts,
            "description": t.description,
        }
        for t in TASK_REGISTRY.values()
    ]
