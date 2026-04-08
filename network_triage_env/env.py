"""
NetworkTriageEnv — OpenEnv-compliant environment class.

Inherits from openenv.core.env_server.Environment so create_fastapi_app()
can wrap it with WebSocket (/ws), REST (/reset /step /state), and /health.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional

from openenv.core.env_server import Environment

from .graders import grade_easy, grade_hard, grade_medium_step
from .models import (
    NetworkAlert,
    NetworkTriageAction,
    NetworkTriageObservation,
    NetworkTriageState,
)
from .rewards import compute_reward
from .scenarios import HARD_CRITICAL_IDS, HARD_HIGH_IDS
from .tasks import Task, get_task


class NetworkTriageEnv(Environment[NetworkTriageAction, NetworkTriageObservation, NetworkTriageState]):
    """
    Network alert triage simulation for NOC analyst training.

    Supports concurrent sessions (each WebSocket connection gets its own instance).
    """

    SUPPORTS_CONCURRENT_SESSIONS = True

    def __init__(self) -> None:
        super().__init__()
        self._task: Task | None = None
        self._step_idx: int = 0
        self._done: bool = False
        self._previous_actions: list[dict[str, Any]] = []
        self._context: dict[str, Any] = {}
        self._cumulative_per_alert: list[dict] = []
        self._episode_id: str | None = None

    # ──────────────────────────────────────────
    # OpenEnv interface
    # ──────────────────────────────────────────

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        task_id: str = "alert-classify",
        **kwargs: Any,
    ) -> NetworkTriageObservation:
        """Start a new episode. task_id selects the task (passed in reset kwargs)."""
        self._task = get_task(task_id)
        self._step_idx = 0
        self._done = False
        self._previous_actions = []
        self._context = {"seen_ips": {}, "alert_history": [], "ip_to_alerts": {}}
        self._cumulative_per_alert = []
        self._episode_id = episode_id or str(uuid.uuid4())
        self._reset_rubric()
        return self._make_observation()

    def step(
        self,
        action: NetworkTriageAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> NetworkTriageObservation:
        """Process the agent's action and advance the environment."""
        if self._task is None:
            raise RuntimeError("Call reset() before step().")
        if self._done:
            raise RuntimeError("Episode is done. Call reset() to start a new episode.")

        task = self._task
        current_batch = task.alerts_by_step[self._step_idx]
        batch_ids = [a.alert_id for a in current_batch]

        # Grade current step
        if task.task_id == "alert-classify":
            per_alert = grade_easy(action, task.ground_truth)
        elif task.task_id == "incident-response":
            per_alert = grade_medium_step(action, batch_ids, task.ground_truth)
        else:
            per_alert = grade_hard(action, task.ground_truth)

        self._cumulative_per_alert.extend(per_alert)
        self._update_context(current_batch, action, per_alert)

        for s in per_alert:
            self._previous_actions.append({
                "alert_id": s["alert_id"],
                "classification": s["predicted_cls"],
                "action": s["predicted_act"],
                "correct_classification": s["correct_cls"],
                "correct_action": s["correct_act"],
            })

        self._step_idx += 1
        all_batches_done = self._step_idx >= len(task.alerts_by_step)
        max_steps_reached = self._step_idx >= task.max_steps
        self._done = all_batches_done or max_steps_reached

        # Compute reward
        if task.task_id == "triage-under-load":
            reward_obj = compute_reward(
                self._cumulative_per_alert,
                task_id=task.task_id,
                priority_order=action.priority_order,
                critical_ids=HARD_CRITICAL_IDS,
                high_ids=HARD_HIGH_IDS,
                total_alerts=task.total_alerts,
            )
        else:
            reward_obj = compute_reward(
                self._cumulative_per_alert,
                task_id=task.task_id,
                total_alerts=len(self._cumulative_per_alert),
            )

        obs = self._make_observation()
        # Populate OpenEnv reward field + breakdown fields
        obs.reward = float(reward_obj.total)
        obs.reward_breakdown = reward_obj.breakdown
        obs.reward_feedback = reward_obj.feedback
        obs.classification_score = float(reward_obj.classification_score)
        obs.action_score = float(reward_obj.action_score)
        obs.efficiency_bonus = float(reward_obj.efficiency_bonus)
        obs.penalties = float(reward_obj.penalties)
        return obs

    @property
    def state(self) -> NetworkTriageState:
        if self._task is None:
            return NetworkTriageState()
        return NetworkTriageState(
            episode_id=self._episode_id,
            step_count=self._step_idx,
            task_id=self._task.task_id,
            task_name=self._task.task_name,
            max_steps=self._task.max_steps,
            total_alerts=self._task.total_alerts,
            alerts_graded=len(self._cumulative_per_alert),
            done=self._done,
            context=dict(self._context),
            previous_actions=list(self._previous_actions),
        )

    # ──────────────────────────────────────────
    # Private helpers
    # ──────────────────────────────────────────

    def _make_observation(self) -> NetworkTriageObservation:
        task = self._task
        if task is None:
            return NetworkTriageObservation(done=True)
        if self._done or self._step_idx >= len(task.alerts_by_step):
            alerts: list[NetworkAlert] = []
        else:
            alerts = task.alerts_by_step[self._step_idx]

        return NetworkTriageObservation(
            done=self._done,
            reward=None,
            task_id=task.task_id,
            task_name=task.task_name,
            step=self._step_idx,
            max_steps=task.max_steps,
            alerts=alerts,
            context=dict(self._context),
            previous_actions=list(self._previous_actions),
            instructions=task.instructions,
        )

    def _update_context(
        self,
        alerts: list[NetworkAlert],
        action: NetworkTriageAction,
        per_alert: list[dict],
    ) -> None:
        ctx = self._context
        seen_ips: dict[str, int] = ctx.setdefault("seen_ips", {})
        ip_to_alerts: dict[str, list[str]] = ctx.setdefault("ip_to_alerts", {})
        alert_history: list[dict] = ctx.setdefault("alert_history", [])

        for alert in alerts:
            for ip in {alert.source_ip, alert.dest_ip}:
                if ip != "0.0.0.0":
                    seen_ips[ip] = seen_ips.get(ip, 0) + 1
                    ip_to_alerts.setdefault(ip, []).append(alert.alert_id)

        for s in per_alert:
            alert_history.append({
                "alert_id": s["alert_id"],
                "classification": s["predicted_cls"],
                "action": s["predicted_act"],
            })

        ctx["repeated_ips"] = {ip: cnt for ip, cnt in seen_ips.items() if cnt > 1}
        ctx["total_alerts_seen"] = len(alert_history)
