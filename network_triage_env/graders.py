"""
Deterministic graders for all three tasks.

Same inputs → same outputs. No randomness.
Each grader returns a list of per-alert score dicts consumed by rewards.compute_reward().
"""
from __future__ import annotations

from .models import NetworkTriageAction as Action
from .rewards import _score_action, _score_classification


def _normalize_cls(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")


def _normalize_act(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")


def grade_step(
    action: Action,
    alert_ids: list[str],
    ground_truth: dict,
) -> list[dict]:
    """
    Grade a single step's action against ground-truth for the given alert_ids.

    Returns a list of per-alert score dicts:
        {alert_id, cls_score, act_positive, act_penalty, cls_feedback, act_feedback}
    """
    per_alert: list[dict] = []
    acceptable_cls = ground_truth["acceptable_classifications"]
    acceptable_act = ground_truth["acceptable_actions"]
    is_threat_map = ground_truth["is_threat"]
    is_critical_map = ground_truth["is_critical"]

    for aid in alert_ids:
        # --- classification ---
        predicted_cls = _normalize_cls(action.classifications.get(aid, "unknown"))
        cls_score, cls_fb = _score_classification(
            aid, predicted_cls, acceptable_cls.get(aid, {})
        )

        # --- action ---
        predicted_act = _normalize_act(action.actions.get(aid, "monitor"))
        is_threat = is_threat_map.get(aid, False)
        is_critical = is_critical_map.get(aid, False)
        act_positive, act_penalty, act_fb = _score_action(
            aid, predicted_act, acceptable_act.get(aid, {}), is_threat, is_critical
        )

        per_alert.append(
            {
                "alert_id": aid,
                "cls_score": cls_score,
                "act_positive": act_positive,
                "act_penalty": act_penalty,
                "cls_feedback": cls_fb,
                "act_feedback": act_fb,
                "predicted_cls": predicted_cls,
                "predicted_act": predicted_act,
                "correct_cls": ground_truth["classifications"].get(aid, "?"),
                "correct_act": ground_truth["actions"].get(aid, "?"),
            }
        )
    return per_alert


def grade_easy(action: Action, ground_truth: dict) -> list[dict]:
    """Grade the easy task (single step, 5 alerts)."""
    alert_ids = list(ground_truth["classifications"].keys())
    return grade_step(action, alert_ids, ground_truth)


def grade_medium_step(
    action: Action,
    batch_alert_ids: list[str],
    ground_truth: dict,
) -> list[dict]:
    """Grade one batch of the medium task (2 alerts per step)."""
    return grade_step(action, batch_alert_ids, ground_truth)


def grade_hard(action: Action, ground_truth: dict) -> list[dict]:
    """Grade the hard task (up to 20 alerts, single comprehensive action)."""
    alert_ids = list(ground_truth["classifications"].keys())
    return grade_step(action, alert_ids, ground_truth)
