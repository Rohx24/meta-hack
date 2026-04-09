"""
Reward shaping with partial credit.

Design:
  • Correct classification:       +0.2 per alert (full credit)
  • Partial classification:       +0.0–0.14 (proportional to partial-credit score)
  • Correct action:               +0.3 per alert (full credit)
  • Partial / close action:       +0.05–0.24 (proportional)
  • Wrong block on legit traffic: −0.4 penalty per occurrence
  • Missed critical threat:       −0.2 penalty per occurrence
  • Efficiency bonus (hard task): up to +0.2 for correct priority ordering

Final score is normalized to [−1.0, 1.0].
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class Reward:
    """Internal reward result (not an OpenEnv model — used only inside rewards.py/env.py)."""
    total: float = 0.0
    classification_score: float = 0.0
    action_score: float = 0.0
    efficiency_bonus: float = 0.0
    penalties: float = 0.0
    breakdown: Dict[str, Any] = field(default_factory=dict)
    feedback: str = ""

# Per-alert weight constants
CLS_MAX = 0.2
ACT_MAX = 0.3
WRONG_BLOCK_PENALTY = -0.4     # Per legitimate alert wrongly blocked
MISSED_CRITICAL_PENALTY = -0.2  # Per critical threat ignored

# Efficiency bonus pool (hard task only)
EFFICIENCY_BONUS_MAX = 0.2


def _clamp_open_interval(value: float, low: float = 0.01, high: float = 0.99) -> float:
    """Clamp score-like fields to the validator's required open interval."""
    return max(low, min(high, value))


def _score_classification(
    alert_id: str,
    predicted: str,
    acceptable: dict[str, float],
) -> tuple[float, str]:
    """Return (raw 0..1 score, feedback string)."""
    score = acceptable.get(predicted, 0.0)
    if score < 0:
        score = 0.0  # Negative cls scores just mean wrong — no cls penalty
    correct_cls = max(acceptable, key=acceptable.get)
    if score == 1.0:
        fb = f"{alert_id}: classification ✓ ({predicted})"
    elif score > 0:
        fb = f"{alert_id}: classification ~partial ({predicted}, expected {correct_cls})"
    else:
        fb = f"{alert_id}: classification ✗ ({predicted}, expected {correct_cls})"
    return score, fb


def _score_action(
    alert_id: str,
    action: str,
    acceptable: dict[str, float],
    is_threat: bool,
    is_critical: bool,
) -> tuple[float, float, str]:
    """Return (positive_score 0..1, penalty ≤ 0, feedback string)."""
    raw = acceptable.get(action, 0.0)
    positive = max(0.0, raw)
    penalty = 0.0
    fb_parts = []

    correct_act = max(acceptable, key=acceptable.get)

    if positive == 1.0:
        fb_parts.append(f"{alert_id}: action ✓ ({action})")
    elif positive > 0:
        fb_parts.append(f"{alert_id}: action ~partial ({action}, expected {correct_act})")
    else:
        fb_parts.append(f"{alert_id}: action ✗ ({action}, expected {correct_act})")

    # Penalty: blocking legitimate (non-threat) traffic
    if action == "block" and not is_threat:
        penalty += WRONG_BLOCK_PENALTY
        fb_parts.append(f"  ⚠  PENALTY {WRONG_BLOCK_PENALTY}: blocked legitimate traffic")

    # Penalty: ignoring a critical threat
    if action == "ignore" and is_critical:
        penalty += MISSED_CRITICAL_PENALTY
        fb_parts.append(f"  ⚠  PENALTY {MISSED_CRITICAL_PENALTY}: ignored critical threat")

    return positive, penalty, " | ".join(fb_parts)


def compute_efficiency_bonus(
    priority_order: list[str] | None,
    critical_ids: set[str],
    high_ids: set[str],
    total_alerts: int,
) -> tuple[float, str]:
    """
    Efficiency bonus for the hard task.

    Rules:
      • Full bonus (0.20) if all critical alerts are in the top-N positions
        where N = len(critical_ids).
      • Proportional partial credit for each critical alert found in the top-N.
      • Additional minor bonus if HIGH alerts appear before LOW/NORMAL alerts.
    """
    if not priority_order:
        return 0.0, "No priority_order provided — no efficiency bonus."

    n_critical = len(critical_ids)
    top_n = priority_order[:n_critical]
    hits = sum(1 for aid in top_n if aid in critical_ids)
    critical_bonus = (hits / n_critical) * EFFICIENCY_BONUS_MAX

    fb = (
        f"Efficiency: {hits}/{n_critical} critical alerts in top-{n_critical} positions "
        f"→ bonus {critical_bonus:.3f}"
    )
    return round(critical_bonus, 4), fb


def compute_reward(
    per_alert_scores: list[dict],
    task_id: str,
    priority_order: list[str] | None = None,
    critical_ids: set[str] | None = None,
    high_ids: set[str] | None = None,
    total_alerts: int = 1,
) -> Reward:
    """
    Aggregate per-alert scores into a normalized Reward.

    per_alert_scores: list of dicts with keys:
        alert_id, cls_score (0..1), act_positive (0..1), act_penalty (≤0),
        cls_feedback, act_feedback
    """
    total_cls_raw = 0.0
    total_act_pos = 0.0
    total_penalties = 0.0
    breakdown: dict = {}
    feedback_lines: list[str] = []

    for s in per_alert_scores:
        aid = s["alert_id"]
        cls_contribution = s["cls_score"] * CLS_MAX
        act_contribution = s["act_positive"] * ACT_MAX
        penalty = s["act_penalty"]

        total_cls_raw += cls_contribution
        total_act_pos += act_contribution
        total_penalties += penalty

        breakdown[aid] = {
            "classification_score": round(cls_contribution, 4),
            "action_score": round(act_contribution, 4),
            "penalty": round(penalty, 4),
            "alert_total": round(cls_contribution + act_contribution + penalty, 4),
        }
        feedback_lines.append(s.get("cls_feedback", ""))
        feedback_lines.append(s.get("act_feedback", ""))

    # Efficiency bonus (hard task only)
    efficiency_bonus = 0.0
    if task_id == "triage-under-load" and critical_ids:
        efficiency_bonus, eff_fb = compute_efficiency_bonus(
            priority_order, critical_ids, high_ids or set(), total_alerts
        )
        feedback_lines.append(eff_fb)

    # Normalize: max positive raw = total_alerts * (CLS_MAX + ACT_MAX) + EFFICIENCY_BONUS_MAX
    max_positive = total_alerts * (CLS_MAX + ACT_MAX) + (
        EFFICIENCY_BONUS_MAX if task_id == "triage-under-load" else 0.0
    )
    raw_total = total_cls_raw + total_act_pos + total_penalties + efficiency_bonus
    normalized = raw_total / max_positive if max_positive > 0 else 0.0
    normalized = _clamp_open_interval(normalized)

    cls_fraction = total_cls_raw / (total_alerts * CLS_MAX) if total_alerts > 0 else 0.0
    act_fraction = (total_act_pos + total_penalties) / (total_alerts * ACT_MAX) if total_alerts > 0 else 0.0

    feedback_lines.append(
        f"\nTotal: {normalized:.3f} | cls={cls_fraction:.2%} | "
        f"action={act_fraction:.2%} | penalties={total_penalties:.3f} | "
        f"efficiency_bonus={efficiency_bonus:.3f}"
    )

    return Reward(
        total=round(normalized, 4),
        classification_score=round(_clamp_open_interval(cls_fraction), 4),
        action_score=round(_clamp_open_interval(act_fraction), 4),
        efficiency_bonus=round(efficiency_bonus, 4),
        penalties=round(total_penalties, 4),
        breakdown=breakdown,
        feedback="\n".join(line for line in feedback_lines if line),
    )
