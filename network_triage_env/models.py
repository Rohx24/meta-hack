"""
Pydantic models for the NetworkTriage environment.

Inherits from openenv-core base classes for full OpenEnv spec compliance.
WebSocket, REST, and validation all flow through these types.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import ConfigDict, Field

from openenv.core.env_server import (
    Action as BaseAction,
    Observation as BaseObservation,
    State as BaseState,
)


# ─────────────────────────────────────────────
# Domain enums (standalone — not Action/Obs)
# ─────────────────────────────────────────────


class AlertType(str, Enum):
    PORT_SCAN = "port_scan"
    NORMAL = "normal"
    DDOS = "ddos"
    BRUTE_FORCE = "brute_force"
    MALWARE = "malware"
    DATA_EXFILTRATION = "data_exfiltration"
    RECONNAISSANCE = "reconnaissance"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNKNOWN = "unknown"


class ActionType(str, Enum):
    BLOCK = "block"
    ESCALATE = "escalate"
    IGNORE = "ignore"
    RATE_LIMIT = "rate_limit"
    MONITOR = "monitor"
    INVESTIGATE = "investigate"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ─────────────────────────────────────────────
# Alert data model (embedded in Observation)
# ─────────────────────────────────────────────


class NetworkAlert(BaseObservation):
    """
    A single network alert as seen by a NOC analyst.

    Inherits from BaseObservation so it can be serialised cleanly, but
    in practice it's used as a nested field inside NetworkTriageObservation.
    """

    model_config = ConfigDict(
        extra="ignore",
        validate_assignment=True,
        arbitrary_types_allowed=True,
    )

    alert_id: str = Field(description="Unique alert identifier")
    timestamp: str = Field(description="ISO 8601 timestamp of detection")
    source_ip: str = Field(description="Source IP (0.0.0.0 = multiple sources)")
    dest_ip: str = Field(description="Destination IP")
    source_port: int = Field(ge=0, le=65535)
    dest_port: int = Field(ge=0, le=65535)
    protocol: str = Field(description="TCP / UDP / ICMP / etc.")
    bytes_transferred: int = Field(ge=0)
    packets_count: int = Field(ge=0)
    duration_seconds: float = Field(ge=0.0)
    alert_type_raw: str = Field(description="Raw IDS/IPS label")
    description: str = Field(description="Human-readable context")
    severity: SeverityLevel = SeverityLevel.MEDIUM
    frequency: int = Field(ge=1, default=1)
    geo_location: Optional[str] = None
    user_agent: Optional[str] = None
    threat_score: float = Field(ge=0.0, le=10.0, default=0.0)
    tags: List[str] = Field(default_factory=list)
    related_alert_ids: List[str] = Field(default_factory=list)


# ─────────────────────────────────────────────
# OpenEnv-compliant Action
# ─────────────────────────────────────────────


class NetworkTriageAction(BaseAction):
    """
    Agent's triage decision for one step.

    Inherits BaseAction (metadata field + extra="forbid" validation).
    The agent must classify every alert in the current batch and choose an action.
    For the hard task, priority_order covering all 20 alert IDs is also required.
    """

    classifications: Dict[str, str] = Field(
        description="alert_id → AlertType (e.g. 'port_scan', 'normal', 'ddos')"
    )
    actions: Dict[str, str] = Field(
        description="alert_id → ActionType (e.g. 'block', 'ignore', 'escalate')"
    )
    priority_order: Optional[List[str]] = Field(
        default=None,
        description="All alert IDs ordered highest-to-lowest priority (required for triage-under-load)",
    )
    reasoning: Optional[str] = Field(
        default=None,
        description="Chain-of-thought reasoning (optional, not graded)",
    )


# Keep 'Action' as an alias so inference.py imports still work
Action = NetworkTriageAction


# ─────────────────────────────────────────────
# OpenEnv-compliant Observation
# ─────────────────────────────────────────────


class NetworkTriageObservation(BaseObservation):
    """
    What the agent sees at each step.

    Inherits BaseObservation: done (bool), reward (float|None), metadata (dict).
    After a step(), reward holds the normalised score [-1, 1].
    Reward breakdown fields are populated after step() calls.
    """

    model_config = ConfigDict(
        extra="ignore",
        validate_assignment=True,
        arbitrary_types_allowed=True,
    )

    task_id: str = ""
    task_name: str = ""
    step: int = Field(default=0, ge=0)
    max_steps: int = Field(default=1, ge=1)
    alerts: List[NetworkAlert] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    previous_actions: List[Dict[str, Any]] = Field(default_factory=list)
    instructions: str = ""

    # Reward breakdown — populated after step(), null after reset()
    reward_breakdown: Optional[Dict[str, Any]] = None
    reward_feedback: Optional[str] = None
    classification_score: Optional[float] = None
    action_score: Optional[float] = None
    efficiency_bonus: Optional[float] = None
    penalties: Optional[float] = None


# Keep 'Observation' alias for backward compatibility
Observation = NetworkTriageObservation


# ─────────────────────────────────────────────
# OpenEnv-compliant State
# ─────────────────────────────────────────────


class NetworkTriageState(BaseState):
    """
    Episode metadata visible at any time via state().

    Inherits BaseState: episode_id (str|None), step_count (int).
    """

    task_id: str = ""
    task_name: str = ""
    max_steps: int = 1
    total_alerts: int = 0
    alerts_graded: int = 0
    done: bool = False
    context: Dict[str, Any] = Field(default_factory=dict)
    previous_actions: List[Dict[str, Any]] = Field(default_factory=list)


# Keep old names for anything that imports them
State = NetworkTriageState
