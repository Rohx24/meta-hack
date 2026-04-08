"""
NetworkTriage Environment Client.

Wraps the OpenEnv EnvClient for connecting to the NetworkTriage server via WebSocket.
"""

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from .models import NetworkTriageAction, NetworkTriageObservation


class NetworkTriageEnvClient(EnvClient[NetworkTriageAction, NetworkTriageObservation, State]):
    """
    Client for the NetworkTriage Environment.

    Maintains a persistent WebSocket connection to the environment server,
    enabling efficient multi-step interactions. Each client instance has its
    own dedicated environment session on the server.

    Example:
        >>> with NetworkTriageEnvClient(base_url="http://localhost:7860") as client:
        ...     result = client.reset(task_id="alert-classify")
        ...     action = NetworkTriageAction(
        ...         classifications={"A001": "port_scan"},
        ...         actions={"A001": "block"},
        ...         priority_order=["A001"],
        ...         reasoning="High threat score port scan"
        ...     )
        ...     result = client.step(action)
        ...     print(result.reward)
    """

    def _step_payload(self, action: NetworkTriageAction) -> Dict:
        return action.model_dump()

    def _parse_result(self, payload: Dict) -> StepResult[NetworkTriageObservation]:
        obs_data = payload.get("observation", {})
        observation = NetworkTriageObservation(
            **obs_data,
            done=payload.get("done", False),
            reward=payload.get("reward"),
        )
        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )
