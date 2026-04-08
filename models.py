"""
Data models for the NetworkTriage Environment.

Re-exports the canonical models from the network_triage_env package.
"""

from network_triage_env.models import NetworkTriageAction, NetworkTriageObservation

__all__ = [
    "NetworkTriageAction",
    "NetworkTriageObservation",
]
