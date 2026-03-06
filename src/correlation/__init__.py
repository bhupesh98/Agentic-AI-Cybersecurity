"""APT correlation engine package.

Phase 4: Intelligence Features — Feature 5 (APT correlation).
"""

from .incident_correlation_engine import IncidentCorrelationEngine, AttackChain, ChainStage

__all__ = ["IncidentCorrelationEngine", "AttackChain", "ChainStage"]
