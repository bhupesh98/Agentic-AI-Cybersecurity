"""Multi-agent package for Autonomous AI SOC Platform.

Phase 2: Multi-Agent Architecture — Features 1, 7, 12.

Agent hierarchy:
  BaseAgent (ABC)
    ├── DetectionAgent       — ML ensemble + context analysis
    ├── InvestigationAgent   — LLM analysis + memory + correlation
    ├── ThreatIntelAgent     — External API enrichment (AbuseIPDB/VT/Shodan)
    ├── ResponseAgent        — Policy engine + playbook execution
    ├── MemoryAgent          — FAISS + SQLite incident memory
    └── GovernanceAgent      — Risk thresholds + human-in-the-loop audit

Each agent is a LangGraph node internally (takes + returns AgentState).
MemoryAgent is not a graph node — it is called internally by Investigation
and Response agents.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base_agent import BaseAgent
    from .detection_agent import DetectionAgent
    from .investigation_agent import InvestigationAgent
    from .threat_intel_agent import ThreatIntelAgent
    from .response_agent import ResponseAgent
    from .memory_agent import MemoryAgent
    from .governance_agent import GovernanceAgent

__all__ = [
    "BaseAgent",
    "DetectionAgent",
    "InvestigationAgent",
    "ThreatIntelAgent",
    "ResponseAgent",
    "MemoryAgent",
    "GovernanceAgent",
]

_EXPORTS = {
    "BaseAgent": (".base_agent", "BaseAgent"),
    "DetectionAgent": (".detection_agent", "DetectionAgent"),
    "InvestigationAgent": (".investigation_agent", "InvestigationAgent"),
    "ThreatIntelAgent": (".threat_intel_agent", "ThreatIntelAgent"),
    "ResponseAgent": (".response_agent", "ResponseAgent"),
    "MemoryAgent": (".memory_agent", "MemoryAgent"),
    "GovernanceAgent": (".governance_agent", "GovernanceAgent"),
}


def __getattr__(name: str):
    """Lazy package exports avoid double-import warnings with ``python -m``."""
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    import importlib

    module_name, attr_name = _EXPORTS[name]
    module = importlib.import_module(module_name, __name__)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value
