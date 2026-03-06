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
