"""
MemoryAgent — convenience wrapper around MemoryManager.

This agent is NOT a LangGraph node (InvestigationAgent and ResponseAgent
call MemoryManager directly via memory_lookup_node / store_incident).
MemoryAgent provides a clean API surface for other agents that need
direct memory access outside of the main workflow.
"""

import logging
from typing import Any, Dict, List, Optional

from .base_agent import BaseAgent

logger = logging.getLogger(__name__)


class MemoryAgent(BaseAgent):
    """
    Thin, agent-oriented wrapper around MemoryManager.

    Useful for:
    - Unit tests that need isolated memory access
    - Agents that need to store / query incidents programmatically
    - Dashboard / reporting code that wants a consistent agent interface

    process() is a no-op because MemoryAgent is not placed in the graph.
    """

    name = "MemoryAgent"
    role = "Incident Memory & Retrieval"
    description = (
        "Provides store / retrieve operations over the SQLite + FAISS "
        "hybrid memory system.  Not a LangGraph node."
    )

    # ------------------------------------------------------------------
    # LangGraph node interface (required by BaseAgent but unused here)
    # ------------------------------------------------------------------

    def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Pass-through — MemoryAgent is called imperatively, not as a node."""
        return state

    def get_capabilities(self) -> List[str]:
        return [
            "incident_storage",
            "faiss_vector_search",
            "ip_reputation",
            "pattern_detection",
            "memory_statistics",
        ]

    # ------------------------------------------------------------------
    # Convenience API
    # ------------------------------------------------------------------

    def store_incident(self, incident: Any) -> Optional[str]:
        """
        Persist an IncidentRecord.

        Args:
            incident: IncidentRecord instance from src.memory.models

        Returns:
            Incident ID string on success, None on failure.
        """
        try:
            memory = self._get_memory()
            return memory.store_incident(incident)
        except Exception as exc:
            logger.error("MemoryAgent.store_incident failed: %s", exc)
            return None

    def get_context(self, incident: Any) -> Dict[str, Any]:
        """
        Retrieve memory context for an incident.

        Args:
            incident: IncidentRecord to find similar incidents for

        Returns:
            Memory context dict from MemoryManager.get_memory_context()
        """
        try:
            memory = self._get_memory()
            return memory.get_memory_context(incident)
        except Exception as exc:
            logger.error("MemoryAgent.get_context failed: %s", exc)
            return {}

    def get_statistics(self) -> Dict[str, Any]:
        """Return memory statistics dict."""
        try:
            memory = self._get_memory()
            stats = memory.get_statistics()
            return stats.__dict__ if hasattr(stats, "__dict__") else dict(stats)
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_memory():
        """Lazy-import MemoryManager singleton to avoid heavy startup cost."""
        from src.memory.memory_manager import MemoryManager  # type: ignore

        # Use a simple module-level singleton pattern
        if not hasattr(MemoryAgent, "_memory_instance"):
            MemoryAgent._memory_instance = MemoryManager()
        return MemoryAgent._memory_instance
