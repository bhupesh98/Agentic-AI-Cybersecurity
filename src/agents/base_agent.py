"""
Abstract BaseAgent for the Autonomous AI SOC Platform.

Phase 2: Multi-Agent Architecture — all agents inherit from this class.

Each agent:
  - Has a name, role, and description (class-level attributes).
  - Implements async process(state) → state as a LangGraph node.
  - Can emit decision trace entries via _emit_trace().
  - Optionally holds a DecisionTraceManager reference.
"""

from __future__ import annotations

import time
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base for all SOC platform agents."""

    # Subclasses override these class-level constants
    name: str = "BaseAgent"
    role: str = "agent"
    description: str = "Abstract agent"

    def __init__(self, trace_manager=None) -> None:
        """
        Args:
            trace_manager: Optional DecisionTraceManager instance for
                            persisting decision traces.
        """
        self.trace_manager = trace_manager
        self.logger = logging.getLogger(f"agents.{self.name}")

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @abstractmethod
    def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the agent's logic and return the updated state.

        Designed as a LangGraph node:  node = agent.process

        Args:
            state: Current AgentState dict (from LangGraph).

        Returns:
            Updated AgentState dict.
        """

    @abstractmethod
    def get_capabilities(self) -> List[str]:
        """Return a list of capability strings for this agent."""

    # ------------------------------------------------------------------
    # Tracing helper
    # ------------------------------------------------------------------

    def _emit_trace(
        self,
        session_id: str,
        input_summary: str,
        decision: str,
        reasoning: str,
        confidence: float,
        duration_ms: float,
    ) -> None:
        """Persist a single decision-trace entry if a trace manager is set."""
        if self.trace_manager is None:
            return
        try:
            self.trace_manager.log_entry(
                session_id=session_id,
                agent_name=self.name,
                input_summary=input_summary,
                decision=decision,
                reasoning=reasoning,
                confidence=confidence,
                duration_ms=duration_ms,
            )
        except Exception as exc:
            self.logger.warning(f"Trace logging failed: {exc}")

    # ------------------------------------------------------------------
    # Convenience: timed execution wrapper
    # ------------------------------------------------------------------

    def _timed_process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Call process() and emit a trace entry with wall-clock duration."""
        start = time.perf_counter()
        result = self.process(state)
        duration_ms = (time.perf_counter() - start) * 1000
        session_id = state.get("session_id", "unknown")
        decision = f"{self.name} completed"
        self._emit_trace(
            session_id=session_id,
            input_summary=f"flows={len(state.get('raw_network_flows', []))}",
            decision=decision,
            reasoning=f"{self.role} processing done",
            confidence=1.0,
            duration_ms=duration_ms,
        )
        return result

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} role={self.role!r}>"
