"""
DetectionAgent — ML ensemble + context analysis LangGraph node.

Wraps the existing ml_detect_node logic so it can be used as a
named agent inside the multi-agent workflow while keeping all
detection logic in one authoritative place.
"""

import time
from typing import Any, Dict, List

from .base_agent import BaseAgent


class DetectionAgent(BaseAgent):
    """
    Runs ML detection (RF + XGBoost ensemble) and context analysis.

    Responsibilities:
    - Load trained ML models
    - Score each network flow with the ensemble
    - Apply 5-layer context routing to decide which flows go to LLM
    - Populate state['detected_threats'] and state['context']['llm_candidates']
    - Emit a DecisionTrace entry per session
    """

    name = "DetectionAgent"
    role = "ML Detection & Context Analysis"
    description = (
        "Runs Random Forest + XGBoost ensemble on network flows, "
        "applies multi-layer context routing, and flags LLM candidates."
    )

    def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        start = time.perf_counter()

        # Lazy import to avoid circular dependency with workflow_graph
        from src.agent.workflow_graph import ml_detect_node  # type: ignore

        state = ml_detect_node(state)

        duration_ms = (time.perf_counter() - start) * 1000
        session_id = state.get("session_id", "unknown")
        n_threats = len(state.get("detected_threats", []))
        n_candidates = len(state.get("context", {}).get("llm_candidates", []))

        self._emit_trace(
            session_id=session_id,
            input_summary=f"flows={len(state.get('raw_network_flows', []))}",
            decision=f"detected {n_threats} threats, {n_candidates} routed to LLM",
            reasoning="RF+XGBoost ensemble + 5-layer context routing",
            confidence=0.9,
            duration_ms=duration_ms,
        )
        return state

    def get_capabilities(self) -> List[str]:
        return [
            "ml_detection",
            "context_analysis",
            "apt_detection",
            "routing_decision",
        ]
