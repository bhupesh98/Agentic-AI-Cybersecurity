"""
InvestigationAgent — LLM analysis + memory retrieval + investigation report.

Combines llm_analyze_node and memory_lookup_node logic, then synthesises a
structured investigation_report that downstream agents can consume.
"""

import time
from typing import Any, Dict, List

from .base_agent import BaseAgent


class InvestigationAgent(BaseAgent):
    """
    Runs LLM threat analysis over flagged flows and correlates with memory.

    Responsibilities:
    - Call LLM for each flagged candidate
    - Retrieve similar past incidents from FAISS memory
    - Store new incidents in memory
    - Synthesise a structured investigation_report in state
    - Emit a DecisionTrace entry per session
    """

    name = "InvestigationAgent"
    role = "LLM Analysis & Memory Correlation"
    description = (
        "Invokes the LLM for contextual threat analysis, retrieves similar "
        "historical incidents, and produces a structured investigation report."
    )

    def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        start = time.perf_counter()

        # Lazy imports to avoid circular dependency
        from src.agent.workflow_graph import llm_analyze_node, memory_lookup_node  # type: ignore

        state = llm_analyze_node(state)
        state = memory_lookup_node(state)

        # Synthesise the investigation_report field (new Phase 2 field)
        llm_analysis = state.get("llm_analysis", {})
        analyses = llm_analysis.get("analyses", [])
        memory_contexts = state.get("memory_contexts", [])

        if analyses:
            top = max(analyses, key=lambda a: float(a.get("confidence", 0)))
            investigation_report: Dict[str, Any] = {
                "threat_type": str(top.get("analysis", "Unknown"))[:100],
                "confidence": float(top.get("confidence", 0.0)),
                "evidence": [a.get("analysis", "") for a in analyses[:3]],
                "attack_chain": None,
                "recommendation": (
                    top.get("recommended_actions", ["Monitor"])[0]
                    if top.get("recommended_actions")
                    else "Monitor"
                ),
                "risk_score": float(top.get("confidence", 0.0)),
                "memory_hits": len(memory_contexts),
            }
        else:
            investigation_report = {
                "threat_type": "Unknown",
                "confidence": 0.0,
                "evidence": [],
                "attack_chain": None,
                "recommendation": "Monitor",
                "risk_score": 0.0,
                "memory_hits": len(memory_contexts),
            }

        state["investigation_report"] = investigation_report

        duration_ms = (time.perf_counter() - start) * 1000
        session_id = state.get("session_id", "unknown")
        n_analyses = len(analyses)
        n_stored = len(state.get("stored_incident_ids", []))

        self._emit_trace(
            session_id=session_id,
            input_summary=f"candidates={len(state.get('context', {}).get('llm_candidates', []))}",
            decision=f"analyzed {n_analyses} threats, stored {n_stored} incidents",
            reasoning="LLM contextual analysis + FAISS semantic memory lookup",
            confidence=investigation_report["confidence"],
            duration_ms=duration_ms,
        )
        return state

    def get_capabilities(self) -> List[str]:
        return [
            "llm_analysis",
            "memory_lookup",
            "incident_storage",
            "investigation_report",
            "pattern_correlation",
        ]
