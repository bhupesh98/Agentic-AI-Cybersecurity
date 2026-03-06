"""
ResponseAgent — policy-driven action selection and execution.

Wraps enhanced_respond_node + enhanced_execute_node from workflow_integration,
adds a lightweight playbook record to state, and emits a trace entry.
"""

import time
import uuid
from typing import Any, Dict, List

from .base_agent import BaseAgent


class ResponseAgent(BaseAgent):
    """
    Selects and executes defensive actions based on policy + governance.

    Responsibilities:
    - Build ThreatContext from detection / investigation results
    - Consult PolicyEngine.suggest_actions()
    - Create BlockIP / AlertEmail action objects
    - Execute via ActionExecutor (respects SIMULATION_MODE)
    - Build state['playbook'] summary
    - Emit a DecisionTrace entry
    """

    name = "ResponseAgent"
    role = "Autonomous Response & Execution"
    description = (
        "Selects defensive actions via PolicyEngine, executes them through "
        "ActionExecutor, and records a playbook summary in agent state."
    )

    def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        start = time.perf_counter()

        # Lazy imports to avoid circular dependency with workflow_graph
        from src.agent.workflow_integration import (  # type: ignore
            enhanced_respond_node,
            enhanced_execute_node,
        )

        # Check governance decisions before executing
        governance_decisions = state.get("governance_decisions", [])
        blocked_actions = {
            d["action"]
            for d in governance_decisions
            if not d.get("approved", True)
        }
        if blocked_actions:
            state["messages"].append(
                f"⚠️  Governance blocked actions: {blocked_actions}"
            )

        state = enhanced_respond_node(state)
        state = enhanced_execute_node(state)

        # Build lightweight playbook record
        actions = state.get("actions_taken", [])
        selected = state.get("selected_actions", [])
        state["playbook"] = {
            "playbook_id": f"pb-{state.get('session_id', uuid.uuid4().hex)[:8]}",
            "title": "Autonomous Response Playbook",
            "total_actions_planned": len(selected),
            "total_actions_taken": len(actions),
            "steps": [
                {
                    "action": getattr(a, "action_type", type(a).__name__),
                    "target": getattr(a, "target", ""),
                    "automated": True,
                }
                for a in selected
            ],
        }

        duration_ms = (time.perf_counter() - start) * 1000
        session_id = state.get("session_id", "unknown")
        n_taken = len(actions)
        n_planned = len(selected)

        self._emit_trace(
            session_id=session_id,
            input_summary=f"threats={len(state.get('detected_threats', []))}",
            decision=f"{n_taken}/{n_planned} actions executed",
            reasoning="PolicyEngine suggestion + ActionExecutor (simulation-safe)",
            confidence=0.9 if n_taken == n_planned else 0.6,
            duration_ms=duration_ms,
        )
        return state

    def get_capabilities(self) -> List[str]:
        return [
            "policy_engine",
            "action_execution",
            "firewall_block",
            "email_alert",
            "playbook_generation",
        ]
