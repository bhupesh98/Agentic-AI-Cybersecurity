"""
GovernanceAgent — risk threshold enforcement, audit logging, human-in-the-loop.

Evaluates each detected threat against configurable risk thresholds and
decides whether a downstream action should be auto-approved or held for
human review.  Results are written to state['governance_decisions'].
"""

import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base_agent import BaseAgent

logger = logging.getLogger(__name__)

# Default risk thresholds: action → minimum confidence required for auto-approval.
# Actions below medium severity threshold are always auto-approved.
DEFAULT_RISK_THRESHOLDS: Dict[str, float] = {
    "block_ip": 0.65,
    "isolate_host": 0.90,
    "alert_email": 0.40,
    "quarantine_file": 0.85,
}

# Confidence at / above this level → always auto-approve regardless of action
_AUTO_APPROVE_ABOVE = 0.90
# Confidence at / below this level → always require human approval
_ALWAYS_REVIEW_BELOW = 0.30


class GovernanceAgent(BaseAgent):
    """
    Enforces risk thresholds and produces governance_decisions list.

    For each detected threat the agent decides:
    - AUTO_APPROVED  — confidence >= threshold
    - AWAIT_APPROVAL — confidence < threshold (human review required)

    In SIMULATION_MODE all decisions are still recorded but execution
    is already blocked upstream by the simulation guard anyway.
    """

    name = "GovernanceAgent"
    role = "Risk Governance & Human-in-the-Loop"
    description = (
        "Evaluates detected threats against risk thresholds. "
        "High-confidence threats are auto-approved; others are queued for review."
    )

    def __init__(
        self,
        risk_thresholds: Optional[Dict[str, float]] = None,
        trace_manager: Any = None,
    ):
        super().__init__(trace_manager=trace_manager)
        self.risk_thresholds = risk_thresholds or DEFAULT_RISK_THRESHOLDS

    def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        start = time.perf_counter()

        threats = state.get("detected_threats", [])
        investigation = state.get("investigation_report", {})
        overall_risk = investigation.get("risk_score", 0.0)

        governance_decisions: List[Dict[str, Any]] = []

        for threat in threats:
            confidence = float(threat.get("confidence", overall_risk))
            src_ip = threat.get("src_ip", "unknown")
            threat_type = threat.get("predicted_label", threat.get("attack_type", "unknown"))

            # Determine which actions the policy engine would likely take
            candidate_actions = self._infer_actions(confidence, threat_type)

            for action_name in candidate_actions:
                threshold = self.risk_thresholds.get(action_name, 0.7)
                approved = confidence >= threshold or confidence >= _AUTO_APPROVE_ABOVE
                requires_human = confidence <= _ALWAYS_REVIEW_BELOW

                decision: Dict[str, Any] = {
                    "action": action_name,
                    "target": src_ip,
                    "threat_type": threat_type,
                    "confidence": round(confidence, 4),
                    "threshold": threshold,
                    "approved": approved and not requires_human,
                    "status": (
                        "AUTO_APPROVED"
                        if (approved and not requires_human)
                        else "AWAIT_APPROVAL"
                    ),
                    "reasoning": (
                        f"confidence {confidence:.2%} "
                        + ("\u2265" if confidence >= threshold else "<")
                        + f" threshold {threshold:.2%}"
                    ),
                    "timestamp": datetime.utcnow().isoformat(),
                }
                governance_decisions.append(decision)
                logger.info(
                    "Governance [%s] %s → %s for %s",
                    decision["status"],
                    action_name,
                    src_ip,
                    threat_type,
                )

        state["governance_decisions"] = governance_decisions

        duration_ms = (time.perf_counter() - start) * 1000
        session_id = state.get("session_id", "unknown")
        approved_cnt = sum(1 for d in governance_decisions if d.get("approved"))
        pending_cnt = len(governance_decisions) - approved_cnt

        self._emit_trace(
            session_id=session_id,
            input_summary=f"threats={len(threats)}, risk_score={overall_risk:.2f}",
            decision=(
                f"{approved_cnt} actions auto-approved, "
                f"{pending_cnt} await human review"
            ),
            reasoning="Risk threshold comparison per action type",
            confidence=0.95,
            duration_ms=duration_ms,
        )
        return state

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_actions(confidence: float, threat_type: str) -> List[str]:
        """Return list of likely actions based on confidence and threat type."""
        tt = threat_type.upper()
        actions = ["alert_email"]
        if confidence >= 0.4:
            actions.append("block_ip")
        if any(k in tt for k in ["EXFIL", "DATA_THEFT", "RANSOMWARE"]):
            actions.append("isolate_host")
        return actions

    def get_capabilities(self) -> List[str]:
        return [
            "risk_assessment",
            "threshold_enforcement",
            "human_in_the_loop",
            "audit_logging",
            "action_approval",
        ]
