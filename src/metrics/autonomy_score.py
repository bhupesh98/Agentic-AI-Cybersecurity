"""
AutonomyScoreCalculator — structured interface to the 7-principle Agentic AI metrics.

Wraps AgenticAIMetricsSummary.calculate_overall_agentic_score() and exposes
a dashboard-friendly dict for each principle as well as an overall
Agent Autonomy Index with trend history.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_PRINCIPLE_WEIGHTS: Dict[str, float] = {
    "self_learning": 1.0,
    "contextual_awareness": 0.5,
    "goal_directed": 1.0,
    "tool_utilization": 1.0,
    "planning_reasoning": 1.0,
    "memory_management": 1.0,
    "feedback_incorporation": 1.0,
}

# Autonomy index interpretation bands
_BANDS = [
    (0.90, "Excellent — research-grade autonomy"),
    (0.80, "Good — production-ready"),
    (0.70, "Moderate — needs improvement"),
    (0.00, "Limited autonomous behaviour"),
]


class AutonomyScoreCalculator:
    """
    Dashboard-oriented wrapper around the existing AgenticAIMetricsSummary.

    Adds:
    - Per-principle score dict for panel rendering
    - agent_autonomy_index: final weighted composite score
    - trend_data: historical scores pulled from the metrics storage
    - interpretation: human-readable band label
    """

    def get_current_scores(
        self, summary: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Compute or return the full autonomy score breakdown.

        Args:
            summary: Optional pre-built AgenticAIMetricsSummary.  If None,
                     a fresh summary is fetched from the global MetricsCollector.

        Returns:
            Dict suitable for direct Streamlit panel rendering.
        """
        if summary is None:
            summary = self._fetch_summary()
        if summary is None:
            return self._empty_scores()

        # Per-principle scores
        principles: Dict[str, float] = {}
        try:
            p = summary.self_learning
            learning_v = min(p.calculate_learning_velocity() / 5.0, 1.0)
            rule_d = p.calculate_rule_diversity()
            principles["self_learning"] = round(learning_v * 0.6 + rule_d * 0.4, 4)
        except Exception:
            principles["self_learning"] = 0.0

        try:
            principles["contextual_awareness"] = round(
                summary.contextual_awareness.calculate_context_incorporation_rate(), 4
            )
        except Exception:
            principles["contextual_awareness"] = 0.0

        try:
            principles["goal_directed"] = round(
                summary.goal_directed.calculate_goal_completion_rate(), 4
            )
        except Exception:
            principles["goal_directed"] = 0.0

        try:
            principles["tool_utilization"] = round(
                summary.tool_utilization.calculate_overall_tool_effectiveness(), 4
            )
        except Exception:
            principles["tool_utilization"] = 0.0

        try:
            principles["planning_reasoning"] = round(
                summary.planning_reasoning.calculate_decision_quality_score(), 4
            )
        except Exception:
            principles["planning_reasoning"] = 0.0

        try:
            mem = summary.memory_management
            principles["memory_management"] = round(
                mem.calculate_memory_utilization_rate() * 0.5
                + mem.calculate_retrieval_accuracy() * 0.5,
                4,
            )
        except Exception:
            principles["memory_management"] = 0.0

        try:
            fb = summary.feedback_incorporation
            principles["feedback_incorporation"] = round(
                fb.calculate_feedback_incorporation_rate() * 0.7
                + fb.calculate_rule_effectiveness() * 0.3,
                4,
            )
        except Exception:
            principles["feedback_incorporation"] = 0.0

        # Weighted composite (agent autonomy index)
        weighted_sum = sum(
            principles.get(p, 0.0) * w for p, w in _PRINCIPLE_WEIGHTS.items()
        )
        total_weight = sum(_PRINCIPLE_WEIGHTS.values())
        aai = round(weighted_sum / total_weight, 4) if total_weight > 0 else 0.0

        return {
            "agent_autonomy_index": aai,
            "interpretation": self._interpret(aai),
            "principles": principles,
            "principle_weights": _PRINCIPLE_WEIGHTS,
            "session_id": getattr(summary, "session_id", "unknown"),
            "timestamp": getattr(summary, "timestamp", datetime.utcnow().isoformat()),
        }

    def get_trend_data(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Return historical autonomy scores for trend charts.

        Args:
            limit: Maximum number of historical sessions to retrieve.

        Returns:
            List of dicts with 'timestamp' and 'overall_agentic_score' keys.
        """
        try:
            from src.metrics.storage import MetricsStorage  # type: ignore

            storage = MetricsStorage()
            rows = storage.get_recent_sessions(limit=limit)
            return [
                {
                    "timestamp": r.get("timestamp", ""),
                    "overall_agentic_score": r.get("overall_agentic_score", 0.0),
                    "session_id": r.get("session_id", ""),
                }
                for r in rows
            ]
        except Exception as exc:
            logger.debug("Trend data unavailable: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fetch_summary() -> Optional[Any]:
        try:
            from src.metrics import get_metrics_collector  # type: ignore

            collector = get_metrics_collector()
            return collector.get_summary()
        except Exception:
            return None

    @staticmethod
    def _interpret(score: float) -> str:
        for threshold, label in _BANDS:
            if score >= threshold:
                return label
        return _BANDS[-1][1]

    @staticmethod
    def _empty_scores() -> Dict[str, Any]:
        return {
            "agent_autonomy_index": 0.0,
            "interpretation": "No data — metrics not yet collected",
            "principles": {p: 0.0 for p in _PRINCIPLE_WEIGHTS},
            "principle_weights": _PRINCIPLE_WEIGHTS,
            "session_id": "none",
            "timestamp": datetime.utcnow().isoformat(),
        }
