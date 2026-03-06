"""
ContextCompressionEngine — reduces LLM prompt token usage by 70-80%.

Instead of feeding raw JSON (800+ tokens) to the LLM, this engine
produces a structured ~200-token text block with the same essential
information.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ContextCompressionEngine:
    """
    Compresses network flow + ML prediction + memory context into a
    dense, token-efficient text block for LLM consumption.

    Example output (~170 tokens):
        THREAT SUMMARY
        Source: 192.168.1.10:4444 → 10.0.0.1:22 (TCP)
        ML: DoS/DDoS (confidence: 94%, agreement: 100%)
        Context: after_hours, high_volume_transfer
        Memory: 3 similar incidents, top severity: HIGH, REPEAT OFFENDER
    """

    def compress(
        self,
        flow: Any,
        ml_prediction: Optional[Dict[str, Any]],
        context_flags: Optional[List[str]],
        memory_hits: Optional[List[Dict[str, Any]]],
    ) -> str:
        """
        Produce a ~200-token structured threat summary string.

        Args:
            flow: NetworkFlow object or dict with src_ip, dst_ip, etc.
            ml_prediction: Dict with ensemble_prediction, ensemble_confidence,
                           agreement_score  (or MLPrediction .to_dict()).
            context_flags: List of context flag strings e.g. ["after_hours"].
            memory_hits:   List of memory context dicts from MemoryManager.

        Returns:
            Compact text suitable for direct inclusion in an LLM prompt.
        """
        # --- Extract flow fields ---
        if hasattr(flow, "to_dict"):
            flow = flow.to_dict()
        if not isinstance(flow, dict):
            flow = {}

        src_ip = flow.get("src_ip", "unknown")
        src_port = flow.get("src_port", 0)
        dst_ip = flow.get("dst_ip", "unknown")
        dst_port = flow.get("dst_port", 0)
        protocol = flow.get("protocol", "unknown")

        # --- Extract ML prediction fields ---
        pred = ml_prediction or {}
        ensemble_pred = pred.get("ensemble_prediction", "unknown")
        confidence = float(pred.get("ensemble_confidence", 0.0))
        agreement = float(pred.get("agreement_score", 0.0))

        # --- Context flags ---
        context_str = ", ".join(context_flags) if context_flags else "none"

        # --- Memory summary ---
        n_hits = len(memory_hits) if memory_hits else 0
        if n_hits == 0:
            memory_str = "no similar incidents"
        else:
            top_severity = self._top_severity(memory_hits)
            repeat_offender = n_hits >= 2
            memory_str = (
                f"{n_hits} similar incident{'s' if n_hits != 1 else ''}, "
                f"top severity: {top_severity}"
            )
            if repeat_offender:
                memory_str += ", REPEAT OFFENDER"

        return (
            "THREAT SUMMARY\n"
            f"Source: {src_ip}:{src_port} \u2192 {dst_ip}:{dst_port} ({protocol})\n"
            f"ML: {ensemble_pred} (confidence: {confidence:.0%}, agreement: {agreement:.0%})\n"
            f"Context: {context_str}\n"
            f"Memory: {memory_str}"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _top_severity(memory_hits: List[Dict[str, Any]]) -> str:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        severities = {
            str(h.get("severity", "")).upper()
            for h in memory_hits
        }
        for sev in order:
            if sev in severities:
                return sev
        return "UNKNOWN"


# Module-level singleton
_engine: Optional[ContextCompressionEngine] = None


def get_compression_engine() -> ContextCompressionEngine:
    """Return the module-level ContextCompressionEngine singleton."""
    global _engine
    if _engine is None:
        _engine = ContextCompressionEngine()
    return _engine
