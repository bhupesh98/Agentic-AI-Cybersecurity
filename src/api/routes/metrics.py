"""GET /metrics — Agentic AI autonomy metrics."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.get("", tags=["Metrics"])
def get_metrics() -> dict:
    """Return current Agentic AI principle scores and autonomy index."""
    try:
        from src.metrics.autonomy_score import AutonomyScoreCalculator  # type: ignore

        calc = AutonomyScoreCalculator()
        return calc.get_current_scores()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/budget", tags=["Metrics"])
def get_budget() -> dict:
    """Return current LLM budget usage."""
    try:
        from src.llm_agent.llm_budget_manager import get_budget_manager  # type: ignore

        return get_budget_manager().get_budget_status()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
