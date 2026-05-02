"""GET /dashboard/data — JSON snapshot for external or embedded dashboards."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.get("/data", tags=["Dashboard"])
def dashboard_data() -> dict:
    """Return a combined data snapshot: recent incidents, metrics, budget status."""
    payload: dict = {}

    # Recent incidents
    try:
        from src.dashboard.dashboard_data_loader import get_data_loader  # type: ignore

        payload["recent_incidents"] = get_data_loader().get_recent_threats(limit=20)
    except Exception as exc:
        payload["recent_incidents"] = []
        payload["incidents_error"] = str(exc)

    # Autonomy metrics
    try:
        from src.metrics.autonomy_score import AutonomyScoreCalculator  # type: ignore

        payload["autonomy_metrics"] = AutonomyScoreCalculator().get_current_scores()
    except Exception as exc:
        payload["autonomy_metrics"] = {}
        payload["metrics_error"] = str(exc)

    # Budget
    try:
        from src.llm_agent.llm_budget_manager import get_budget_manager  # type: ignore

        payload["budget"] = get_budget_manager().get_budget_status()
    except Exception as exc:
        payload["budget"] = {}
        payload["budget_error"] = str(exc)

    # Simulation mode
    try:
        from config import settings  # type: ignore

        payload["simulation_mode"] = settings.SIMULATION_MODE
        payload["llm_provider"] = settings.LLM_PROVIDER
    except Exception:
        pass

    return payload


@router.get("/incidents/{incident_id}/summary", tags=["Dashboard"])
def incident_summary(incident_id: str) -> dict:
    """Return an on-demand AI-style incident summary with reasoning and response."""
    try:
        from src.dashboard.dashboard_data_loader import get_data_loader  # type: ignore

        summary = get_data_loader().get_incident_summary(incident_id)
        if not summary:
            raise HTTPException(status_code=404, detail="Incident not found")
        return summary
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
