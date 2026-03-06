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
        import sqlite3
        from src.memory import get_memory_manager  # type: ignore

        memory = get_memory_manager()
        conn = sqlite3.connect(memory.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT incident_id, src_ip, llm_severity, detected_at "
            "FROM incidents ORDER BY detected_at DESC LIMIT 20"
        )
        rows = cursor.fetchall()
        conn.close()
        payload["recent_incidents"] = [dict(r) for r in rows]
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
