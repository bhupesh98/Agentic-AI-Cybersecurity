"""GET /incidents, GET /reputation/{ip} — memory access endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter()


class IncidentSummary(BaseModel):
    incident_id: str
    src_ip: str
    severity: str
    threat_type: str
    detected_at: str


@router.get("/incidents", response_model=list[IncidentSummary], tags=["Memory"])
def list_incidents(limit: int = Query(20, ge=1, le=200)) -> list[IncidentSummary]:
    """Return the most recent incidents stored in memory."""
    try:
        import sqlite3
        from src.memory import get_memory_manager  # type: ignore

        memory = get_memory_manager()
        conn = sqlite3.connect(memory.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """SELECT incident_id, src_ip,
                      COALESCE(llm_severity, 'UNKNOWN') AS severity,
                      COALESCE(llm_analysis, 'unknown') AS threat_type,
                      COALESCE(detected_at, timestamp)  AS detected_at
               FROM incidents
               ORDER BY detected_at DESC
               LIMIT ?""",
            (limit,),
        )
        rows = cursor.fetchall()
        conn.close()
        return [
            IncidentSummary(
                incident_id=r["incident_id"],
                src_ip=r["src_ip"],
                severity=r["severity"].upper(),
                threat_type=r["threat_type"][:120],
                detected_at=r["detected_at"] or "",
            )
            for r in rows
        ]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/reputation/{ip}", tags=["Memory"])
def ip_reputation(ip: str) -> dict:
    """Return memory-based threat reputation for an IP address."""
    try:
        from src.memory import get_memory_manager  # type: ignore

        memory = get_memory_manager()
        ctx = memory.get_memory_context(ip)
        return {
            "ip": ip,
            "context": ctx,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
