"""POST /analyze — run LLM threat analysis on detection results."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()


class AnalyzeRequest(BaseModel):
    threat_data: dict[str, Any] = Field(..., description="Detection output to analyse")
    severity: str = Field("MEDIUM", description="CRITICAL | HIGH | MEDIUM | LOW")


class AnalyzeResponse(BaseModel):
    threat_type: str
    confidence: float
    evidence: list[str]
    recommendation: str
    risk_score: float
    raw_analysis: dict[str, Any]


@router.post("", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    """Run the LLM investigation agent and return a structured analysis."""
    try:
        from src.agent.state_management import create_initial_state  # type: ignore
        from src.agents.investigation_agent import InvestigationAgent  # type: ignore

        agent = InvestigationAgent()
        state = create_initial_state()
        state["detected_threats"] = [req.threat_data]
        out = agent.process(state)
        report = out.get("investigation_report", {})
        return AnalyzeResponse(
            threat_type=report.get("threat_type", "unknown"),
            confidence=float(report.get("confidence", 0.0)),
            evidence=report.get("evidence", []),
            recommendation=report.get("recommendation", ""),
            risk_score=float(report.get("risk_score", 0.0)),
            raw_analysis=report,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
