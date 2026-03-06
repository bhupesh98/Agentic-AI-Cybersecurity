"""POST /detect — run ML ensemble detection on a batch of network flows."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()


class FlowRecord(BaseModel):
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    src_port: int = Field(..., ge=0, le=65535)
    dst_port: int = Field(..., ge=0, le=65535)
    protocol: str = "TCP"
    features: dict[str, Any] = Field(default_factory=dict,
                                     description="Pre-extracted feature values")


class DetectRequest(BaseModel):
    flows: list[FlowRecord] = Field(..., min_length=1, max_length=1000)


class DetectResponse(BaseModel):
    results: list[dict[str, Any]]
    total: int
    threats_found: int


@router.post("", response_model=DetectResponse)
def detect(req: DetectRequest) -> DetectResponse:
    """Run ML detection pipeline on the supplied network flows."""
    try:
        from src.agent.state_management import create_initial_state  # type: ignore
        from src.agents.detection_agent import DetectionAgent  # type: ignore

        agent = DetectionAgent()
        results: list[dict[str, Any]] = []
        threats = 0

        for flow in req.flows:
            state = create_initial_state()
            state["network_flows"] = [flow.model_dump()]
            out = agent.process(state)
            detections = out.get("detected_threats", [])
            threats += len(detections)
            results.append({
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "detected_threats": detections,
            })

        return DetectResponse(results=results, total=len(req.flows), threats_found=threats)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
