"""POST /respond — trigger a response action (honours SIMULATION_MODE)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()


class ActionRequest(BaseModel):
    action_type: str = Field(..., description="block_ip | alert_email | isolate_host | etc.")
    parameters: dict[str, Any] = Field(default_factory=dict)
    priority: str = Field("MEDIUM", description="CRITICAL | HIGH | MEDIUM | LOW")


class ActionResponse(BaseModel):
    action_type: str
    success: bool
    simulated: bool
    message: str
    details: dict[str, Any]


@router.post("", response_model=ActionResponse)
def respond(req: ActionRequest) -> ActionResponse:
    """Execute a defensive response action through the action executor."""
    try:
        from src.actions.action_executor import ActionExecutor  # type: ignore

        executor = ActionExecutor()
        result = executor.execute_action(
            action_type=req.action_type,
            parameters=req.parameters,
        )
        return ActionResponse(
            action_type=req.action_type,
            success=result.success,
            simulated=result.simulated,
            message=result.message,
            details=result.to_dict(),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
