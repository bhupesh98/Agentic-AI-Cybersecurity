"""
FastAPI application entry-point for the Agentic AI SOC Platform REST gateway.

Routes:
  GET  /health          — liveness probe
  GET  /ready           — readiness probe (checks sub-system availability)
  POST /detect          — run ML detection on a batch of network flows
  POST /analyze         — run LLM threat analysis on a detection result
  GET  /incidents       — list recent incidents from memory
  GET  /reputation/{ip} — threat reputation lookup for an IP
  POST /respond         — trigger a response action (respects SIMULATION_MODE)
  GET  /metrics         — Agentic AI autonomy metrics
  GET  /dashboard/data  — JSON data snapshot for external dashboards

Run with:
  uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import os
import sys

# Ensure project root is on the path when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.api.routes import detection, analyze, memory, actions, metrics, dashboard

app = FastAPI(
    title="Agentic AI SOC Platform",
    description="Autonomous Security Operations Centre — REST API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Tighten in production (set ALLOWED_ORIGINS env var)
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(detection.router, prefix="/detect",    tags=["Detection"])
app.include_router(analyze.router,   prefix="/analyze",   tags=["Analysis"])
app.include_router(memory.router,    prefix="",           tags=["Memory"])
app.include_router(actions.router,   prefix="/respond",   tags=["Response"])
app.include_router(metrics.router,   prefix="/metrics",   tags=["Metrics"])
app.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])


# ── Health / readiness ────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health() -> dict:
    return {"status": "ok"}


@app.get("/ready", tags=["Health"])
def ready() -> JSONResponse:
    checks: dict[str, str] = {}

    # Memory sub-system
    try:
        from src.memory import get_memory_manager  # type: ignore
        get_memory_manager()
        checks["memory"] = "ok"
    except Exception as exc:
        checks["memory"] = f"error: {exc}"

    # Config
    try:
        from config import settings  # type: ignore
        checks["config"] = "ok"
        checks["simulation_mode"] = str(settings.SIMULATION_MODE)
    except Exception as exc:
        checks["config"] = f"error: {exc}"

    all_ok = all(v == "ok" for v in checks.values() if k != "simulation_mode" for k in [v])
    status_code = 200 if checks.get("memory") == "ok" else 503
    return JSONResponse(content={"status": "ready" if status_code == 200 else "not_ready",
                                  "checks": checks},
                        status_code=status_code)
