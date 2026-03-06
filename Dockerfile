# ─────────────────────────────────────────────────────────────────────────────
# Agentic AI SOC Platform — multi-stage Dockerfile
#
# SERVICE_TYPE (set at runtime) controls which process is launched:
#   orchestrator   — LangGraph multi-agent orchestration loop
#   ml-detection   — ML ensemble inference worker
#   llm-reasoning  — LLM analysis worker
#   memory         — Memory / vector-search service
#   response       — Response execution worker
#   dashboard      — Streamlit SOC dashboard  (port 8501)
#   api            — FastAPI REST gateway      (port 8000)
#   metrics        — Prometheus metrics exporter
#   packet-capture — Scapy packet capture (requires host networking)
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: dependency builder ───────────────────────────────────────────────
FROM python:3.11-slim AS builder

# System libs required by some transitive deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy dependency manifest first for layer caching
COPY pyproject.toml ./

# Install uv (fast pip replacement), then all deps into /build/.venv
RUN pip install --no-cache-dir uv==0.5.* && \
    uv venv .venv && \
    uv pip install --no-cache ".[api]"

# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /build/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Copy application code
COPY config/ ./config/
COPY src/     ./src/
COPY models/  ./models/

# Data directory — will be mounted as a volume at runtime
RUN mkdir -p data && chown -R appuser:appuser /app

USER appuser

# Environment defaults (override with --env-file or docker-compose envs)
ENV PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONPATH=/app \
    LOG_LEVEL=INFO \
    SIMULATION_MODE=true \
    ENABLE_METRICS=true \
    SERVICE_TYPE=orchestrator

EXPOSE 8000 8501

# Entrypoint dispatches to the correct process based on SERVICE_TYPE
ENTRYPOINT ["/bin/sh", "-c", "\
  case \"$SERVICE_TYPE\" in \
    orchestrator)   exec python -m src.agent.workflow_graph ;; \
    ml-detection)   exec python -m src.agents.detection_agent ;; \
    llm-reasoning)  exec python -m src.agents.investigation_agent ;; \
    memory)         exec python -m src.memory.memory_manager ;; \
    response)       exec python -m src.agents.response_agent ;; \
    dashboard)      exec streamlit run src/dashboard/live_dashboard.py --server.port=8501 --server.address=0.0.0.0 ;; \
    api)            exec uvicorn src.api.app:app --host 0.0.0.0 --port 8000 ;; \
    metrics)        exec python -m src.metrics.autonomy_score ;; \
    packet-capture) exec python -m src.data_processing.packet_capture ;; \
    *)              echo \"Unknown SERVICE_TYPE: $SERVICE_TYPE\" && exit 1 ;; \
  esac \
"]
