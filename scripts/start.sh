#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${ROOT_DIR}/run"
ENV_FILE="${ROOT_DIR}/.env"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"

log() {
  printf "[%s] %s\n" "$(date +"%H:%M:%S")" "$*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

compose_cmd() {
  if has_cmd podman && podman compose version >/dev/null 2>&1; then
    echo "podman compose"
    return
  fi
  if has_cmd podman-compose; then
    echo "podman-compose"
    return
  fi
  if has_cmd docker && docker compose version >/dev/null 2>&1; then
    echo "docker compose"
    return
  fi
  if has_cmd docker-compose; then
    echo "docker-compose"
    return
  fi
  echo ""
}

python_bin() {
  if [ -x "${ROOT_DIR}/.venv/bin/python" ]; then
    echo "${ROOT_DIR}/.venv/bin/python"
    return
  fi
  if has_cmd python3; then
    echo "python3"
    return
  fi
  if has_cmd python; then
    echo "python"
    return
  fi
  echo ""
}

ensure_venv() {
  if ! has_cmd uv; then
    echo "Missing uv. Install uv and re-run." >&2
    exit 1
  fi

  if [ -x "${ROOT_DIR}/.venv/bin/python" ]; then
    local venv_minor
    venv_minor="$(${ROOT_DIR}/.venv/bin/python -c "import sys; print(sys.version_info.minor)" 2>/dev/null || echo "")"
    if [ "${venv_minor}" != "11" ] && [ "${venv_minor}" != "12" ]; then
      log "Recreating venv (unsupported Python ${venv_minor})"
      rm -rf "${ROOT_DIR}/.venv"
    else
      return 0
    fi
  fi

  log "Creating venv with uv (Python 3.11)"
  if ! uv venv --python 3.11 "${ROOT_DIR}/.venv"; then
    echo "Failed to create venv with Python 3.11. Install Python 3.11 and re-run." >&2
    exit 1
  fi
  log "Installing dependencies with uv"
  uv pip install "${ROOT_DIR}/.[api]"
}

load_env() {
  if [ ! -f "${ENV_FILE}" ]; then
    echo "Missing .env at ${ENV_FILE}" >&2
    exit 1
  fi
  set -a
  # shellcheck source=/dev/null
  . "${ENV_FILE}"
  set +a

  : "${REDIS_URL:=redis://localhost:6379/0}"
  : "${KAFKA_BOOTSTRAP_SERVERS:=localhost:9092}"
}

start_service() {
  local name="$1"
  shift
  local cmd="$*"
  local pidfile="${RUN_DIR}/${name}.pid"
  local logfile="${RUN_DIR}/${name}.log"

  if [ -f "${pidfile}" ] && kill -0 "$(cat "${pidfile}")" >/dev/null 2>&1; then
    log "${name} already running (pid $(cat "${pidfile}") )"
    return
  fi

  log "Starting ${name}"
  nohup bash -lc "cd '${ROOT_DIR}' && ${cmd}" >>"${logfile}" 2>&1 &
  echo $! >"${pidfile}"
}

main() {
  mkdir -p "${RUN_DIR}"

  load_env

  local compose
  compose="$(compose_cmd)"
  if [ -z "${compose}" ]; then
    echo "Missing docker or podman compose" >&2
    exit 1
  fi

  log "Starting Redis and Kafka (KRaft)"
  ${compose} -f "${COMPOSE_FILE}" up -d redis kafka

  ensure_venv

  if [ -f "${ROOT_DIR}/.venv/bin/activate" ]; then
    # shellcheck source=/dev/null
    . "${ROOT_DIR}/.venv/bin/activate"
  fi

  local py
  py="$(python_bin)"
  if [ -z "${py}" ]; then
    echo "Missing Python interpreter" >&2
    exit 1
  fi

  

  # Verify core Python deps for API/dashboard
  if ! ${py} -c "import uvicorn, streamlit" >/dev/null 2>&1; then
    echo "Python dependencies missing. Install with: pip install '.[api]'" >&2
    exit 1
  fi

  start_service api "SERVICE_TYPE=api REDIS_URL='${REDIS_URL}' KAFKA_BOOTSTRAP_SERVERS='${KAFKA_BOOTSTRAP_SERVERS}' ${py} -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000"
  start_service dashboard "SERVICE_TYPE=dashboard REDIS_URL='${REDIS_URL}' STREAMLIT_BROWSER_GATHER_USAGE_STATS=false STREAMLIT_GATHER_USAGE_STATS=false STREAMLIT_SERVER_HEADLESS=true ${py} -m streamlit run src/dashboard/live_dashboard.py --server.port=8501 --server.address=0.0.0.0 --server.headless=true"

  start_service orchestrator "SERVICE_TYPE=orchestrator REDIS_URL='${REDIS_URL}' KAFKA_BOOTSTRAP_SERVERS='${KAFKA_BOOTSTRAP_SERVERS}' ${py} -m src.agent.workflow_graph"
  start_service ml_detection "SERVICE_TYPE=ml-detection REDIS_URL='${REDIS_URL}' KAFKA_BOOTSTRAP_SERVERS='${KAFKA_BOOTSTRAP_SERVERS}' ${py} -m src.agents.detection_agent"
  start_service llm_reasoning "SERVICE_TYPE=llm-reasoning REDIS_URL='${REDIS_URL}' KAFKA_BOOTSTRAP_SERVERS='${KAFKA_BOOTSTRAP_SERVERS}' ${py} -m src.agents.investigation_agent"
  start_service memory "SERVICE_TYPE=memory REDIS_URL='${REDIS_URL}' ${py} -m src.memory.memory_manager"
  start_service response "SERVICE_TYPE=response REDIS_URL='${REDIS_URL}' KAFKA_BOOTSTRAP_SERVERS='${KAFKA_BOOTSTRAP_SERVERS}' ${py} -m src.agents.response_agent"

  log "Services started. Logs and PID files are in ${RUN_DIR}"
  cat <<EOF

Next steps:
  API:       http://localhost:8000/docs
  Dashboard: http://localhost:8501

To stop everything:
  bash scripts/stop.sh
EOF
}

main "$@"
