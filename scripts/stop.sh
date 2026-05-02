#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${ROOT_DIR}/run"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"

log() {
  printf "[%s] %s\n" "$(date +"%H:%M:%S")" "$*"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

compose_cmd() {
  if [ -n "${COMPOSE_CMD:-}" ]; then
    echo "${COMPOSE_CMD}"
    return
  fi
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

stop_service() {
  local name="$1"
  local pidfile="${RUN_DIR}/${name}.pid"

  if [ ! -f "${pidfile}" ]; then
    return
  fi

  local pid
  pid="$(cat "${pidfile}")"
  if kill -0 "${pid}" >/dev/null 2>&1; then
    log "Stopping ${name} (pid ${pid})"
    kill "${pid}" >/dev/null 2>&1 || true
  fi
  rm -f "${pidfile}"
}

main() {
  local cleanup_all=false
  if [ "${1:-}" = "--all" ]; then
    cleanup_all=true
  fi

  if [ -d "${RUN_DIR}" ]; then
    stop_service response
    stop_service memory
    stop_service llm_reasoning
    stop_service ml_detection
    stop_service orchestrator
    stop_service dashboard
    stop_service api
  fi

  local compose
  compose="$(compose_cmd)"
  if [ -n "${compose}" ]; then
    log "Stopping Redis and Kafka"
    ${compose} -f "${COMPOSE_FILE}" down
  fi

  if [ "${cleanup_all}" = true ]; then
    log "Cleaning run logs"
    find "${RUN_DIR}" -maxdepth 1 -type f -name "*.log" -delete 2>/dev/null || true
    log "Cleaning exported metrics"
    find "${ROOT_DIR}/data/metrics/exports" -type f ! -name ".gitkeep" -delete 2>/dev/null || true
  else
    log "Run logs remain in ${RUN_DIR}"
  fi
}

main "$@"
