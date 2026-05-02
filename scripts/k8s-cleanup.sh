#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="soc-platform"
IMAGE_TAR="${IMAGE_TAR:-$HOME/agentic-ai-soc.tar}"

log() {
	printf "[%s] %s\n" "$(date +"%H:%M:%S")" "$*"
}

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Missing required command: $1" >&2
		exit 1
	fi
}

main() {
	require_cmd kubectl

	log "Deleting Kubernetes resources in ${NAMESPACE}"
	kubectl delete -f "${ROOT_DIR}/k8s/hpa.yaml" --ignore-not-found
	kubectl delete -f "${ROOT_DIR}/k8s/deployments" --ignore-not-found
	kubectl delete -f "${ROOT_DIR}/k8s/services.yaml" --ignore-not-found
	kubectl delete -f "${ROOT_DIR}/k8s/ingress.yaml" --ignore-not-found
	kubectl delete -f "${ROOT_DIR}/k8s/configmap.yaml" --ignore-not-found
	kubectl delete secret soc-secrets -n "${NAMESPACE}" --ignore-not-found

	log "Deleting namespace ${NAMESPACE}"
	kubectl delete namespace "${NAMESPACE}" --ignore-not-found

	if [ -f "${IMAGE_TAR}" ]; then
		log "Removing image tar: ${IMAGE_TAR}"
		rm -f "${IMAGE_TAR}"
	else
		log "No image tar found at ${IMAGE_TAR}"
	fi

	log "Cleanup complete (container image caches preserved)."
}

main "$@"
