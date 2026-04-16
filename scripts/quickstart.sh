#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="soc-platform"
IMAGE_NAME="${IMAGE_NAME:-localhost/agentic-ai-soc:latest}"
IMAGE_TAR="${IMAGE_TAR:-$HOME/agentic-ai-soc.tar}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-60s}"

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

select_minikube_driver() {
	if [ -n "${MINIKUBE_DRIVER:-}" ]; then
		echo "${MINIKUBE_DRIVER}"
		return
	fi
	if has_cmd docker; then
		echo "docker"
		return
	fi
	if has_cmd podman; then
		echo "podman"
		return
	fi
	echo "docker"
}

minikube_running() {
	minikube status --format "{{.Host}}" 2>/dev/null | grep -qi running
}

load_image_into_minikube() {
	if minikube image list | grep -q "${IMAGE_NAME}$"; then
		log "Image already in Minikube: ${IMAGE_NAME}"
		return
	fi

	if [ -f "${IMAGE_TAR}" ]; then
		log "Loading image tar into Minikube: ${IMAGE_TAR}"
		minikube image load "${IMAGE_TAR}"
		return
	fi

	if has_cmd docker; then
		log "Building Docker image: ${IMAGE_NAME}"
		docker build -t "${IMAGE_NAME}" "${ROOT_DIR}"
		log "Saving image tar: ${IMAGE_TAR}"
		docker save -o "${IMAGE_TAR}" "${IMAGE_NAME}"
		log "Loading image tar into Minikube"
		minikube image load "${IMAGE_TAR}"
		return
	fi

	if has_cmd podman; then
		log "Building Podman image: ${IMAGE_NAME}"
		podman build -t "${IMAGE_NAME}" "${ROOT_DIR}"
		log "Saving image tar: ${IMAGE_TAR}"
		podman save -o "${IMAGE_TAR}" "${IMAGE_NAME}"
		log "Loading image tar into Minikube"
		minikube image load "${IMAGE_TAR}"
		return
	fi

	log "Docker not available; building directly in Minikube"
	minikube image build -t "${IMAGE_NAME}" "${ROOT_DIR}"
}

ensure_secret() {
	local env_file="$1"
	if kubectl -n "${NAMESPACE}" get secret soc-secrets >/dev/null 2>&1; then
		log "Secret already exists: soc-secrets"
		return
	fi
	log "Creating Kubernetes secret from ${env_file}"
	kubectl -n "${NAMESPACE}" create secret generic soc-secrets --from-env-file="${env_file}"
}

main() {
	require_cmd minikube
	require_cmd kubectl
	if ! minikube_running; then
		local driver
		driver="$(select_minikube_driver)"
		log "Starting Minikube"
		minikube start --driver="${driver}"
	else
		log "Minikube already running"
	fi

    if ! minikube addons list | grep -q "ingress.*enabled"; then
	    log "Enabling ingress addon"
        minikube addons enable ingress
    else
        log "Ingress addon already enabled"
    fi

	load_image_into_minikube

	log "Applying namespace and config"
	kubectl apply -f "${ROOT_DIR}/k8s/namespace.yaml"
	kubectl apply -f "${ROOT_DIR}/k8s/configmap.yaml"

	if [ ! -f "${ROOT_DIR}/.env" ]; then
		echo "Missing .env at project root: ${ROOT_DIR}/.env" >&2
		exit 1
	fi
	ensure_secret "${ROOT_DIR}/.env"

	log "Applying PVCs and ingress"
	kubectl apply -f "${ROOT_DIR}/k8s/ingress.yaml"

	log "Applying services"
	kubectl apply -f "${ROOT_DIR}/k8s/services.yaml"

	log "Applying deployments"
	kubectl apply -f "${ROOT_DIR}/k8s/deployments"

	log "Applying autoscalers"
	kubectl apply -f "${ROOT_DIR}/k8s/hpa.yaml"

	log "Waiting for deployments (timeout: ${WAIT_TIMEOUT})"
	kubectl -n "${NAMESPACE}" get pods
	for deploy in redis kafka orchestrator api dashboard; do
		kubectl -n "${NAMESPACE}" rollout status "deployment/${deploy}" --timeout="${WAIT_TIMEOUT}"
	done

	log "Done. Services are deployed to namespace: ${NAMESPACE}"
	cat <<EOF

Next steps:
	kubectl -n ${NAMESPACE} port-forward svc/api 8000:8000
	kubectl -n ${NAMESPACE} port-forward svc/dashboard 8501:8501

If pods fail to become Ready, check logs with:
	kubectl -n ${NAMESPACE} get pods
	kubectl -n ${NAMESPACE} logs deploy/api --tail=200
	kubectl -n ${NAMESPACE} logs deploy/dashboard --tail=200
	kubectl -n ${NAMESPACE} logs deploy/kafka --tail=200


	API docs: http://localhost:8000/docs
	Dashboard: http://localhost:8501
EOF
}

main "$@"