#!/usr/bin/env bash
# Build Interlock image and push to ECR; patch DaemonSet image refs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_PAGER=""

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
IMAGE_NAME="${IMAGE_NAME:-interlock}"
TAG="${TAG:-dev}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
REPO="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${IMAGE_NAME}"
REGISTRY="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

echo "==> ECR ${REPO}:${TAG}"
aws ecr describe-repositories --repository-names "${IMAGE_NAME}" --region "${AWS_REGION}" >/dev/null 2>&1 || \
  aws ecr create-repository --repository-name "${IMAGE_NAME}" --region "${AWS_REGION}" >/dev/null

# Avoid broken system docker-credential-pass ("pass not initialized").
DOCKER_CONFIG_TMP="$(mktemp -d)"
trap 'rm -rf "${DOCKER_CONFIG_TMP}"' EXIT
export DOCKER_CONFIG="${DOCKER_CONFIG_TMP}"
printf '%s\n' '{"auths":{}}' > "${DOCKER_CONFIG}/config.json"

aws ecr get-login-password --region "${AWS_REGION}" | \
  docker login --username AWS --password-stdin "${REGISTRY}"

cd "${ROOT}"
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: cannot talk to Docker daemon (permission denied on /var/run/docker.sock)."
  echo "Fix once, then re-run this script:"
  echo "  sudo usermod -aG docker \"\$USER\""
  echo "  newgrp docker   # or log out/in"
  echo "Patched manifests (if previously written) stay under /tmp/interlock-*.yaml"
  exit 1
fi
docker build -t "${IMAGE_NAME}:${TAG}" .
docker tag "${IMAGE_NAME}:${TAG}" "${REPO}:${TAG}"
docker push "${REPO}:${TAG}"

for f in daemonset.yaml daemonset-capabilities.yaml; do
  # Keep local kind tags intact in git; write a patched copy for apply.
  sed "s|image: interlock:dev|image: ${REPO}:${TAG}|; s|imagePullPolicy: IfNotPresent|imagePullPolicy: Always|" \
    "${ROOT}/deploy/k8s/${f}" > "/tmp/interlock-${f}"
  echo "wrote /tmp/interlock-${f}"
done

echo
echo "Apply capabilities-first (preferred on EKS):"
echo "  kubectl apply -f ${ROOT}/deploy/k8s/rbac.yaml"
echo "  kubectl apply -f /tmp/interlock-daemonset-capabilities.yaml"
echo "  kubectl apply -f ${ROOT}/deploy/k8s/service-metrics.yaml"
