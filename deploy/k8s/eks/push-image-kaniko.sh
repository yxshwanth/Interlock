#!/usr/bin/env bash
# Build+push Interlock image to ECR via Kaniko on the EKS cluster.
# Compiles locally (Go), then Kaniko only packages the runtime image —
# t3.small nodes OOM on in-cluster golang builds.
# No local Docker / sudo required.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_PAGER=""

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
IMAGE_NAME="${IMAGE_NAME:-interlock}"
TAG="${TAG:-dev}"
NS="${BUILD_NAMESPACE:-interlock-system}"
POD="interlock-kaniko-build"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
REPO="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${IMAGE_NAME}"
REGISTRY="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

echo "==> Kaniko build → ${REPO}:${TAG}"
aws ecr describe-repositories --repository-names "${IMAGE_NAME}" --region "${AWS_REGION}" >/dev/null 2>&1 || \
  aws ecr create-repository --repository-name "${IMAGE_NAME}" --region "${AWS_REGION}" >/dev/null

kubectl get ns "${NS}" >/dev/null 2>&1 || kubectl create ns "${NS}"

# ECR pull/push secret for Kaniko (12h token).
TOKEN="$(aws ecr get-login-password --region "${AWS_REGION}")"
AUTH="$(printf 'AWS:%s' "${TOKEN}" | base64 -w0 2>/dev/null || printf 'AWS:%s' "${TOKEN}" | base64)"
kubectl -n "${NS}" delete secret ecr-kaniko 2>/dev/null || true
kubectl -n "${NS}" create secret generic ecr-kaniko \
  --from-literal=config.json="{\"auths\":{\"${REGISTRY}\":{\"auth\":\"${AUTH}\"}}}"

STAGE="$(mktemp -d -t interlock-img-XXXX)"
trap 'rm -rf "${STAGE}"' EXIT

echo "==> compiling linux/amd64 binaries locally"
mkdir -p "${STAGE}/out"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${STAGE}/out/interlock" "${ROOT}/cmd/interlock"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${STAGE}/out/k8s-exfil-demo" "${ROOT}/cmd/k8s-exfil-demo"

cat >"${STAGE}/Dockerfile" <<'EOF'
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
	&& rm -rf /var/lib/apt/lists/*
COPY out/interlock /interlock
COPY out/k8s-exfil-demo /k8s-exfil-demo
ENTRYPOINT ["/interlock"]
EOF

kubectl -n "${NS}" delete pod "${POD}" --ignore-not-found --wait=true 2>/dev/null || true
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${POD}
  namespace: ${NS}
spec:
  restartPolicy: Never
  containers:
    - name: kaniko
      image: gcr.io/kaniko-project/executor:v1.23.2-debug
      command: ["/busybox/sleep", "1800"]
      resources:
        requests:
          memory: 256Mi
          cpu: 100m
        limits:
          memory: 768Mi
      volumeMounts:
        - name: workspace
          mountPath: /workspace
        - name: docker-config
          mountPath: /kaniko/.docker
  volumes:
    - name: workspace
      emptyDir:
        sizeLimit: 256Mi
    - name: docker-config
      secret:
        secretName: ecr-kaniko
        items:
          - key: config.json
            path: config.json
EOF

kubectl -n "${NS}" wait --for=condition=Ready "pod/${POD}" --timeout=120s
kubectl -n "${NS}" exec "${POD}" -- /busybox/mkdir -p /workspace/out

CTX="$(mktemp -t interlock-ctx-XXXX.tgz)"
trap 'rm -rf "${STAGE}"; rm -f "${CTX}"' EXIT
echo "==> packing runtime context"
tar -C "${STAGE}" -czf "${CTX}" Dockerfile out

echo "==> uploading context ($(du -h "${CTX}" | cut -f1))"
kubectl -n "${NS}" cp "${CTX}" "${POD}:/workspace/ctx.tgz"
kubectl -n "${NS}" exec "${POD}" -- /busybox/tar -xzf /workspace/ctx.tgz -C /workspace
kubectl -n "${NS}" exec "${POD}" -- /busybox/rm -f /workspace/ctx.tgz

echo "==> running Kaniko…"
set +e
kubectl -n "${NS}" exec "${POD}" -- /kaniko/executor \
  --dockerfile=/workspace/Dockerfile \
  --context=dir:///workspace \
  --destination="${REPO}:${TAG}" \
  --cache=false \
  --verbosity=info
RC=$?
set -e
if [[ "${RC}" -ne 0 ]]; then
  echo "Kaniko failed (exit ${RC}); pod status:" >&2
  kubectl -n "${NS}" get pod "${POD}" -o wide >&2 || true
  exit "${RC}"
fi

kubectl -n "${NS}" delete pod "${POD}" --ignore-not-found >/dev/null
kubectl -n "${NS}" delete secret ecr-kaniko --ignore-not-found >/dev/null

for f in daemonset.yaml daemonset-capabilities.yaml; do
  sed "s|image: interlock:dev|image: ${REPO}:${TAG}|; s|imagePullPolicy: IfNotPresent|imagePullPolicy: Always|" \
    "${ROOT}/deploy/k8s/${f}" > "/tmp/interlock-${f}"
  echo "wrote /tmp/interlock-${f}"
done

echo
echo "Done. Apply:"
echo "  kubectl apply -f /tmp/interlock-daemonset-capabilities.yaml"
echo "  ./deploy/k8s/eks/validate.sh"
