#!/usr/bin/env bash
# kind smoke demo for the sensor-only DaemonSet.
# Prerequisites: docker, kind, kubectl, Go 1.25+, Linux host with BTF in kind nodes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER="${INTERLOCK_KIND_CLUSTER:-interlock}"
IMAGE="${INTERLOCK_IMAGE:-interlock:dev}"

log() { printf '[demo-k8s] %s\n' "$*"; }

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing dependency: $1" >&2
    case "$1" in
      kind)
        echo "  install: curl -fsSL -o ~/.local/bin/kind https://kind.sigs.k8s.io/dl/v0.27.0/kind-linux-amd64 && chmod +x ~/.local/bin/kind" >&2
        echo "  (ensure ~/.local/bin is on PATH)" >&2
        ;;
      kubectl)
        echo "  install: see https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/" >&2
        echo "  or: curl -fsSL -o ~/.local/bin/kubectl \"https://dl.k8s.io/release/\$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl\" && chmod +x ~/.local/bin/kubectl" >&2
        ;;
      docker)
        echo "  install Docker Desktop or docker engine, then retry" >&2
        ;;
    esac
    exit 1
  fi
}

need docker
need kind
need kubectl

cd "$ROOT"

log "building image ${IMAGE}"
docker build -t "${IMAGE}" .

if ! kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
  log "creating kind cluster ${CLUSTER}"
  kind create cluster --name "${CLUSTER}"
else
  log "using existing kind cluster ${CLUSTER}"
fi

log "loading image into kind"
kind load docker-image "${IMAGE}" --name "${CLUSTER}"

log "applying manifests"
kubectl apply -f "${ROOT}/deploy/k8s/rbac.yaml"
kubectl apply -f "${ROOT}/deploy/k8s/daemonset.yaml"
kubectl apply -f "${ROOT}/deploy/k8s/service-metrics.yaml"
# Same tag (interlock:dev) may already be present — force pods onto the freshly loaded image.
kubectl -n interlock-system rollout restart daemonset/interlock-sensor 2>/dev/null || true

log "waiting for DaemonSet"
kubectl -n interlock-system rollout status daemonset/interlock-sensor --timeout=180s

log "applying demo exfil pod"
kubectl delete pod interlock-exfil-demo --ignore-not-found=true
kubectl apply -f "${ROOT}/deploy/k8s/demo/exfil-pod.yaml"

log "waiting for demo pod to start"
kubectl wait --for=condition=Ready pod/interlock-exfil-demo --timeout=60s || true

# Wait for DELAY_SEC (12) + dials + deferred kill window.
sleep 25

SENSOR_POD="$(kubectl -n interlock-system get pod -l app.kubernetes.io/component=sensor -o jsonpath='{.items[0].metadata.name}')"
if [[ -z "${SENSOR_POD}" ]]; then
  echo "no sensor pod found" >&2
  kubectl -n interlock-system get pods -o wide >&2 || true
  exit 1
fi

log "sensor pod: ${SENSOR_POD}"
kubectl -n interlock-system logs "${SENSOR_POD}" --tail=120 || true

# Also dump events for debugging attribution races.
EVENTS="$(kubectl -n interlock-system exec "${SENSOR_POD}" -- cat /var/log/interlock/events.jsonl 2>/dev/null || true)"
EVIDENCE="$(kubectl -n interlock-system exec "${SENSOR_POD}" -- cat /var/log/interlock/evidence.jsonl 2>/dev/null || true)"
if [[ -z "${EVIDENCE}" ]]; then
  echo "FAIL: no evidence written (sensor may lack BTF/caps — see deploy/k8s/PRIVILEGE.md)" >&2
  echo "--- events.jsonl ---" >&2
  echo "${EVENTS}" >&2
  kubectl -n interlock-system describe pod "${SENSOR_POD}" >&2 || true
  exit 1
fi

echo "${EVIDENCE}" | tee /tmp/interlock-k8s-evidence.jsonl

DEMO_SECRET='sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef'

if ! echo "${EVIDENCE}" | grep -q 'pod_context'; then
  echo "FAIL: evidence missing pod_context" >&2
  exit 1
fi
if ! echo "${EVIDENCE}" | grep -q '"verdict":"EXFIL"'; then
  echo "FAIL: expected EXFIL verdict (sensitive-read → tainted write)" >&2
  echo "${EVIDENCE}" >&2
  exit 1
fi
if ! echo "${EVIDENCE}" | grep -q '0.95\|"confidence":0.95'; then
  echo "FAIL: expected confidence 0.95 on EXFIL" >&2
  exit 1
fi
if echo "${EVIDENCE}" | grep -Fq "${DEMO_SECRET}"; then
  echo "FAIL: raw demo secret leaked into evidence (redaction broken)" >&2
  exit 1
fi
if ! echo "${EVIDENCE}" | grep -q 'contained_by_kill'; then
  echo "FAIL: evidence missing contained_by_kill action" >&2
  exit 1
fi

log "OK: EXFIL + pod_context + redacted payload_excerpt"
echo "${EVIDENCE}" | head -c 2500
echo
