#!/usr/bin/env bash
# Smoke-validate Interlock sensor on the current kubectl context (EKS).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
NS=interlock-system
export PATH="${HOME}/.local/bin:${PATH}"

echo "==> context: $(kubectl config current-context)"
kubectl get ns "${NS}" >/dev/null

echo "==> DaemonSet"
kubectl -n "${NS}" get ds interlock-sensor -o wide
kubectl -n "${NS}" rollout status ds/interlock-sensor --timeout=180s

POD="$(kubectl -n "${NS}" get pod -l app.kubernetes.io/component=sensor -o jsonpath='{.items[0].metadata.name}')"
echo "==> sensor pod: ${POD}"

echo "==> healthz"
# Slim image has no curl/wget — probe via local port-forward.
PF_LOG="$(mktemp)"
kubectl -n "${NS}" port-forward "${POD}" 19090:9090 >"${PF_LOG}" 2>&1 &
PF_PID=$!
cleanup_pf() { kill "${PF_PID}" 2>/dev/null || true; rm -f "${PF_LOG}"; }
trap cleanup_pf EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -sf http://127.0.0.1:19090/healthz; then
    echo
    break
  fi
  sleep 0.5
done
if ! curl -sf http://127.0.0.1:19090/healthz >/dev/null; then
  echo "healthz failed; port-forward log:" >&2
  cat "${PF_LOG}" >&2 || true
  exit 1
fi
cleanup_pf
trap - EXIT

echo "==> node OS / kernel (from node)"
NODE="$(kubectl -n "${NS}" get pod "${POD}" -o jsonpath='{.spec.nodeName}')"
kubectl get node "${NODE}" -o jsonpath='{.status.nodeInfo.osImage}{" | kernel "}{.status.nodeInfo.kernelVersion}{" | runtime "}{.status.nodeInfo.containerRuntimeVersion}{"\n"}'

echo "==> securityContext"
kubectl -n "${NS}" get pod "${POD}" -o jsonpath='{.spec.containers[0].securityContext}' ; echo

echo "==> recent logs"
kubectl -n "${NS}" logs "${POD}" --tail=80

echo
echo "Manual cross-pod step:"
echo "  kubectl apply -f ${ROOT}/deploy/k8s/demo/exfil-pod.yaml"
echo "  kubectl -n ${NS} logs ${POD} -f   # look for EXFIL / detections"
echo "Then append to PRIVILEGE.md:"
echo "  Validated on EKS / containerd / kernel <from above> (\$(date -I))"
