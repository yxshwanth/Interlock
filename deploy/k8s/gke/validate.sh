#!/usr/bin/env bash
# Smoke-validate Interlock sensor on the current kubectl context (GKE/EKS).
# Does not claim success in PRIVILEGE.md — operator appends the validated line.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
NS=interlock-system

echo "==> context: $(kubectl config current-context)"
kubectl get ns "${NS}" >/dev/null

echo "==> DaemonSet"
kubectl -n "${NS}" get ds interlock-sensor -o wide
kubectl -n "${NS}" rollout status ds/interlock-sensor --timeout=180s

POD="$(kubectl -n "${NS}" get pod -l app.kubernetes.io/component=sensor -o jsonpath='{.items[0].metadata.name}')"
echo "==> sensor pod: ${POD}"

echo "==> healthz"
kubectl -n "${NS}" exec "${POD}" -- wget -qO- http://127.0.0.1:9090/healthz || \
  kubectl -n "${NS}" exec "${POD}" -- curl -sf http://127.0.0.1:9090/healthz

echo "==> recent logs (probe attach / errors)"
kubectl -n "${NS}" logs "${POD}" --tail=80

echo "==> securityContext (expect capabilities, not privileged, for caps manifest)"
kubectl -n "${NS}" get pod "${POD}" -o jsonpath='{.spec.containers[0].securityContext}' ; echo

echo
echo "Manual cross-pod step:"
echo "  kubectl apply -f ${ROOT}/deploy/k8s/demo/exfil-pod.yaml"
echo "  kubectl -n ${NS} logs ${POD} -f   # look for EXFIL / detections"
echo "Then append to PRIVILEGE.md: Validated on GKE|EKS / containerd / kernel X.Y (date)"
