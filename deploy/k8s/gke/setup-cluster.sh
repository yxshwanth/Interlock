#!/usr/bin/env bash
# Create a small GKE Autopilot-incompatible (Standard) cluster suitable for
# Interlock sensor validation (hostPID + BPF + BTF).
#
# Prerequisites: gcloud authenticated, billing enabled, APIs available.
# Usage:
#   export PROJECT_ID=my-project
#   export ZONE=us-central1-a   # optional
#   ./deploy/k8s/gke/setup-cluster.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
if [[ -f "$HOME/.local/bin/gcloud" ]]; then
  export PATH="$HOME/.local/bin:/tmp/google-cloud-sdk/bin:${PATH}"
fi

PROJECT_ID="${PROJECT_ID:?set PROJECT_ID}"
CLUSTER_NAME="${CLUSTER_NAME:-interlock-bpf}"
ZONE="${ZONE:-us-central1-a}"
MACHINE="${MACHINE:-e2-standard-4}"
NUM_NODES="${NUM_NODES:-1}"

echo "==> Project ${PROJECT_ID} zone ${ZONE} cluster ${CLUSTER_NAME}"
gcloud config set project "${PROJECT_ID}"
gcloud services enable container.googleapis.com --project="${PROJECT_ID}"

if gcloud container clusters describe "${CLUSTER_NAME}" --zone="${ZONE}" >/dev/null 2>&1; then
  echo "cluster already exists"
else
  # Standard (not Autopilot): Autopilot rejects privileged/hostPID DaemonSets.
  gcloud container clusters create "${CLUSTER_NAME}" \
    --zone="${ZONE}" \
    --num-nodes="${NUM_NODES}" \
    --machine-type="${MACHINE}" \
    --release-channel=regular \
    --enable-dataplane-v2 \
    --workload-pool="${PROJECT_ID}.svc.id.goog" \
    --scopes=cloud-platform
fi

gcloud components install gke-gcloud-auth-plugin --quiet || true
gcloud container clusters get-credentials "${CLUSTER_NAME}" --zone="${ZONE}"

echo "==> Node kernel / BTF (from a debug pod if needed):"
kubectl get nodes -o wide
echo
echo "Next:"
echo "  1. Build/push image to Artifact Registry and set image: on the DaemonSet"
echo "  2. kubectl apply -f ${ROOT}/deploy/k8s/rbac.yaml"
echo "  3. kubectl apply -f ${ROOT}/deploy/k8s/daemonset-capabilities.yaml"
echo "  4. ${ROOT}/deploy/k8s/gke/validate.sh"
echo "  5. Record 'Validated on GKE / containerd / kernel X.Y (date)' in PRIVILEGE.md"
