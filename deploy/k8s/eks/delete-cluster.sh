#!/usr/bin/env bash
# Delete the Interlock EKS cluster (stops node charges).
set -euo pipefail
export PATH="${HOME}/.local/bin:${PATH}"

CLUSTER_NAME="${CLUSTER_NAME:-interlock-bpf}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"

echo "==> deleting cluster ${CLUSTER_NAME} in ${AWS_REGION}"
eksctl delete cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" --wait
echo "done"
