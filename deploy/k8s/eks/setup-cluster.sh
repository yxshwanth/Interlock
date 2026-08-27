#!/usr/bin/env bash
# Create or resume a small EKS managed-node cluster for Interlock sensor
# validation (hostPID + BPF + BTF). Amazon Linux 2023 managed nodes — not Fargate.
#
# Prerequisites:
#   ./deploy/k8s/eks/setup-iam.sh   # once, as needed
#   export AWS_REGION=us-east-1
#
# Usage:
#   ./deploy/k8s/eks/setup-cluster.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_PAGER=""

CLUSTER_NAME="${CLUSTER_NAME:-interlock-bpf}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
NODE_TYPE="${NODE_TYPE:-t3.small}"
NODES="${NODES:-2}"
K8S_VERSION="${K8S_VERSION:-1.31}"
STACK="eksctl-${CLUSTER_NAME}-cluster"

echo "==> region=${AWS_REGION} cluster=${CLUSTER_NAME} nodes=${NODES}x ${NODE_TYPE}"
aws sts get-caller-identity

# Fail fast with the real error (do not swallow stderr).
if ! aws eks list-clusters --region "${AWS_REGION}" >/dev/null; then
  echo "ERROR: IAM cannot call eks:ListClusters. Attach lab permissions:"
  echo "  ./deploy/k8s/eks/setup-iam.sh"
  echo "Or IAM console → Users → interlock → AdministratorAccess (lab only)."
  exit 1
fi

wait_for_stack() {
  local name="$1"
  echo "==> waiting for CloudFormation stack ${name} …"
  while true; do
    status="$(aws cloudformation describe-stacks --stack-name "${name}" --region "${AWS_REGION}" \
      --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo MISSING)"
    echo "    ${name}: ${status}"
    case "${status}" in
      CREATE_COMPLETE|UPDATE_COMPLETE) return 0 ;;
      CREATE_FAILED|ROLLBACK_COMPLETE|ROLLBACK_FAILED|DELETE_COMPLETE|MISSING)
        echo "ERROR: stack ${name} ended in ${status}"
        aws cloudformation describe-stack-events --stack-name "${name}" --region "${AWS_REGION}" \
          --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`].[LogicalResourceId,ResourceStatusReason]' \
          --output table 2>/dev/null || true
        return 1
        ;;
      *)
        sleep 30
        ;;
    esac
  done
}

CFG="$(mktemp -t eksctl-XXXX.yaml)"
trap 'rm -f "${CFG}"' EXIT
cat >"${CFG}" <<EOF
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: ${CLUSTER_NAME}
  region: ${AWS_REGION}
  version: "${K8S_VERSION}"

# Keep classic managed node groups (needed for hostPID/eBPF DaemonSet).
autoModeConfig:
  enabled: false

iam:
  withOIDC: true

managedNodeGroups:
  - name: bpf-workers
    instanceType: ${NODE_TYPE}
    desiredCapacity: ${NODES}
    minSize: 1
    maxSize: ${NODES}
    amiFamily: AmazonLinux2023
    privateNetworking: false
    volumeSize: 40
    ssh:
      allow: false
    labels:
      interlock.io/role: sensor-node
    tags:
      project: interlock
EOF

STACK_STATUS="$(aws cloudformation describe-stacks --stack-name "${STACK}" --region "${AWS_REGION}" \
  --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo MISSING)"

CLUSTER_STATUS="$(aws eks describe-cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" \
  --query 'cluster.status' --output text 2>/dev/null || echo MISSING)"

if [[ "${CLUSTER_STATUS}" == "ACTIVE" ]]; then
  echo "cluster already ACTIVE — refreshing kubeconfig"
elif [[ "${STACK_STATUS}" == CREATE_IN_PROGRESS || "${STACK_STATUS}" == UPDATE_IN_PROGRESS || "${CLUSTER_STATUS}" == "CREATING" ]]; then
  echo "CloudFormation/cluster still creating (earlier Ctrl+C is OK) — waiting; do not create again"
  if [[ "${STACK_STATUS}" != MISSING ]]; then
    wait_for_stack "${STACK}"
  fi
  # Poll EKS until ACTIVE
  while true; do
    CLUSTER_STATUS="$(aws eks describe-cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" \
      --query 'cluster.status' --output text 2>/dev/null || echo MISSING)"
    echo "    EKS status: ${CLUSTER_STATUS}"
    [[ "${CLUSTER_STATUS}" == "ACTIVE" ]] && break
    [[ "${CLUSTER_STATUS}" == "FAILED" || "${CLUSTER_STATUS}" == "MISSING" ]] && {
      echo "ERROR: cluster ${CLUSTER_STATUS}"; exit 1; }
    sleep 30
  done
  # Nodegroup stack may still be pending / missing after control plane
  NG_STACK="eksctl-${CLUSTER_NAME}-nodegroup-bpf-workers"
  NG_STATUS="$(aws cloudformation describe-stacks --stack-name "${NG_STACK}" --region "${AWS_REGION}" \
    --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo MISSING)"
  if [[ "${NG_STATUS}" == CREATE_IN_PROGRESS ]]; then
    wait_for_stack "${NG_STACK}"
  elif [[ "${NG_STATUS}" == MISSING ]]; then
    echo "==> creating managed nodegroup via eksctl"
    eksctl create nodegroup -f "${CFG}"
  fi
elif [[ "${STACK_STATUS}" == CREATE_COMPLETE ]]; then
  echo "cluster stack complete — ensuring nodegroup / kubeconfig"
  NG_STACK="eksctl-${CLUSTER_NAME}-nodegroup-bpf-workers"
  NG_STATUS="$(aws cloudformation describe-stacks --stack-name "${NG_STACK}" --region "${AWS_REGION}" \
    --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo MISSING)"
  if [[ "${NG_STATUS}" == MISSING ]]; then
    eksctl create nodegroup -f "${CFG}"
  elif [[ "${NG_STATUS}" == CREATE_IN_PROGRESS ]]; then
    wait_for_stack "${NG_STACK}"
  fi
else
  echo "==> creating cluster (15–25 minutes)…"
  eksctl create cluster -f "${CFG}"
fi

aws eks update-kubeconfig --name "${CLUSTER_NAME}" --region "${AWS_REGION}"
kubectl get nodes -o wide

echo
echo "Next (one step at a time):"
echo "  1. ${ROOT}/deploy/k8s/eks/push-image.sh"
echo "  2. kubectl apply -f ${ROOT}/deploy/k8s/rbac.yaml"
echo "  3. kubectl apply -f /tmp/interlock-daemonset-capabilities.yaml"
echo "  4. kubectl apply -f ${ROOT}/deploy/k8s/service-metrics.yaml"
echo "  5. ${ROOT}/deploy/k8s/eks/validate.sh"
