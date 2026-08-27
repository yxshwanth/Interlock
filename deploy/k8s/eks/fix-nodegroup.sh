#!/usr/bin/env bash
# Fix Free Tier nodegroup failure on an already-ACTIVE EKS control plane.
#
# Failure mode: m5.large is not Free Tier eligible → ManagedNodeGroup CREATE_FAILED.
# This script:
#   1) deletes the rolled-back nodegroup stack (if present)
#   2) installs vpc-cni / kube-proxy / coredns addons (missing after Ctrl+C create)
#   3) creates a Free Tier–eligible nodegroup (default: t3.small)
#
# Usage:
#   export AWS_REGION=us-east-1
#   ./deploy/k8s/eks/fix-nodegroup.sh
set -euo pipefail

export PATH="${HOME}/.local/bin:${PATH}"
export AWS_PAGER=""

CLUSTER_NAME="${CLUSTER_NAME:-interlock-bpf}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
# Free Tier eligible in us-east-1: t3.micro t3.small t4g.* m7i-flex.large c7i-flex.large
# t3.small is the smallest amd64 size that is realistic for an eBPF DaemonSet.
NODE_TYPE="${NODE_TYPE:-t3.small}"
NODES="${NODES:-2}"
NG_NAME="${NG_NAME:-bpf-workers}"
NG_STACK="eksctl-${CLUSTER_NAME}-nodegroup-${NG_NAME}"

echo "==> cluster=${CLUSTER_NAME} region=${AWS_REGION} node=${NODE_TYPE}x${NODES}"
aws sts get-caller-identity
aws eks describe-cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" --query 'cluster.status' --output text | grep -qx ACTIVE

# --- 1) Clean failed / rolled-back nodegroup stack ---
STATUS="$(aws cloudformation describe-stacks --stack-name "${NG_STACK}" --region "${AWS_REGION}" \
  --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo MISSING)"
echo "nodegroup stack: ${STATUS}"
if [[ "${STATUS}" != MISSING ]]; then
  echo "==> deleting ${NG_STACK}"
  aws cloudformation update-termination-protection --no-enable-termination-protection \
    --stack-name "${NG_STACK}" --region "${AWS_REGION}" 2>/dev/null || true
  aws cloudformation delete-stack --stack-name "${NG_STACK}" --region "${AWS_REGION}"
  aws cloudformation wait stack-delete-complete --stack-name "${NG_STACK}" --region "${AWS_REGION}"
  echo "deleted"
fi
# Also try eksctl cleanup if a nodegroup object exists
eksctl delete nodegroup --cluster="${CLUSTER_NAME}" --region="${AWS_REGION}" --name="${NG_NAME}" --wait 2>/dev/null || true

# --- 2) Networking addons first (coredns stays DEGRADED until nodes exist) ---
echo "==> ensuring EKS addons (vpc-cni, kube-proxy; coredns after nodes)"
for addon in vpc-cni kube-proxy; do
  if aws eks describe-addon --cluster-name "${CLUSTER_NAME}" --addon-name "${addon}" --region "${AWS_REGION}" >/dev/null 2>&1; then
    echo "  ${addon}: present"
  else
    echo "  ${addon}: creating…"
    aws eks create-addon --cluster-name "${CLUSTER_NAME}" --addon-name "${addon}" --region "${AWS_REGION}" >/dev/null
  fi
done
# Create coredns if missing, but do not require ACTIVE yet.
if ! aws eks describe-addon --cluster-name "${CLUSTER_NAME}" --addon-name coredns --region "${AWS_REGION}" >/dev/null 2>&1; then
  echo "  coredns: creating (will become ACTIVE after nodes join)…"
  aws eks create-addon --cluster-name "${CLUSTER_NAME}" --addon-name coredns --region "${AWS_REGION}" >/dev/null || true
fi
for addon in vpc-cni kube-proxy; do
  echo -n "  waiting ${addon}…"
  while true; do
    st="$(aws eks describe-addon --cluster-name "${CLUSTER_NAME}" --addon-name "${addon}" --region "${AWS_REGION}" \
      --query 'addon.status' --output text 2>/dev/null || echo MISSING)"
    [[ "${st}" == "ACTIVE" ]] && { echo " ACTIVE"; break; }
    [[ "${st}" == "CREATE_FAILED" || "${st}" == "MISSING" ]] && {
      echo " ${st}"; exit 1; }
    sleep 15
  done
done

# --- 3) Create Free Tier nodegroup ---
CFG="$(mktemp -t eksctl-ng-XXXX.yaml)"
trap 'rm -f "${CFG}"' EXIT
cat >"${CFG}" <<EOF
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: ${CLUSTER_NAME}
  region: ${AWS_REGION}
autoModeConfig:
  enabled: false
managedNodeGroups:
  - name: ${NG_NAME}
    instanceType: ${NODE_TYPE}
    desiredCapacity: ${NODES}
    minSize: 1
    maxSize: ${NODES}
    amiFamily: AmazonLinux2023
    volumeSize: 20
    labels:
      interlock.io/role: sensor-node
EOF

echo "==> creating nodegroup ${NG_NAME} (${NODE_TYPE})"
eksctl create nodegroup -f "${CFG}"

aws eks update-kubeconfig --name "${CLUSTER_NAME}" --region "${AWS_REGION}"
kubectl get nodes -o wide

echo
echo "Next:"
echo "  ./deploy/k8s/eks/push-image.sh"
echo "  kubectl apply -f deploy/k8s/rbac.yaml"
echo "  kubectl apply -f /tmp/interlock-daemonset-capabilities.yaml"
echo "  kubectl apply -f deploy/k8s/service-metrics.yaml"
echo "  ./deploy/k8s/eks/validate.sh"
