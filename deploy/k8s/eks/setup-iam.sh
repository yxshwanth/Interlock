#!/usr/bin/env bash
# Attach lab IAM permissions to the interlock IAM user so eksctl + ECR work.
#
# Run this as an account admin (root console user / AdministratorAccess), NOT
# as the limited interlock user:
#
#   export PATH="$HOME/.local/bin:$PATH"
#   # switch to admin credentials first, then:
#   ./deploy/k8s/eks/setup-iam.sh
#
# Lab shortcut (less precise): attach AWS managed AdministratorAccess to user
# interlock in the IAM console, then skip this script.
set -euo pipefail

export PATH="${HOME}/.local/bin:${PATH}"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
POLICY_NAME="${POLICY_NAME:-InterlockEKSLab}"
USER_NAME="${USER_NAME:-interlock}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"

echo "==> caller:"
aws sts get-caller-identity

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"

if aws iam get-policy --policy-arn "${POLICY_ARN}" >/dev/null 2>&1; then
  echo "policy exists: ${POLICY_ARN} — creating new version"
  aws iam create-policy-version \
    --policy-arn "${POLICY_ARN}" \
    --policy-document "file://${ROOT}/deploy/k8s/eks/iam-policy.json" \
    --set-as-default >/dev/null
else
  echo "creating policy ${POLICY_NAME}"
  aws iam create-policy \
    --policy-name "${POLICY_NAME}" \
    --policy-document "file://${ROOT}/deploy/k8s/eks/iam-policy.json" \
    --description "EKS+ECR+eksctl lab permissions for Interlock sensor validation" \
    >/dev/null
fi

echo "attaching ${POLICY_ARN} -> user ${USER_NAME}"
aws iam attach-user-policy --user-name "${USER_NAME}" --policy-arn "${POLICY_ARN}" || true

# Also needed for some eksctl paths that assume service roles.
for managed in \
  arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser
do
  aws iam attach-user-policy --user-name "${USER_NAME}" --policy-arn "${managed}" 2>/dev/null || true
done

echo
echo "Verify as the interlock user:"
echo "  aws sts get-caller-identity"
echo "  aws eks describe-cluster-versions --region ${AWS_REGION} --max-results 1"
echo "Then: ./deploy/k8s/eks/setup-cluster.sh"
