#!/usr/bin/env bash
# Tear down the throwaway LSM/KRSI VM: terminate the instance, remove the
# security group and key pair. Safe to re-run. Run this whenever the VM
# wedges/panics too — cheaper and safer than trying to recover it.
set -euo pipefail
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_PAGER=""

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NAME="${NAME:-interlock-lsm-vm}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
KEY_PATH="${ROOT}/deploy/ec2/.keys/${NAME}.pem"

INSTANCE_IDS="$(aws ec2 describe-instances --region "${AWS_REGION}" \
  --filters "Name=tag:Name,Values=${NAME}" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
  --query 'Reservations[].Instances[].InstanceId' --output text)"

if [[ -n "${INSTANCE_IDS}" ]]; then
  echo "==> terminating: ${INSTANCE_IDS}"
  # shellcheck disable=SC2086
  aws ec2 terminate-instances --region "${AWS_REGION}" --instance-ids ${INSTANCE_IDS} >/dev/null
  # shellcheck disable=SC2086
  aws ec2 wait instance-terminated --region "${AWS_REGION}" --instance-ids ${INSTANCE_IDS}
else
  echo "==> no instance tagged Name=${NAME}"
fi

SG_ID="$(aws ec2 describe-security-groups --region "${AWS_REGION}" \
  --filters "Name=group-name,Values=${NAME}" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo None)"
if [[ "${SG_ID}" != "None" && -n "${SG_ID}" ]]; then
  echo "==> deleting security group ${SG_ID}"
  aws ec2 delete-security-group --region "${AWS_REGION}" --group-id "${SG_ID}" \
    || echo "  (still detaching? wait a minute and re-run this script)"
fi

if aws ec2 describe-key-pairs --key-names "${NAME}" --region "${AWS_REGION}" >/dev/null 2>&1; then
  echo "==> deleting key pair ${NAME}"
  aws ec2 delete-key-pair --key-name "${NAME}" --region "${AWS_REGION}"
fi
rm -f "${KEY_PATH}"

echo "done — no more charges from this VM."
