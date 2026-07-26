#!/usr/bin/env bash
# rsync the working tree (including uncommitted changes) to the throwaway VM.
# LSM/eBPF code has to be built and loaded against a real kernel — it can't be
# exercised locally — so re-run this after every local edit, then build/test
# over SSH. Honors .gitignore via rsync's filter merge.
set -euo pipefail
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_PAGER=""

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NAME="${NAME:-interlock-lsm-vm}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
KEY_PATH="${ROOT}/deploy/ec2/.keys/${NAME}.pem"
REMOTE_DIR="${REMOTE_DIR:-~/interlock}"

INSTANCE_ID="$(aws ec2 describe-instances --region "${AWS_REGION}" \
  --filters "Name=tag:Name,Values=${NAME}" "Name=instance-state-name,Values=running" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null || echo None)"
if [[ "${INSTANCE_ID}" == "None" || -z "${INSTANCE_ID}" ]]; then
  echo "ERROR: no running instance tagged Name=${NAME}. Run ./deploy/ec2/setup-instance.sh first." >&2
  exit 1
fi

PUBLIC_IP="$(aws ec2 describe-instances --region "${AWS_REGION}" --instance-ids "${INSTANCE_ID}" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"

echo "==> syncing ${ROOT} -> ubuntu@${PUBLIC_IP}:${REMOTE_DIR}"
rsync -az --delete \
  --filter=':- .gitignore' \
  --exclude='.git/' --exclude='deploy/ec2/.keys/' \
  -e "ssh -o StrictHostKeyChecking=accept-new -i ${KEY_PATH}" \
  "${ROOT}/" "ubuntu@${PUBLIC_IP}:${REMOTE_DIR}/"
echo "done — ./deploy/ec2/ssh.sh to build/test"
