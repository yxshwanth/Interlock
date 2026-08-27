#!/usr/bin/env bash
# SSH into the throwaway LSM/KRSI VM. Any args are passed through as a remote
# command, e.g.: ./deploy/ec2/ssh.sh 'tail -f /var/log/interlock-bootstrap.log'
set -euo pipefail
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_PAGER=""

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NAME="${NAME:-interlock-lsm-vm}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
KEY_PATH="${ROOT}/deploy/ec2/.keys/${NAME}.pem"

INSTANCE_ID="$(aws ec2 describe-instances --region "${AWS_REGION}" \
  --filters "Name=tag:Name,Values=${NAME}" "Name=instance-state-name,Values=running" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null || echo None)"
if [[ "${INSTANCE_ID}" == "None" || -z "${INSTANCE_ID}" ]]; then
  echo "ERROR: no running instance tagged Name=${NAME}. Run ./deploy/ec2/setup-instance.sh first." >&2
  exit 1
fi

PUBLIC_IP="$(aws ec2 describe-instances --region "${AWS_REGION}" --instance-ids "${INSTANCE_ID}" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"

exec ssh -o StrictHostKeyChecking=accept-new -i "${KEY_PATH}" "ubuntu@${PUBLIC_IP}" "$@"
