#!/usr/bin/env bash
# Launch a throwaway EC2 VM for LSM/KRSI eBPF prototyping (ROADMAP v0.3
# Phase 2 — "Prototype in a throwaway VM you can destroy, not your main
# machine"). Ubuntu 24.04, SSH locked to your current public IP, tagged for
# easy cleanup. Safe to re-run — reuses the instance/key/security-group if
# they already exist.
#
# Prerequisites: aws CLI configured (same account/region as deploy/k8s/eks/).
#
# Usage:
#   ./deploy/ec2/setup-instance.sh
#
# Env overrides: NAME, AWS_REGION, INSTANCE_TYPE, VOLUME_SIZE
set -euo pipefail
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_PAGER=""

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NAME="${NAME:-interlock-lsm-vm}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
# This AWS account is restricted to free-tier-eligible instance types.
# m7i-flex.large (2 vCPU / 8GB) is the most capable option in that set —
# comfortable enough for clang/llvm + kernel headers + go build.
INSTANCE_TYPE="${INSTANCE_TYPE:-m7i-flex.large}"
VOLUME_SIZE="${VOLUME_SIZE:-30}"
KEY_DIR="${ROOT}/deploy/ec2/.keys"
KEY_PATH="${KEY_DIR}/${NAME}.pem"

echo "==> caller:"
aws sts get-caller-identity --region "${AWS_REGION}"

mkdir -p "${KEY_DIR}"

# --- key pair (create once, reuse) ---
if [[ -f "${KEY_PATH}" ]]; then
  echo "==> key pair already local: ${KEY_PATH}"
elif aws ec2 describe-key-pairs --key-names "${NAME}" --region "${AWS_REGION}" >/dev/null 2>&1; then
  echo "ERROR: key pair ${NAME} exists in AWS but the .pem isn't at ${KEY_PATH}."
  echo "Delete it (aws ec2 delete-key-pair --key-name ${NAME} --region ${AWS_REGION}) and re-run, or restore the .pem."
  exit 1
else
  echo "==> creating key pair ${NAME}"
  aws ec2 create-key-pair --key-name "${NAME}" --region "${AWS_REGION}" \
    --query 'KeyMaterial' --output text > "${KEY_PATH}"
  chmod 400 "${KEY_PATH}"
fi

# --- default VPC / subnet ---
VPC_ID="$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --region "${AWS_REGION}" \
  --query 'Vpcs[0].VpcId' --output text)"
SUBNET_ID="$(aws ec2 describe-subnets --filters Name=vpc-id,Values="${VPC_ID}" Name=default-for-az,Values=true \
  --region "${AWS_REGION}" --query 'Subnets[0].SubnetId' --output text)"

# --- security group: SSH from caller IP only ---
MY_IP="$(curl -s -4 https://checkip.amazonaws.com)/32"
SG_ID="$(aws ec2 describe-security-groups --region "${AWS_REGION}" \
  --filters Name=group-name,Values="${NAME}" Name=vpc-id,Values="${VPC_ID}" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo None)"

if [[ "${SG_ID}" == "None" || -z "${SG_ID}" ]]; then
  echo "==> creating security group ${NAME} (SSH from ${MY_IP} only)"
  SG_ID="$(aws ec2 create-security-group --group-name "${NAME}" \
    --description "Throwaway LSM/KRSI prototyping VM - SSH only" \
    --vpc-id "${VPC_ID}" --region "${AWS_REGION}" --query 'GroupId' --output text)"
  aws ec2 create-tags --resources "${SG_ID}" --region "${AWS_REGION}" \
    --tags Key=project,Value=interlock Key=purpose,Value=lsm-krsi-prototype
  aws ec2 authorize-security-group-ingress --group-id "${SG_ID}" --region "${AWS_REGION}" \
    --protocol tcp --port 22 --cidr "${MY_IP}" >/dev/null
else
  echo "==> reusing security group ${SG_ID}; refreshing SSH allow-list to ${MY_IP}"
  aws ec2 revoke-security-group-ingress --group-id "${SG_ID}" --region "${AWS_REGION}" \
    --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
  aws ec2 authorize-security-group-ingress --group-id "${SG_ID}" --region "${AWS_REGION}" \
    --protocol tcp --port 22 --cidr "${MY_IP}" >/dev/null 2>&1 || true
fi

# --- reuse a running instance if one already exists ---
EXISTING="$(aws ec2 describe-instances --region "${AWS_REGION}" \
  --filters "Name=tag:Name,Values=${NAME}" "Name=instance-state-name,Values=pending,running" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null || echo None)"

if [[ "${EXISTING}" != "None" && -n "${EXISTING}" ]]; then
  echo "==> instance already up: ${EXISTING}"
  INSTANCE_ID="${EXISTING}"
else
  AMI_ID="$(aws ssm get-parameter --region "${AWS_REGION}" \
    --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
    --query 'Parameter.Value' --output text)"
  echo "==> launching ${INSTANCE_TYPE} (${AMI_ID}, Ubuntu 24.04) in ${SUBNET_ID}"
  INSTANCE_ID="$(aws ec2 run-instances --region "${AWS_REGION}" \
    --image-id "${AMI_ID}" --instance-type "${INSTANCE_TYPE}" \
    --key-name "${NAME}" --security-group-ids "${SG_ID}" --subnet-id "${SUBNET_ID}" \
    --associate-public-ip-address \
    --block-device-mappings "[{\"DeviceName\":\"/dev/sda1\",\"Ebs\":{\"VolumeSize\":${VOLUME_SIZE},\"VolumeType\":\"gp3\",\"DeleteOnTermination\":true}}]" \
    --user-data "file://${ROOT}/deploy/ec2/bootstrap.sh" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${NAME}},{Key=project,Value=interlock},{Key=purpose,Value=lsm-krsi-prototype},{Key=throwaway,Value=true}]" \
    --query 'Instances[0].InstanceId' --output text)"
  echo "==> waiting for ${INSTANCE_ID} to enter running state"
  aws ec2 wait instance-running --region "${AWS_REGION}" --instance-ids "${INSTANCE_ID}"
fi

PUBLIC_IP="$(aws ec2 describe-instances --region "${AWS_REGION}" --instance-ids "${INSTANCE_ID}" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"

echo "==> waiting for SSH on ${PUBLIC_IP}"
for _ in $(seq 1 30); do
  if ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 \
      -i "${KEY_PATH}" "ubuntu@${PUBLIC_IP}" true 2>/dev/null; then
    break
  fi
  sleep 10
done

echo
echo "instance:   ${INSTANCE_ID}"
echo "public ip:  ${PUBLIC_IP}"
echo "ssh:        ssh -i ${KEY_PATH} ubuntu@${PUBLIC_IP}"
echo "  or:       ./deploy/ec2/ssh.sh"
echo
echo "Bootstrap (build deps + BPF-LSM check) runs in the background via"
echo "cloud-init. Tail it, and reboot if it flags REBOOT_REQUIRED:"
echo "  ./deploy/ec2/ssh.sh 'tail -f /var/log/interlock-bootstrap.log'"
echo "  ./deploy/ec2/ssh.sh '[[ -f REBOOT_REQUIRED ]] && sudo reboot || true'"
echo
echo "Sync the repo over:  ./deploy/ec2/sync.sh"
echo "Destroy when done:   ./deploy/ec2/destroy-instance.sh"
