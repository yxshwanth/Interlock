#!/usr/bin/env bash
# cloud-init user-data for the throwaway LSM/KRSI prototyping VM (ROADMAP v0.3
# Phase 2). Runs once as root at first boot. Installs eBPF/LSM build deps,
# reports whether the "bpf" LSM is active, and enables it via GRUB if not.
#
# Logs to /var/log/interlock-bootstrap.log — tail with:
#   ./deploy/ec2/ssh.sh 'tail -f /var/log/interlock-bootstrap.log'
set -euo pipefail
exec > >(tee -a /var/log/interlock-bootstrap.log) 2>&1
echo "==> $(date -u) bootstrap start"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y

# Core toolchain — always available on Ubuntu 24.04.
apt-get install -y --no-install-recommends \
  build-essential clang llvm lld libelf-dev zlib1g-dev \
  git make pkg-config m4 jq curl rsync

# Kernel-flavor-specific packages vary (e.g. "-aws" kernels); fall back
# gracefully instead of aborting the whole bootstrap on one missing package.
apt-get install -y --no-install-recommends libbpf-dev || true
apt-get install -y --no-install-recommends "linux-headers-$(uname -r)" \
  || apt-get install -y --no-install-recommends linux-headers-generic || true
apt-get install -y --no-install-recommends "linux-tools-$(uname -r)" linux-tools-common \
  || apt-get install -y --no-install-recommends linux-tools-generic || true
# bpftool is a virtual package resolved by linux-tools-<version> above (via
# update-alternatives to /usr/sbin/bpftool) — no separate package to install.

# Go toolchain (for building/testing the Interlock sensor itself).
GOVER="1.23.4"
if ! command -v go >/dev/null 2>&1; then
  curl -fsSL "https://go.dev/dl/go${GOVER}.linux-amd64.tar.gz" -o /tmp/go.tgz
  tar -C /usr/local -xzf /tmp/go.tgz
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
  rm -f /tmp/go.tgz
fi

echo "==> kernel: $(uname -r)"
echo "==> CONFIG_BPF_LSM:"
zgrep CONFIG_BPF_LSM "/boot/config-$(uname -r)" 2>/dev/null || echo "  not found in /boot/config"

echo "==> active LSMs:"
cat /sys/kernel/security/lsm 2>/dev/null || echo "  /sys/kernel/security/lsm unavailable"

if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
  echo "==> 'bpf' not active — appending to GRUB_CMDLINE_LINUX and marking reboot-required"
  if ! grep -q 'lsm=' /etc/default/grub; then
    sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 lsm=landlock,lockdown,yama,integrity,apparmor,bpf"/' /etc/default/grub
    update-grub
  fi
  touch /home/ubuntu/REBOOT_REQUIRED
else
  echo "==> bpf LSM already active — no reboot needed"
fi

touch /home/ubuntu/BOOTSTRAP_DONE
chown ubuntu:ubuntu /home/ubuntu/BOOTSTRAP_DONE 2>/dev/null || true
[[ -f /home/ubuntu/REBOOT_REQUIRED ]] && chown ubuntu:ubuntu /home/ubuntu/REBOOT_REQUIRED
echo "==> $(date -u) bootstrap done"
