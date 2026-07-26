# Throwaway LSM/KRSI prototyping VM

For [`ROADMAP.md`](../../docs/ROADMAP.md) v0.3 Phase 2 — Kernel-Level Blocking
(LSM/KRSI). The roadmap calls this **the highest-risk work in the project**: a
bug in an LSM BPF hook is more constrained than a tracepoint, more
kernel-version-sensitive, and can break the host's networking or deadlock
processes. Its explicit guidance is to **prototype in a throwaway VM you can
destroy, not your main machine** — this is that VM.

It is a disposable, single-purpose Ubuntu 24.04 EC2 instance:

- SSH locked to your current public IP only (`/32`), refreshed on every
  `setup-instance.sh` run.
- Tagged `project=interlock`, `purpose=lsm-krsi-prototype`, `throwaway=true`.
- Nothing about it is meant to be long-lived. If it wedges or panics, destroy
  it and start a fresh one — that is the intended failure mode, not a bug in
  the tooling.

Uses the same AWS account/credentials as [`deploy/k8s/eks/`](../k8s/eks/).

## Quick start

```bash
export PATH="$HOME/.local/bin:$PATH"
export AWS_REGION=us-east-1   # optional, this is already the default

make lsm-vm-up      # create + boot (Ubuntu 24.04, m7i-flex.large, 30GB gp3)
make lsm-vm-sync     # rsync the working tree over (repeat after local edits)
make lsm-vm-ssh      # interactive shell on the VM

# when you're done for the day, or the VM wedges:
make lsm-vm-down
```

`setup-instance.sh` is idempotent — re-running it reuses the existing
instance/key/security-group instead of creating duplicates, and refreshes the
SSH allow-list to wherever you're currently connecting from.

## What's on it

`bootstrap.sh` runs once via cloud-init at first boot (background — tail it
with `./deploy/ec2/ssh.sh 'tail -f /var/log/interlock-bootstrap.log'`):

- Build toolchain: `clang`, `llvm`, `lld`, `libelf-dev`, `libbpf-dev`,
  matching `linux-headers-*` / `linux-tools-*` (falls back to generic
  packages if the exact kernel-flavor package isn't published), `bpftool`.
- Go toolchain, for building/testing the Interlock sensor itself.
- Reports `CONFIG_BPF_LSM` and the active LSM list
  (`/sys/kernel/security/lsm`). If `bpf` isn't active, it appends it to
  `GRUB_CMDLINE_LINUX` and drops a `~/REBOOT_REQUIRED` marker — check for
  it and reboot once before loading an LSM program:

  ```bash
  ./deploy/ec2/ssh.sh '[[ -f REBOOT_REQUIRED ]] && sudo reboot || true'
  ```

## Workflow

1. Edit LSM/eBPF + Go glue locally, same as any other change.
2. `make lsm-vm-sync` to push the working tree (including uncommitted
   changes) to `~/interlock` on the VM.
3. `make lsm-vm-ssh`, then build/load/test on the real kernel there —
   this can't be exercised locally since it needs an actual `bpf` LSM hook.
4. Iterate 2–3. Once a change is validated, commit it locally as usual.
5. `make lsm-vm-down` when done — don't leave it running.

Useful root+BPF-LSM tests on the VM:

```bash
cd ~/interlock
sudo go test ./internal/ebpf/ -count=1 -run 'TestLSM_|TestSensor_FailClosed|TestEBPF_RingbufSaturation|TestLSM_DenySurvivesConnectFlood' -v
```

These cover quarantine deny, fail-closed mass quarantine, dual-ring saturation
(connect flood vs write flood), and `lsm_deny` surviving a connect flood on the
critical ring.

## Cost

This AWS account is restricted to free-tier-eligible instance types (a
`RunInstances` call with a non-eligible type is rejected outright), so
`setup-instance.sh` defaults to `m7i-flex.large` (2 vCPU / 8GB) — the most
capable type in that set. The 30GB gp3 root volume is destroyed with the
instance (`DeleteOnTermination: true`). There is no always-on cost as long as
you run `lsm-vm-down` between sessions.

## Safety notes

- This VM is intentionally disposable — do not put anything on it you'd miss.
- The security group only opens port 22, restricted to your current IP.
  It does not expose the instance to the wider internet beyond that.
- `.keys/*.pem` (created by `setup-instance.sh`) never leaves this machine
  and is gitignored — do not commit it.
- A kernel panic, deadlock, or broken networking **on this VM** is an
  expected possible outcome of this work, not an incident — that's the
  entire reason it isn't your main machine. `make lsm-vm-down` and re-run
  `make lsm-vm-up` for a clean instance.
