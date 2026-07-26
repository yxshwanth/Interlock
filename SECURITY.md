# Security Policy

Interlock runs privileged, loads eBPF kernel probes, and manages child processes. A vulnerability in Interlock is a serious vulnerability in the host. Treat reports accordingly.

## Reporting a vulnerability

**Do not open a public GitHub issue for security bugs.**

Report privately via [GitHub private security advisories](https://github.com/yxshwanth/Interlock/security/advisories/new).

Include:

- Affected version (tag or commit)
- Platform (distro, kernel version, `ls /sys/kernel/btf/vmlinux` result)
- Steps to reproduce
- Impact assessment (privilege escalation, data leak, denial of service, etc.)

## Scope

**In scope:**

- MCP proxy (`internal/proxy/`) — framing, routing, enforcement gate, child process lifecycle
- Correlation engine (`internal/engine/`) — trifecta state machine, taint/overlap, evidence emission
- eBPF sensor (`internal/ebpf/`, `internal/ebpf/bpf/connect.c`) — probe logic, PID/cgroup filter, dual ring buffers, LSM quarantine hook
- Fail-closed breaker (`internal/failclosed/`) — ringbuf/sink/panic trips → mass quarantine / proxy deny
- Kubernetes attribution (`internal/k8s/`) — cgroup→container→pod resolution, RBAC surface (`deploy/k8s/rbac.yaml`)
- Operability (`internal/observability/`, `internal/alerting/`, `internal/siem/`, `internal/reload/`) — metrics/health exposure, outbound webhook/SIEM delivery, `SIGHUP` config reload
- Demo and CLI entrypoints (`cmd/interlock/`, `cmd/demo/`, `cmd/k8s-exfil-demo/`, `cmd/verify-evidence/`)
- Deployment manifests (`deploy/k8s/`, `deploy/systemd/`, `deploy/ec2/`) — privilege/capability requests, RBAC scope, LSM throwaway VM
- Privilege model — what runs as root, what capabilities are held, fail-open default vs opt-in `fail_closed`
- Secret handling — redaction, evidence sink, hash-chain integrity, log output

**Out of scope (for now):**

- Toy MCP servers under `servers/` (demo fixtures only)
- Denial-of-service via legitimate high-volume agent traffic (unless it bypasses detection or crashes the TCB)
- Attacks requiring physical access or kernel compromise outside Interlock's trust model

## Response expectations

This is a solo-maintainer v0.x project. Best-effort timelines:

| Stage | Target |
|---|---|
| Acknowledgment | 72 hours |
| Initial assessment | 7 days |
| Fix or mitigation plan | 30 days (severity-dependent) |

Critical issues (remote code execution, privilege escalation via Interlock) get priority. I will coordinate disclosure timing with reporters.

## What Interlock defends against (and does not)

Interlock detects **programmatic** runtime exfiltration (lethal trifecta + value overlap across MCP and eBPF). See **[`docs/detection_boundary.md`](docs/detection_boundary.md)** for what it catches, what it does not (including **semantic / paraphrased exfil**), and why.

As of this tree (v0.3.0 + Unreleased robustness):

- Published detection / FP corpus: [`docs/fp_corpus.md`](docs/fp_corpus.md)
- Signed tags (since `v0.2.0`); reproducible build path + release workflow — [`docs/reproducible_builds.md`](docs/reproducible_builds.md)
- Threat model *of Interlock itself* (TCB / tamper-resistance): [`docs/threat_model.md`](docs/threat_model.md)
- Kernel-level quarantine — opt-in `ebpf.lsm_enforce` (repeat-connect `prevented` after EXFIL); first EXFIL packet remains `contained_by_kill`
- Opt-in `fail_closed.enabled`; dual ringbufs; evidence hash chain (`make verify-evidence`)
- No protection against a compromised kernel or a malicious operator with root on the host

## eBPF probe transparency

The only kernel code Interlock loads is [`internal/ebpf/bpf/connect.c`](internal/ebpf/bpf/connect.c) (connect / write / sendto / openat probes; dual ringbufs `events` + `critical_events`; `drop_count` / `critical_drop_count`; opt-in LSM `socket_connect`). Precompiled objects are committed and embedded — read the C source before trusting it. Regen: [`docs/reproducible_builds.md`](docs/reproducible_builds.md).

## Signed releases

Release tags are **signed** starting with **v0.2.0** (`git tag -s`, SSH key). Verify with the repo's [`allowed_signers`](allowed_signers) file:

```bash
git fetch --tags
git -c gpg.ssh.allowedSignersFile=allowed_signers tag -v v0.2.0
```

Success looks like `Good "git" signature for yash@L5iPro.lan with ED25519 key SHA256:j0vZxZexFyPA8Hj8ys2NbdMEtyqmZ+kT60eWRdfjlq8`. If you see `gpg.ssh.allowedSignersFile needs to be configured`, you ran `git tag -v` without pointing Git at `allowed_signers` — the tag is signed; verification just needs the trust file.

Optional one-time setup (any clone of this repo):

```bash
git config gpg.ssh.allowedSignersFile "$(git rev-parse --show-toplevel)/allowed_signers"
git tag -v v0.2.0
```

**Signing key (SSH):** `SHA256:j0vZxZexFyPA8Hj8ys2NbdMEtyqmZ+kT60eWRdfjlq8` — `ssh-ed25519`, GitHub identity `yxshwanth@github`

**Tagger identities:** `v0.2.0` was signed as `Yash <yash@L5iPro.lan>` — git's auto-generated fallback when `user.email` is unset (`<username>@<hostname>.<domain>`), not a reachable address. Future tags use `85288090+yxshwanth@users.noreply.github.com`. Both map to the same key in [`allowed_signers`](allowed_signers).

**Maintainer setup (future tags only — do not retag v0.2.0):**

```bash
git config user.name "Yash"
git config user.email "85288090+yxshwanth@users.noreply.github.com"
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519.pub
git tag -s v0.2.1 -m "..."
git push origin v0.2.1   # triggers .github/workflows/release.yml
```

### Release binaries and checksums

Pushing a signed `v*` tag runs the release workflow, which builds with
`make release` (`CGO_ENABLED=0`, `-trimpath`) and uploads:

- `interlock_linux_amd64`
- `k8s-exfil-demo_linux_amd64`
- `SHA256SUMS`
- `SHA256SUMS.bpf` (hashes of committed eBPF embed files)

Verify:

```bash
# after downloading assets from the GitHub Release
sha256sum -c SHA256SUMS
./interlock_linux_amd64 --version
```

Full build environment and BPF regen: [`docs/reproducible_builds.md`](docs/reproducible_builds.md).
TCB threats (blind sensor, poison bridge, fail-open, etc.): [`docs/threat_model.md`](docs/threat_model.md).
