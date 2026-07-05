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
- eBPF sensor (`internal/ebpf/`, `internal/ebpf/bpf/connect.c`) — probe logic, PID filter, ring buffer handling
- Demo and CLI entrypoints (`cmd/interlock/`, `cmd/demo/`)
- Privilege model — what runs as root, what capabilities are held, fail-open behavior
- Secret handling — redaction, evidence sink, log output

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

Interlock detects runtime exfiltration patterns (Simon Willison's lethal trifecta) across MCP tool chains and kernel-level side channels. See the README **Honest limitations** section and [CHANGELOG.md](CHANGELOG.md) for v0.1 boundaries.

Interlock v0.1 does **not** yet provide:

- A formal threat model document (planned for v0.3)
- Signed releases or reproducible builds (planned)
- Kernel-level blocking (LSM/KRSI) — Variant B is detect-and-contain, not prevent
- Protection against a compromised kernel or a malicious operator with root on the host

## eBPF probe transparency

The only kernel code Interlock loads in v0.1 is [`internal/ebpf/bpf/connect.c`](internal/ebpf/bpf/connect.c) (~75 lines). It attaches to `tracepoint/syscalls/sys_enter_connect`, filters by PID hash map, and emits destination IP/port to a ring buffer. Read the source before trusting it.

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
```

Release artifacts and reproducible builds are not yet published; binary provenance is on the v0.3 roadmap.
