# Privilege surface for the Interlock sensor DaemonSet

The DaemonSet is **sensor-only**: it loads eBPF probes, watches labeled pods on
the node, emits evidence, and may SIGKILL contained processes. It does **not**
terminate MCP traffic or run the Interlock proxy.

## Required settings

| Setting | Why |
|---|---|
| `hostPID: true` | eBPF `bpf_get_current_pid_tgid` and `/proc` scans use host PIDs |
| hostPath `/sys/kernel/btf` | CO-RE / BTF for loading committed BPF objects |
| hostPath `/sys/fs/bpf`, `/sys/kernel/tracing` | map pin / tracepoint attach |
| Elevated privileges | load/attach programs and observe other pods' syscalls |

## Default vs hardened

| Manifest | Posture | When to use |
|---|---|---|
| [`daemonset.yaml`](daemonset.yaml) | `privileged: true` | kind / `make demo-k8s`; **EKS full EXFIL** (taint seed via `/proc/<pid>/root` → trip → kill) |
| [`daemonset-capabilities.yaml`](daemonset-capabilities.yaml) | drop ALL; add `BPF`, `PERFMON`, `SYS_ADMIN`, `KILL` | Managed clusters try-first — load, health, cross-pod `connect`/`write` capture |

Capabilities-first `securityContext`:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    add: ["BPF", "PERFMON", "SYS_ADMIN", "KILL"]
    drop: ["ALL"]
```

## Optional: kernel-level connect() quarantine (`ebpf.lsm_enforce`)

v0.3 Phase 2 Slice 1 adds an **opt-in** (default `false`) `BPF_PROG_TYPE_LSM`
hook on `security_socket_connect`: once the existing write/`sendto`
payload-overlap path confirms **EXFIL** for a PID/cgroup, any further
`connect()` from it is denied in-kernel with `-EPERM`. It does **not** change
what the required-settings table above needs — no new hostPath, no new RBAC —
but it adds a **kernel prerequisite** that is not guaranteed even on the node
images already validated above:

| Requirement | Check | Notes |
|---|---|---|
| `CONFIG_BPF_LSM=y` | `zgrep CONFIG_BPF_LSM /boot/config-$(uname -r)` (or check the kernel's `/proc/config.gz` if enabled) | Compiled-in kernel support for BPF-based LSMs |
| `"bpf"` active in the LSM stack | `cat /sys/kernel/security/lsm` — must contain `bpf` | **Not on by default** even on a stock Ubuntu 24.04 kernel; confirmed only after a GRUB `lsm=` cmdline edit + reboot on the throwaway EC2 VM used to validate this feature ([`deploy/ec2/`](../../deploy/ec2/)) |

**Day-1 checklist item:** before enabling `ebpf.lsm_enforce` on a fleet,
confirm both of the above on a representative node image — do not assume
parity with the EKS/kind validation already documented in this file, which
predates this feature and did not exercise it.

**Fails soft, like everything else in this doc's posture:** if the prerequisite
isn't met (or the DaemonSet lacks the capability to attach), the sensor logs a
`[SECURITY]` warning and keeps running tracepoint-only — `ebpf.lsm_enforce`
never blocks sensor startup, and the existing kill-on-detect containment is
unaffected either way. Check `sensor.LSMEnforced()` / the `[SECURITY]` log line
to confirm whether the hook actually attached, don't assume the config flag
alone means it's active.

**Honest scope:** this only stops *repeat* connection attempts after an EXFIL
trip (forked children sharing the cgroup, a kill that races, a respawned
process) — it does not move detection earlier or catch the first
EXFIL-carrying packet. See [`docs/detection_boundary.md`](../../docs/detection_boundary.md).

## Optional: fail-closed (`fail_closed.enabled`)

When Interlock's own health degrades (routine or critical ringbuf drop rate,
consecutive evidence sink failures, or engine/sensor panic), opt-in fail-closed
blocks **all currently watched** egress instead of failing open with
`[SECURITY]` warnings.

| Mode | Deny path | Prerequisite |
|---|---|---|
| Sensor (`--mode=sensor`) | Mass-quarantine watched PIDs/cgroups via the same LSM `socket_connect` maps | `ebpf.lsm_enforce: true` **and** a live LSM attach (config validation refuses otherwise) |
| Proxy | Deny `tools/call` before `EvaluateRequest` | None beyond `fail_closed.enabled` |

Named limitations: scope is always all watched workloads (drop counters are
severity-class globals, not per-pod); deny is `connect()`-only via LSM. Dual
ringbufs mean a connect flood no longer blinds EXFIL/`lsm_deny` evidence —
see [`docs/threat_model.md`](../../docs/threat_model.md) T1.

**EKS finding (2026-07-12):** capabilities are enough for probe load and cross-pod
syscall visibility (`connect` / `write` payload). Reading another container’s
root via `/proc/<pid>/root` for taint seed returned `permission denied` — without
seed contents, and without a proxy sidecar forwarding anything over the taint
bridge, egress on this posture reaches **no verdict at all — not even
`SUSPICIOUS`.** `IngestSyscallSensor` never lights `untrusted_content_present`
on its own (no MCP untrusted-content plane inside a privileged, proxy-less pod),
so the soft tripwire is structurally unreachable here regardless of syscall
type — see [`docs/architecture.md`](../../docs/architecture.md) §13's
"Sensor-only DaemonSet" section. (An earlier version of this doc claimed
`SUSPICIOUS` still fired here; it did not, and never had — corrected.)

**Production fix (ROADMAP §4 — shipped):** enable the **sensor↔proxy taint bridge**.
An unprivileged MCP proxy in the agent pod forwards hashed/masked `TaintedValue`s
(with in-memory `Value`/`Variants` over the node-local Unix socket) to the sensor,
**and** — since this is a prerequisite, not an optional enhancement — also
forwards an "untrusted content observed" signal (`RegisterRemoteUntrusted` /
`register_untrusted`) so the sensor session can light `untrusted_content_present`
too. Mount hostPath `/var/run/interlock` on both DaemonSet and proxy; set `POD_UID` via
the Downward API. Sensor config must set `allowed_uids` and/or `allowed_gids`
(SO_PEERCRED); use `socket_gid` + pod `fsGroup`/`supplementalGroups` for non-root
proxies (`0660` + shared GID, dir `0750`). See
[`proxy-taint-bridge-example.yaml`](proxy-taint-bridge-example.yaml).
With the bridge, capabilities DaemonSet can reach **both** `EXFIL` (taint seed,
without privileged root reads) **and** the soft connect-only `SUSPICIOUS` tripwire
(untrusted-content forwarding) — neither is reachable without it on this posture.
`privileged: true` remains available for openat `/proc` seed demos without a proxy,
but a demo without a proxy still cannot reach `SUSPICIOUS` either, for the same
structural reason.

## Validation status

| Environment | Status |
|---|---|
| kind (containerd / Docker Desktop) | **Validated** via `make demo-k8s` (privileged default) |
| EKS (Amazon Linux 2023 / containerd) | **Validated** (2026-07-12) — see line below |
| GKE (containerd) | Scripts in [`gke/`](gke/); not yet live-validated |

Validated on EKS / containerd / kernel 6.1.174-217.345.amzn2023.x86_64 (2026-07-12):

- **Capabilities DaemonSet** (`BPF`/`PERFMON`/`SYS_ADMIN`/`KILL`): eBPF attached; `/healthz` ok; labeled demo → cross-pod `connect` + `write` payload capture; `/proc/*/root` seed → permission denied (no taint → no EXFIL).
- **Privileged DaemonSet**: openat seed registered taint → `SENSOR TRIP` verdict=`EXFIL` → `KILL-ON-DETECT`.

## Managed-cluster validation checklist

Run against a real EKS or GKE node (not kind). Prefer
[`daemonset-capabilities.yaml`](daemonset-capabilities.yaml) first.

1. **Node OS / runtime** — confirm containerd and kernel ≥ 5.10 with BTF
   (`ls /sys/kernel/btf/vmlinux` on the node). EKS script uses **Amazon Linux 2023** managed nodes (not Fargate).
2. **Build & push image** — `deploy/k8s/eks/push-image.sh` (ECR; Docker Desktop or [`push-image-kaniko.sh`](eks/push-image-kaniko.sh)) or GKE Artifact Registry; set `image:` on the DaemonSet.
3. **Apply** — `kubectl apply -f deploy/k8s/rbac.yaml` then
   `daemonset-capabilities.yaml` (or the `/tmp/interlock-…` patched copy from push-image) and
   `service-metrics.yaml`.
4. **Probe load** — sensor logs show programs attached; `/healthz` returns 200;
   no `permission denied` / verifier failures in pod logs. **Met on EKS.**
5. **Cross-pod visibility** — label a demo pod `interlock.io/monitor=true`,
   generate non-allowlisted `connect`+`write`; confirm evidence /
   `connect detected` / payload capture (not only self-PID noise). **Met on EKS (caps).**
6. **Taint seed + EXFIL** — prefer the **taint bridge** (proxy → Unix socket) under
   capabilities. openat `/proc` seed still works with privileged DaemonSet.
   Look for `remote taint:` or `registered N tainted value(s)` then `verdict=EXFIL` + kill.
7. **Metrics** — scrape `:9090/metrics` via
   `interlock-sensor-metrics.interlock-system` (or port-forward; slim image has no curl).
8. **Fallback** — if bridge is unavailable and step 6 fails under capabilities, switch to
   privileged DaemonSet for `/proc` seed; record which step failed. **EKS (pre-bridge):**
   step 6 failed under caps; passed privileged.

**EKS helpers:** [`eks/setup-cluster.sh`](eks/setup-cluster.sh), [`eks/push-image.sh`](eks/push-image.sh), [`eks/push-image-kaniko.sh`](eks/push-image-kaniko.sh), [`eks/validate.sh`](eks/validate.sh), [`eks/delete-cluster.sh`](eks/delete-cluster.sh).

**GKE helpers:** [`gke/setup-cluster.sh`](gke/setup-cluster.sh), [`gke/validate.sh`](gke/validate.sh).

## What we deliberately avoid

- **No MCP proxy in the DaemonSet** — smaller blast radius; integrators keep their own proxy/sidecar.

## Proxy mode: `sandbox.netns` (CLONE_NEWNET)

When Interlock runs as an **MCP proxy** (not this DaemonSet) and
`sandbox.netns: true`, each child MCP server is spawned with `CLONE_NEWNET`:
a fresh network namespace with **no route to the host NIC** and **no DNS
resolver**. Non-loopback `connect()` fails with `ENETUNREACH` /
`EHOSTUNREACH`. This **prevents** Variant B's uncontrolled side-channel by
construction when Interlock controls spawning.

| Requirement | Notes |
|---|---|
| `CAP_SYS_ADMIN` (or root) at spawn | Needed for `CLONE_NEWNET`. Nested user-namespace fallback is **not** implemented in this pass. |
| Linux only | Non-Linux builds reject `sandbox.netns: true` at spawn. |
| Default `false` | Opt-in; SIGHUP cannot flip it for already-running children (restart / new sessions). |

**This DaemonSet does not gain this prevention.** Sensor-only mode watches
workloads Interlock did not spawn — eBPF Variant B (payload overlap + kill /
LSM quarantine) remains the mechanism there. See
[`docs/architecture.md`](../../docs/architecture.md) §2 trust boundaries.

## RBAC

The sensor ServiceAccount can only `get/list/watch` pods. Narrow further with
`WATCH_NAMESPACE` if you only monitor one namespace.
