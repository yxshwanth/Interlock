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

**EKS finding (2026-07-12):** capabilities are enough for probe load and cross-pod
syscall visibility (`connect` / `write` payload). Reading another container’s
root via `/proc/<pid>/root` for taint seed returned `permission denied` — without
seed contents, egress stays SUSPICIOUS (not EXFIL).

**Production fix (ROADMAP §4 — shipped):** enable the **sensor↔proxy taint bridge**.
An unprivileged MCP proxy in the agent pod forwards hashed/masked `TaintedValue`s
(with in-memory `Value`/`Variants` over the node-local Unix socket) to the sensor.
Mount hostPath `/var/run/interlock` on both DaemonSet and proxy; set `POD_UID` via
the Downward API. See [`proxy-taint-bridge-example.yaml`](proxy-taint-bridge-example.yaml).
With the bridge, capabilities DaemonSet can reach EXFIL without privileged root reads.
`privileged: true` remains available for openat `/proc` seed demos without a proxy.

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

## RBAC

The sensor ServiceAccount can only `get/list/watch` pods. Narrow further with
`WATCH_NAMESPACE` if you only monitor one namespace.
