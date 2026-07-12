# Interlock sensor DaemonSet

Sensor-only node agent: eBPF visibility + containment for pods labeled
`interlock.io/monitor: "true"`. **Does not run the MCP proxy.**

## Quick start

```bash
# from repo root
make image
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/daemonset.yaml
kubectl apply -f deploy/k8s/service-metrics.yaml

# kind end-to-end (build, load, apply, exfil demo pod, assert EXFIL evidence)
make demo-k8s
```

## Label workloads

```yaml
metadata:
  labels:
    interlock.io/monitor: "true"
```

## Demo: sensitive read → EXFIL

`make demo-k8s` runs a labeled pod that:

1. Opens `/secrets/demo-token` (ConfigMap) — sensor seeds taint (no kill on openat).
2. `connect()` + `write()` of that secret to a non-allowlisted host — **EXFIL 0.95** with redacted `payload_excerpt`.

Taint seeding reads the file via `/proc/<pid>/root`; requires the sensor pod to have `hostPID: true` and read access to the node's procfs. Without that, openat still lights legs but no taint is registered and the write stays SUSPICIOUS.

**EKS note:** on Amazon Linux 2023 / containerd, the capabilities DaemonSet sees cross-pod `connect`/`write` but cannot seed via `/proc/*/root` (`permission denied`). Prefer the **taint bridge** (proxy → `/var/run/interlock/taint.sock`) for EXFIL under capabilities; privileged DaemonSet remains for openat-seed demos. Details: [PRIVILEGE.md](PRIVILEGE.md). Example: [`proxy-taint-bridge-example.yaml`](proxy-taint-bridge-example.yaml).

Sensor-only lights `untrusted_content_present` with detail: *monitored agent pod accessed sensitive path; no MCP untrusted-content plane*.

## Taint bridge (proxy → sensor)

Node-local Unix socket (default `/var/run/interlock/taint.sock`):

1. Sensor DaemonSet: `taint_bridge.enabled: true` (ConfigMap) + hostPath mount.
2. Agent proxy: same `taint_bridge` block + `POD_UID` Downward API + same hostPath.
3. On sensitive_source results, proxy forwards `TaintedValue` (value+variants in memory on the wire; evidence still hash+preview only).
4. Sensor `RegisterRemoteTaint` → session `k8s:<podUID>` → egress `CheckOverlapPayload` → EXFIL.

## Privilege

See [PRIVILEGE.md](PRIVILEGE.md) for `hostPID`, capabilities, and the
`privileged: true` fallback.

| Manifest | Use |
|---|---|
| `daemonset.yaml` | kind / `make demo-k8s`; privileged openat-seed EXFIL |
| `daemonset-capabilities.yaml` | Managed try-first + **taint bridge** for EXFIL without privileged root |
| `proxy-taint-bridge-example.yaml` | Agent pod mount + `POD_UID` wiring |

GKE helper: [`gke/setup-cluster.sh`](gke/setup-cluster.sh) (requires `gcloud auth login` + `PROJECT_ID`).

**EKS (validated 2026-07-12):** Amazon Linux 2023, kernel `6.1.174-217.345.amzn2023.x86_64`, containerd — capabilities load/observe; privileged full EXFIL. Needs EKS/ECR permissions ([`eks/setup-iam.sh`](eks/setup-iam.sh)).

```bash
export PATH="$HOME/.local/bin:$PATH"
export AWS_REGION=us-east-1

# 1) As account admin, grant perms:
./deploy/k8s/eks/setup-iam.sh

# 2) As the interlock user:
./deploy/k8s/eks/setup-cluster.sh    # ~15–25 min, AL2023 managed nodes
./deploy/k8s/eks/push-image.sh       # or push-image-kaniko.sh without local Docker
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f /tmp/interlock-daemonset-capabilities.yaml
kubectl apply -f deploy/k8s/service-metrics.yaml
./deploy/k8s/eks/validate.sh

# Full EXFIL demo (privileged + fresh pod):
kubectl apply -f /tmp/interlock-daemonset.yaml
kubectl delete pod interlock-exfil-demo -n default --ignore-not-found --wait=true
# apply deploy/k8s/demo/exfil-pod.yaml with image rewritten to the ECR tag from push-image
# tear down when done: ./deploy/k8s/eks/delete-cluster.sh
```


## Config

ConfigMap `interlock-sensor-config` in `interlock-system` (see `rbac.yaml`).
Include sensitive path prefixes (e.g. `/secrets`) for taint seeding.
Tune `egress_allowlist` for your cluster DNS/API before production use.

## Metrics and health (Phase 3 Slice 1)

The sensor listens on `observability.listen` (default in DaemonSet: `0.0.0.0:9090`):

| Path | Purpose |
|------|---------|
| `/healthz` | Liveness/readiness — `200` when the process is up |
| `/metrics` | Prometheus scrape |

Headless Service: `interlock-sensor-metrics.interlock-system:9090`.

Example scrape config:

```yaml
- job_name: interlock-sensor
  kubernetes_sd_configs:
    - role: endpoints
      namespaces:
        names: [interlock-system]
  relabel_configs:
    - source_labels: [__meta_kubernetes_service_name]
      action: keep
      regex: interlock-sensor-metrics
```

No auth on the metrics port — restrict with NetworkPolicy in production. No ServiceMonitor CRD is shipped; wire your own if you use prometheus-operator.

Key series: `interlock_up`, `interlock_detections_total{verdict,variant,action}`,
`interlock_evidence_dropped_total`, `interlock_events_dropped_total`,
`interlock_ebpf_ringbuf_drops_total`, `interlock_watched_pids`, `interlock_watched_cgroups`,
`interlock_alert_deliveries_total{kind,result}`.

Bare-metal hosts: see [`../systemd/README.md`](../systemd/README.md) for systemd units and SIGHUP config reload.

## Alerting and SIEM (Phase 3 Slices 2–3)

Disabled by default. Put secrets in a Kubernetes Secret and merge into the ConfigMap or mount an overlay — **do not commit webhook URLs or routing keys**.

```yaml
# example — apply via Secret-backed config, not git
alerting:
  webhook:
    url: https://hooks.slack.com/services/T.../B.../...
    format: slack          # generic | slack | pagerduty
    min_verdict: SUSPICIOUS
    # format: pagerduty
    # url: https://events.pagerduty.com/v2/enqueue
    # pagerduty_routing_key: <from Secret>
siem:
  format: ocsf
  path: /var/log/interlock/ocsf.jsonl
  # url: https://siem.example/ingest
  min_verdict: SUSPICIOUS
```

Trips fan out after evidence persist: Slack Incoming Webhook / PagerDuty Events API v2 / generic JSON, plus OCSF Detection Finding (class_uid 2004) to file and/or HTTP. CEF is not shipped yet.
