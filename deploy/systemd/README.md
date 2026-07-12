# Interlock systemd units

Bare-metal / VM install. **Kubernetes remains the primary deploy path** — see [`../k8s/README.md`](../k8s/README.md).

## Install

```bash
# build and install binary
go build -o /usr/local/bin/interlock ./cmd/interlock

sudo mkdir -p /etc/interlock
sudo cp interlock-sensor.yaml /etc/interlock/interlock.yaml   # or your config
# optional: sudo cp interlock.env.example /etc/interlock/interlock.env

sudo cp deploy/systemd/interlock-sensor.service /etc/systemd/system/
# or: interlock-proxy.service for proxy mode
sudo systemctl daemon-reload
sudo systemctl enable --now interlock-sensor
```

Sensor mode requires root (or equivalent BPF capabilities) and a BTF-enabled kernel — same privilege story as the DaemonSet ([`../k8s/PRIVILEGE.md`](../k8s/PRIVILEGE.md)).

## Hot-reload (SIGHUP)

After editing `/etc/interlock/interlock.yaml`:

```bash
sudo systemctl kill -s HUP interlock-sensor
# or: sudo kill -HUP $(pidof interlock)
```

**Reloadable live:** `egress_allowlist`, `sensitive_paths`, `alerting.webhook`, `siem`.

**Requires restart:** `enforcement`, `transport`, `servers`, `observability.listen`, `evidence` backend/path.

Invalid YAML or validation errors are logged and the previous config is kept.

## Proxy unit

`interlock-proxy.service` runs default proxy mode. Add `--ebpf` via drop-in or edit `ExecStart` if you want Variant B on the host.
