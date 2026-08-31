# Interlock sensor image (amd64). Precompiled BPF objects are committed in-tree.
# Build: make image
# Release-aligned flags: CGO_ENABLED=0, -trimpath, version ldflags (see docs/reproducible_builds.md).
ARG VERSION=dev
FROM golang:1.25 AS build
ARG VERSION
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
	-o /out/interlock ./cmd/interlock
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	go build -trimpath -ldflags="-s -w" \
	-o /out/k8s-exfil-demo ./cmd/k8s-exfil-demo

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd -r -u 65532 -g nogroup interlock 2>/dev/null || useradd -r -u 65532 interlock
COPY --from=build /out/interlock /interlock
COPY --from=build /out/k8s-exfil-demo /k8s-exfil-demo
# Default non-root for proxy mode. Sensor/eBPF DaemonSets must set securityContext.runAsUser: 0.
USER 65532
ENTRYPOINT ["/interlock"]
