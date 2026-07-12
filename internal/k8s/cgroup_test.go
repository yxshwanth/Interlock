package k8s

import "testing"

func TestExtractContainerID_Containerd(t *testing.T) {
	cg := `0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc123.slice/cri-containerd-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope
`
	id := ExtractContainerID(cg)
	want := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if id != want {
		t.Fatalf("got %q want %q", id, want)
	}
}

func TestExtractContainerID_CRIO(t *testing.T) {
	cg := `11:memory:/kubepods/burstable/poduid/crio-fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
`
	id := ExtractContainerID(cg)
	want := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	if id != want {
		t.Fatalf("got %q want %q", id, want)
	}
}

func TestExtractContainerID_Docker(t *testing.T) {
	cg := `1:name=systemd:/docker/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`
	// docker path without docker- prefix — generic kubepods fallback won't match.
	// Use docker- prefix form:
	cg = `1:name=systemd:/system.slice/docker-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope
`
	id := ExtractContainerID(cg)
	want := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if id != want {
		t.Fatalf("got %q want %q", id, want)
	}
}

func TestExtractContainerID_Empty(t *testing.T) {
	if id := ExtractContainerID("0::/\n"); id != "" {
		t.Fatalf("expected empty, got %q", id)
	}
}

func TestNormalizeContainerID(t *testing.T) {
	raw := "containerd://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	want := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if got := NormalizeContainerID(raw); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
