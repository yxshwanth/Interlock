package k8s

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPodAttribution_RegisterLookup(t *testing.T) {
	r := NewPodAttribution()
	pod := PodInfo{UID: "uid-1", Namespace: "ns", Name: "agent", NodeName: "node-a"}
	key := ProcessKey{PID: 4242, StartTimeNs: 100}
	r.Register(key, pod, "abc")

	a, ok := r.Lookup(4242)
	if !ok {
		t.Fatal("expected lookup hit")
	}
	if a.SessionID != "k8s:uid-1" {
		t.Fatalf("session = %q", a.SessionID)
	}
	if a.Pod.Namespace != "ns" || a.Pod.PodName != "agent" {
		t.Fatalf("pod = %+v", a.Pod)
	}
}

func TestPodAttribution_SyncPodAddRemove(t *testing.T) {
	r := NewPodAttribution()
	pod := PodInfo{UID: "uid-2", Namespace: "default", Name: "exfil", NodeName: "n1"}

	added, removed := r.SyncPod(pod, "cid", []ProcessKey{
		{PID: 1, StartTimeNs: 10},
		{PID: 2, StartTimeNs: 20},
	})
	if len(added) != 2 || len(removed) != 0 {
		t.Fatalf("added=%v removed=%v", added, removed)
	}

	added, removed = r.SyncPod(pod, "cid", []ProcessKey{
		{PID: 2, StartTimeNs: 20},
		{PID: 3, StartTimeNs: 30},
	})
	if len(added) != 1 || added[0] != 3 {
		t.Fatalf("added=%v", added)
	}
	if len(removed) != 1 || removed[0] != 1 {
		t.Fatalf("removed=%v", removed)
	}

	if _, ok := r.Lookup(1); ok {
		t.Fatal("pid 1 should be gone")
	}
	if _, ok := r.Lookup(2); !ok {
		t.Fatal("pid 2 should remain")
	}
}

func TestPodAttribution_UnregisterPod(t *testing.T) {
	r := NewPodAttribution()
	pod := PodInfo{UID: "uid-3", Namespace: "ns", Name: "p", NodeName: "n"}
	r.SyncPod(pod, "c", []ProcessKey{{PID: 9, StartTimeNs: 1}})
	pids := r.UnregisterPod("uid-3")
	if len(pids) != 1 || pids[0] != 9 {
		t.Fatalf("pids=%v", pids)
	}
	if _, ok := r.Lookup(9); ok {
		t.Fatal("expected miss after unregister")
	}
}

func TestProcScanner_PIDsForContainers(t *testing.T) {
	root := t.TempDir()
	cid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	pidDir := filepath.Join(root, "12345")
	if err := os.Mkdir(pidDir, 0755); err != nil {
		t.Fatal(err)
	}
	cg := "0::/kubepods.slice/cri-containerd-" + cid + ".scope\n"
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cg), 0644); err != nil {
		t.Fatal(err)
	}
	// Minimal /proc/pid/stat: pid (comm) state ... starttime at field 22 (index 19 after comm)
	// Format: 12345 (fake) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 999 0 0 ...
	stat := "12345 (fake) S 1 1 1 0 -1 4194304 0 0 0 0 0 0 0 0 0 0 0 0 0 0 999 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
	if err := os.WriteFile(filepath.Join(pidDir, "stat"), []byte(stat), 0644); err != nil {
		t.Fatal(err)
	}

	s := &ProcScanner{ProcRoot: root}
	keys, err := s.PIDsForContainers(map[string]struct{}{cid: {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].PID != 12345 {
		t.Fatalf("keys=%v", keys)
	}
}
