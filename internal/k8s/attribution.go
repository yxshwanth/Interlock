package k8s

import (
	"sync"
	"syscall"

	"github.com/yxshwanth/Interlock/internal/model"
)

// PodInfo is the Kubernetes identity for a watched pod.
type PodInfo struct {
	UID       string
	Namespace string
	Name      string
	NodeName  string
}

// SessionIDForPod returns the Interlock session id for a pod UID.
func SessionIDForPod(podUID string) string {
	return "k8s:" + podUID
}

// Attribution is the lookup result for a host PID.
type Attribution struct {
	SessionID   string
	Pod         model.PodContext
	ContainerID string
}

// entry is one registered process.
type entry struct {
	Key         ProcessKey
	SessionID   string
	Pod         model.PodContext
	ContainerID string
}

// PodAttribution maps host PIDs / cgroup IDs to pod sessions (PID-reuse safe).
type PodAttribution struct {
	mu       sync.RWMutex
	entries  map[ProcessKey]entry
	byPID    map[int][]ProcessKey
	byPod    map[string][]ProcessKey // pod UID → keys
	byCgroup map[uint64]string       // cgroup id → pod UID
	podInfo  map[string]PodInfo
}

// NewPodAttribution creates an empty attribution registry.
func NewPodAttribution() *PodAttribution {
	return &PodAttribution{
		entries:  make(map[ProcessKey]entry),
		byPID:    make(map[int][]ProcessKey),
		byPod:    make(map[string][]ProcessKey),
		byCgroup: make(map[uint64]string),
		podInfo:  make(map[string]PodInfo),
	}
}

// Register records that a host process belongs to a pod/container.
func (r *PodAttribution) Register(key ProcessKey, pod PodInfo, containerID string) {
	e := entry{
		Key:       key,
		SessionID: SessionIDForPod(pod.UID),
		Pod: model.PodContext{
			Namespace: pod.Namespace,
			PodName:   pod.Name,
			PodUID:    pod.UID,
			NodeName:  pod.NodeName,
		},
		ContainerID: containerID,
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.entries[key]; !exists {
		r.byPID[key.PID] = append(r.byPID[key.PID], key)
		r.byPod[pod.UID] = append(r.byPod[pod.UID], key)
	}
	r.entries[key] = e
}

// UnregisterPod removes all processes for a pod UID. Returns the PIDs removed.
func (r *PodAttribution) UnregisterPod(podUID string) []int {
	r.mu.Lock()
	defer r.mu.Unlock()

	keys := r.byPod[podUID]
	delete(r.byPod, podUID)
	var pids []int
	for _, key := range keys {
		delete(r.entries, key)
		filterPIDKeysLocked(r.byPID, key)
		pids = appendUnique(pids, key.PID)
	}
	return pids
}

// SyncPod replaces the registered set for a pod with keys. Returns PIDs newly
// added and PIDs that were removed.
func (r *PodAttribution) SyncPod(pod PodInfo, containerID string, keys []ProcessKey) (added, removed []int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	want := make(map[ProcessKey]struct{}, len(keys))
	for _, k := range keys {
		want[k] = struct{}{}
	}

	oldKeys := r.byPod[pod.UID]
	for _, key := range oldKeys {
		if _, ok := want[key]; ok {
			continue
		}
		delete(r.entries, key)
		filterPIDKeysLocked(r.byPID, key)
		removed = appendUnique(removed, key.PID)
	}

	newByPod := make([]ProcessKey, 0, len(keys))
	for _, key := range keys {
		e := entry{
			Key:       key,
			SessionID: SessionIDForPod(pod.UID),
			Pod: model.PodContext{
				Namespace: pod.Namespace,
				PodName:   pod.Name,
				PodUID:    pod.UID,
				NodeName:  pod.NodeName,
			},
			ContainerID: containerID,
		}
		if _, exists := r.entries[key]; !exists {
			r.byPID[key.PID] = append(r.byPID[key.PID], key)
			added = appendUnique(added, key.PID)
		}
		r.entries[key] = e
		newByPod = append(newByPod, key)
	}
	if len(newByPod) == 0 {
		delete(r.byPod, pod.UID)
	} else {
		r.byPod[pod.UID] = newByPod
	}
	return added, removed
}

func filterPIDKeysLocked(byPID map[int][]ProcessKey, key ProcessKey) {
	keys := byPID[key.PID]
	filtered := keys[:0]
	for _, k := range keys {
		if k != key {
			filtered = append(filtered, k)
		}
	}
	if len(filtered) == 0 {
		delete(byPID, key.PID)
	} else {
		byPID[key.PID] = filtered
	}
}

func appendUnique(pids []int, pid int) []int {
	for _, p := range pids {
		if p == pid {
			return pids
		}
	}
	return append(pids, pid)
}

// LookupByCgroup resolves attribution from a BPF cgroup id.
func (r *PodAttribution) LookupByCgroup(cgroupID uint64) (Attribution, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	uid, ok := r.byCgroup[cgroupID]
	if !ok {
		return Attribution{}, false
	}
	info, ok := r.podInfo[uid]
	if !ok {
		return Attribution{}, false
	}
	return Attribution{
		SessionID:   SessionIDForPod(info.UID),
		Pod: model.PodContext{
			Namespace: info.Namespace,
			PodName:   info.Name,
			PodUID:    info.UID,
			NodeName:  info.NodeName,
		},
		ContainerID: "",
	}, true
}

// NodePIDsForCgroup returns node-local PIDs currently registered for a cgroup's pod.
func (r *PodAttribution) NodePIDsForCgroup(cgroupID uint64) []int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	uid, ok := r.byCgroup[cgroupID]
	if !ok {
		return nil
	}
	keys := r.byPod[uid]
	var out []int
	for _, k := range keys {
		out = appendUnique(out, k.PID)
	}
	return out
}

// SetPodCgroups records which cgroup IDs belong to a pod (replaces prior set for that pod).
func (r *PodAttribution) SetPodCgroups(pod PodInfo, cgroupIDs []uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.podInfo[pod.UID] = pod
	// Drop old cgroup mappings for this pod.
	for cg, uid := range r.byCgroup {
		if uid == pod.UID {
			delete(r.byCgroup, cg)
		}
	}
	for _, id := range cgroupIDs {
		if id != 0 {
			r.byCgroup[id] = pod.UID
		}
	}
}

// Lookup resolves a host PID to pod attribution.
func (r *PodAttribution) Lookup(pid int) (Attribution, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	keys := r.byPID[pid]
	if len(keys) == 0 {
		return Attribution{}, false
	}

	var fallback *entry
	for _, key := range keys {
		e, exists := r.entries[key]
		if !exists {
			continue
		}
		if processAlive(pid) {
			return Attribution{
				SessionID:   e.SessionID,
				Pod:         e.Pod,
				ContainerID: e.ContainerID,
			}, true
		}
		if fallback == nil {
			cp := e
			fallback = &cp
		}
	}
	if fallback != nil {
		return Attribution{
			SessionID:   fallback.SessionID,
			Pod:         fallback.Pod,
			ContainerID: fallback.ContainerID,
		}, true
	}
	return Attribution{}, false
}

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil
}
