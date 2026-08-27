package k8s

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

// MonitorLabel is the pod label that opts a workload into sensor watching.
const MonitorLabel = "interlock.io/monitor"

// PIDHooks are called when host PIDs / cgroups should be added/removed from the eBPF filter.
type PIDHooks struct {
	OnWatch         func(pids []int)
	OnUnwatch       func(pids []int)
	OnWatchCgroups  func(ids []uint64)
	OnUnwatchCgroups func(ids []uint64)
}

// WatcherConfig configures the node-local pod watcher.
type WatcherConfig struct {
	NodeName       string
	Namespace      string // empty = all namespaces
	RescanInterval time.Duration
	LabelSelector  string // default MonitorLabel=true
	Kubeconfig     string // optional; empty uses in-cluster config
	ProcRoot       string
}

// NodeWatcher watches labeled pods on this node and syncs PIDs into PodAttribution.
type NodeWatcher struct {
	cfg    WatcherConfig
	client kubernetes.Interface
	attr   *PodAttribution
	scan   *ProcScanner
	hooks  PIDHooks
	log    *log.Logger

	mu         sync.Mutex
	containers map[string]map[string]struct{} // podUID → container IDs
	pods       map[string]PodInfo
}

// NewNodeWatcher builds a watcher. Call Run to start.
func NewNodeWatcher(cfg WatcherConfig, attr *PodAttribution, hooks PIDHooks) (*NodeWatcher, error) {
	if cfg.NodeName == "" {
		cfg.NodeName = os.Getenv("NODE_NAME")
	}
	if cfg.NodeName == "" {
		return nil, fmt.Errorf("NODE_NAME is required for sensor mode")
	}
	if cfg.RescanInterval == 0 {
		cfg.RescanInterval = 1 * time.Second
	}
	if cfg.LabelSelector == "" {
		cfg.LabelSelector = MonitorLabel + "=true"
	}
	if cfg.Namespace == "" {
		cfg.Namespace = os.Getenv("WATCH_NAMESPACE")
	}

	restCfg, err := restConfig(cfg.Kubeconfig)
	if err != nil {
		return nil, err
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}

	return &NodeWatcher{
		cfg:        cfg,
		client:     client,
		attr:       attr,
		scan:       &ProcScanner{ProcRoot: cfg.ProcRoot},
		hooks:      hooks,
		log:        log.New(os.Stderr, "[k8s-watcher] ", log.LstdFlags),
		containers: make(map[string]map[string]struct{}),
		pods:       make(map[string]PodInfo),
	}, nil
}

func restConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if env := os.Getenv("KUBECONFIG"); env != "" {
		return clientcmd.BuildConfigFromFlags("", env)
	}
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}
	// Dev fallback: ~/.kube/config
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, &clientcmd.ConfigOverrides{},
	).ClientConfig()
}

// Run blocks until ctx is cancelled.
func (w *NodeWatcher) Run(ctx context.Context) error {
	ns := w.cfg.Namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	factory := informers.NewSharedInformerFactoryWithOptions(w.client, 30*time.Second,
		informers.WithNamespace(ns),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.LabelSelector = w.cfg.LabelSelector
			opts.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", w.cfg.NodeName).String()
		}),
	)

	informer := factory.Core().V1().Pods().Informer()
	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			w.upsertPod(pod)
		},
		UpdateFunc: func(_, newObj any) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}
			w.upsertPod(pod)
		},
		DeleteFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
					pod, _ = tombstone.Obj.(*corev1.Pod)
				}
			}
			if pod == nil {
				return
			}
			w.removePod(string(pod.UID))
		},
	})
	if err != nil {
		return fmt.Errorf("add event handler: %w", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return fmt.Errorf("pod informer sync failed")
	}
	w.log.Printf("watching pods on node=%s label=%q namespace=%q",
		w.cfg.NodeName, w.cfg.LabelSelector, ns)

	ticker := time.NewTicker(w.cfg.RescanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			w.rescanAll()
		}
	}
}

func (w *NodeWatcher) upsertPod(pod *corev1.Pod) {
	if pod.Spec.NodeName != "" && pod.Spec.NodeName != w.cfg.NodeName {
		return
	}
	ids := containerIDsFromPod(pod)
	info := PodInfo{
		UID:       string(pod.UID),
		Namespace: pod.Namespace,
		Name:      pod.Name,
		NodeName:  w.cfg.NodeName,
	}

	w.mu.Lock()
	w.pods[info.UID] = info
	if len(ids) == 0 {
		w.mu.Unlock()
		return
	}
	w.containers[info.UID] = ids
	w.mu.Unlock()

	w.syncPIDs(info, ids)
}

func (w *NodeWatcher) removePod(uid string) {
	w.mu.Lock()
	delete(w.containers, uid)
	delete(w.pods, uid)
	w.mu.Unlock()

	pids := w.attr.UnregisterPod(uid)
	w.attr.SetPodCgroups(PodInfo{UID: uid}, nil)
	if len(pids) > 0 && w.hooks.OnUnwatch != nil {
		w.hooks.OnUnwatch(pids)
	}
	w.log.Printf("unwatched pod uid=%s pids=%v", uid, pids)
}

func (w *NodeWatcher) rescanAll() {
	w.mu.Lock()
	type pair struct {
		info PodInfo
		ids  map[string]struct{}
	}
	var work []pair
	for uid, ids := range w.containers {
		info, ok := w.pods[uid]
		if !ok {
			continue
		}
		cp := make(map[string]struct{}, len(ids))
		for id := range ids {
			cp[id] = struct{}{}
		}
		work = append(work, pair{info: info, ids: cp})
	}
	w.mu.Unlock()

	for _, p := range work {
		w.syncPIDs(p.info, p.ids)
	}
}

func (w *NodeWatcher) syncPIDs(info PodInfo, ids map[string]struct{}) {
	keys, err := w.scan.PIDsForContainers(ids)
	if err != nil {
		w.log.Printf("proc scan: %v", err)
		return
	}
	var cid string
	for id := range ids {
		cid = id
		break
	}
	added, removed := w.attr.SyncPod(info, cid, keys)
	if len(removed) > 0 && w.hooks.OnUnwatch != nil {
		w.hooks.OnUnwatch(removed)
	}
	if len(added) > 0 && w.hooks.OnWatch != nil {
		w.hooks.OnWatch(added)
		w.log.Printf("watching pod %s/%s uid=%s pids=%v", info.Namespace, info.Name, info.UID, added)
	}

	// Resolve cgroup v2 IDs from any live PID (cross-namespace BPF filter).
	var cgIDs []uint64
	seen := map[uint64]struct{}{}
	for _, key := range keys {
		cg, err := CgroupIDFromPID(key.PID, w.cfg.ProcRoot, "")
		if err != nil || cg == 0 {
			continue
		}
		if _, ok := seen[cg]; ok {
			continue
		}
		seen[cg] = struct{}{}
		cgIDs = append(cgIDs, cg)
	}
	w.attr.SetPodCgroups(info, cgIDs)
	if len(cgIDs) > 0 && w.hooks.OnWatchCgroups != nil {
		// Idempotent map puts; log only when we first discover cgroups for this sync with PIDs.
		if len(added) > 0 || len(keys) > 0 {
			w.hooks.OnWatchCgroups(cgIDs)
		}
	}
	if len(added) > 0 {
		w.log.Printf("watching pod %s/%s uid=%s pids=%v cgroups=%v",
			info.Namespace, info.Name, info.UID, added, cgIDs)
	}
}

func containerIDsFromPod(pod *corev1.Pod) map[string]struct{} {
	out := make(map[string]struct{})
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.ContainerID == "" {
			continue
		}
		id := NormalizeContainerID(cs.ContainerID)
		if id != "" {
			out[id] = struct{}{}
		}
	}
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.ContainerID == "" || cs.State.Running == nil {
			continue
		}
		id := NormalizeContainerID(cs.ContainerID)
		if id != "" {
			out[id] = struct{}{}
		}
	}
	for _, cs := range pod.Status.EphemeralContainerStatuses {
		if cs.ContainerID == "" {
			continue
		}
		id := NormalizeContainerID(cs.ContainerID)
		if id != "" {
			out[id] = struct{}{}
		}
	}
	return out
}
