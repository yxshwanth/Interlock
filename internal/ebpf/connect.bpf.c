// SPDX-License-Identifier: GPL-2.0
// Interlock eBPF connect() probe — detects outbound TCP connections from
// monitored PIDs. Rung 1: tracepoint on sys_enter_connect, extracts dest
// IP/port, pushes event to ring buffer. Rung 2: BPF hash map for PID-set
// filtering so only Interlock's process subtree generates events.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2

struct connect_event {
	__u64 ts_ns;
	__u32 pid;
	__u32 tid;
	__u32 dest_ip;
	__u16 dest_port;
	char  comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
} pid_filter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	__u8 *found = bpf_map_lookup_elem(&pid_filter, &pid);
	if (!found)
		return 0;

	struct sockaddr *sa = (struct sockaddr *)(unsigned long)ctx->args[1];
	if (!sa)
		return 0;

	unsigned short family;
	bpf_probe_read_user(&family, sizeof(family), &sa->sa_family);
	if (family != AF_INET)
		return 0;

	struct connect_event *ev;
	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->ts_ns = bpf_ktime_get_ns();
	ev->pid = pid;
	ev->tid = tid;

	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	bpf_probe_read_user(&ev->dest_ip, sizeof(ev->dest_ip), &sin->sin_addr.s_addr);
	bpf_probe_read_user(&ev->dest_port, sizeof(ev->dest_port), &sin->sin_port);
	ev->dest_port = bpf_ntohs(ev->dest_port);

	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
