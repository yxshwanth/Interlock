// SPDX-License-Identifier: GPL-2.0
// Interlock eBPF probes — connect() tripwire + write() first-N payload capture.
// Events share a tagged ring-buffer layout so userspace can decode both.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define EVENT_CONNECT 1
#define EVENT_WRITE   2
#define PAYLOAD_MAX   256

struct connect_event {
	__u32 type; /* EVENT_CONNECT */
	__u32 _pad;
	__u64 ts_ns;
	__u32 pid;
	__u32 tid;
	__u32 dest_ip;
	__u16 dest_port;
	char  comm[16];
};

struct write_event {
	__u32 type; /* EVENT_WRITE */
	__u32 len;  /* bytes captured (≤ PAYLOAD_MAX) */
	__u64 ts_ns;
	__u32 pid;
	__u32 tid;
	__u32 fd;
	char  comm[16];
	char  payload[PAYLOAD_MAX];
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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drop_count SEC(".maps");

static __always_inline void inc_drop_count(void) {
	__u32 key = 0;
	__u64 *count = bpf_map_lookup_elem(&drop_count, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}

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
	if (!ev) {
		inc_drop_count();
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->type = EVENT_CONNECT;
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

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	__u8 *found = bpf_map_lookup_elem(&pid_filter, &pid);
	if (!found)
		return 0;

	__u32 fd = (__u32)ctx->args[0];
	/* Skip stdin/stdout/stderr — cut log noise; socket FDs are typically ≥ 3. */
	if (fd < 3)
		return 0;

	const char *buf = (const char *)(unsigned long)ctx->args[1];
	__u64 count = (__u64)ctx->args[2];
	if (!buf || count == 0)
		return 0;

	__u32 cap = PAYLOAD_MAX;
	if (count < cap)
		cap = (__u32)count;

	struct write_event *ev;
	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		inc_drop_count();
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->type = EVENT_WRITE;
	ev->len = cap;
	ev->ts_ns = bpf_ktime_get_ns();
	ev->pid = pid;
	ev->tid = tid;
	ev->fd = fd;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
	bpf_probe_read_user(ev->payload, cap, buf);

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
