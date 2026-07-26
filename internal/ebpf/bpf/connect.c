// SPDX-License-Identifier: GPL-2.0
// Interlock eBPF probes — connect, write, writev, sendto, sendmsg (IPv4+IPv6),
// openat, plus an opt-in LSM quarantine hook on socket_connect.
// Routine events (connect/openat) and critical events
// (write/writev/sendto/sendmsg/lsm_deny) use segregated ring buffers.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define AF_INET  2
#define AF_INET6 10
#define EVENT_CONNECT 1
#define EVENT_WRITE   2
#define EVENT_SENDTO  3
#define EVENT_OPENAT  4
#define EVENT_LSM_DENY 5
#define EVENT_WRITEV  6
#define EVENT_SENDMSG 7
#define PAYLOAD_MAX   1024
#define PATH_MAX_CAP  128
#define DEFAULT_PAYLOAD_CAP 512
/* BPF programs don't have <errno.h>; EPERM is 1 on every Linux arch. */
#define EPERM 1

/* Dest-bearing events: family + 16-byte addr (IPv4 in first 4 bytes) + port. */
struct connect_event {
	__u32 type; /* EVENT_CONNECT */
	__u32 _pad;
	__u64 ts_ns;
	__u32 pid;
	__u32 tid;
	__u8  family; /* AF_INET / AF_INET6 */
	__u8  dest_addr[16];
	__u16 dest_port;
	__u8  _pad2[5];
	__u64 cgroup_id;
	char  comm[16];
};

struct write_event {
	__u32 type; /* EVENT_WRITE or EVENT_WRITEV (or unnamed EVENT_SENDMSG) */
	__u32 len;  /* bytes captured (≤ PAYLOAD_MAX) */
	__u64 ts_ns;
	__u32 pid;
	__u32 tid;
	__u32 fd;
	__u32 _pad;
	__u64 cgroup_id;
	char  comm[16];
	char  payload[PAYLOAD_MAX];
};

struct sendto_event {
	__u32 type; /* EVENT_SENDTO or named EVENT_SENDMSG */
	__u32 len;
	__u64 ts_ns;
	__u32 pid;
	__u32 tid;
	__u8  family;
	__u8  dest_addr[16];
	__u16 dest_port;
	__u8  _pad[5];
	__u64 cgroup_id;
	char  comm[16];
	char  payload[PAYLOAD_MAX];
};

struct openat_event {
	__u32 type; /* EVENT_OPENAT */
	__u32 path_len;
	__u64 ts_ns;
	__u32 pid;
	__u32 tid;
	__u64 cgroup_id;
	char  comm[16];
	char  path[PATH_MAX_CAP];
};

struct lsm_deny_event {
	__u32 type; /* EVENT_LSM_DENY */
	__u32 _pad;
	__u64 ts_ns;
	__u32 pid;
	__u32 tid;
	__u64 cgroup_id;
	char  comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
} pid_filter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, __u8);
} cgroup_filter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
} lsm_blocklist_pid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, __u8);
} lsm_blocklist_cgroup SEC(".maps");

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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} critical_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} critical_drop_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} payload_cap SEC(".maps");

static __always_inline void inc_drop_count(void) {
	__u32 key = 0;
	__u64 *count = bpf_map_lookup_elem(&drop_count, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}

static __always_inline void inc_critical_drop_count(void) {
	__u32 key = 0;
	__u64 *count = bpf_map_lookup_elem(&critical_drop_count, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}

static __always_inline __u32 payload_limit(void) {
	__u32 key = 0;
	__u32 *v = bpf_map_lookup_elem(&payload_cap, &key);
	__u32 lim = DEFAULT_PAYLOAD_CAP;
	if (v && *v > 0)
		lim = *v;
	if (lim > PAYLOAD_MAX)
		lim = PAYLOAD_MAX;
	return lim;
}

static __always_inline int monitored_task(void) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u8 *found = bpf_map_lookup_elem(&pid_filter, &pid);
	if (found)
		return 1;
	__u64 cg = bpf_get_current_cgroup_id();
	found = bpf_map_lookup_elem(&cgroup_filter, &cg);
	return found != 0;
}

/* Fill family/dest_addr/port from userspace sockaddr. Returns 0 on success. */
static __always_inline int read_dest(__u8 *family_out, __u8 dest_addr[16], __u16 *port_out,
				     const struct sockaddr *sa) {
	unsigned short family;
	bpf_probe_read_user(&family, sizeof(family), &sa->sa_family);
	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;
		__u32 ip = 0;
		__u16 port = 0;
		bpf_probe_read_user(&ip, sizeof(ip), &sin->sin_addr.s_addr);
		bpf_probe_read_user(&port, sizeof(port), &sin->sin_port);
		*family_out = AF_INET;
		__builtin_memset(dest_addr, 0, 16);
		__builtin_memcpy(dest_addr, &ip, 4);
		*port_out = bpf_ntohs(port);
		return 0;
	}
	if (family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
		__u16 port = 0;
		bpf_probe_read_user(dest_addr, 16, &sin6->sin6_addr);
		bpf_probe_read_user(&port, sizeof(port), &sin6->sin6_port);
		*family_out = AF_INET6;
		*port_out = bpf_ntohs(port);
		return 0;
	}
	return -1;
}

static __always_inline __u32 clamp_cap(__u64 count) {
	__u32 cap = payload_limit();
	if (cap > PAYLOAD_MAX)
		cap = PAYLOAD_MAX;
	if (count < cap)
		cap = (__u32)count;
	return cap;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
	if (!monitored_task())
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	struct sockaddr *sa = (struct sockaddr *)(unsigned long)ctx->args[1];
	if (!sa)
		return 0;

	__u8 family = 0;
	__u8 dest_addr[16];
	__u16 dest_port = 0;
	__builtin_memset(dest_addr, 0, sizeof(dest_addr));
	if (read_dest(&family, dest_addr, &dest_port, sa) != 0)
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
	ev->family = family;
	__builtin_memcpy(ev->dest_addr, dest_addr, 16);
	ev->dest_port = dest_port;
	ev->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
	if (!monitored_task())
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	__u32 fd = (__u32)ctx->args[0];
	if (fd < 3)
		return 0;

	const char *buf = (const char *)(unsigned long)ctx->args[1];
	__u64 count = (__u64)ctx->args[2];
	if (!buf || count == 0)
		return 0;

	__u32 cap = clamp_cap(count);

	struct write_event *ev;
	ev = bpf_ringbuf_reserve(&critical_events, sizeof(*ev), 0);
	if (!ev) {
		inc_critical_drop_count();
		return 0;
	}

	__builtin_memset(ev, 0, offsetof(struct write_event, payload));
	ev->type = EVENT_WRITE;
	ev->len = cap;
	ev->ts_ns = bpf_ktime_get_ns();
	ev->pid = pid;
	ev->tid = tid;
	ev->fd = fd;
	ev->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
	bpf_probe_read_user(ev->payload, PAYLOAD_MAX, buf);

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

/* writev(fd, iov, iovcnt) — capture first iovec only (verifier-safe). */
SEC("tracepoint/syscalls/sys_enter_writev")
int tracepoint__syscalls__sys_enter_writev(struct trace_event_raw_sys_enter *ctx) {
	if (!monitored_task())
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	__u32 fd = (__u32)ctx->args[0];
	if (fd < 3)
		return 0;

	const struct iovec *iovp = (const struct iovec *)(unsigned long)ctx->args[1];
	__u64 iovcnt = (__u64)ctx->args[2];
	if (!iovp || iovcnt == 0)
		return 0;

	struct iovec iov0;
	bpf_probe_read_user(&iov0, sizeof(iov0), iovp);
	if (!iov0.iov_base || iov0.iov_len == 0)
		return 0;

	__u32 cap = clamp_cap(iov0.iov_len);

	struct write_event *ev;
	ev = bpf_ringbuf_reserve(&critical_events, sizeof(*ev), 0);
	if (!ev) {
		inc_critical_drop_count();
		return 0;
	}

	__builtin_memset(ev, 0, offsetof(struct write_event, payload));
	ev->type = EVENT_WRITEV;
	ev->len = cap;
	ev->ts_ns = bpf_ktime_get_ns();
	ev->pid = pid;
	ev->tid = tid;
	ev->fd = fd;
	ev->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
	bpf_probe_read_user(ev->payload, PAYLOAD_MAX, iov0.iov_base);

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint__syscalls__sys_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
	if (!monitored_task())
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	__u32 fd = (__u32)ctx->args[0];
	if (fd < 3)
		return 0;

	const char *buf = (const char *)(unsigned long)ctx->args[1];
	__u64 count = (__u64)ctx->args[2];
	struct sockaddr *sa = (struct sockaddr *)(unsigned long)ctx->args[4];
	if (!buf || count == 0 || !sa)
		return 0;

	__u8 family = 0;
	__u8 dest_addr[16];
	__u16 dest_port = 0;
	__builtin_memset(dest_addr, 0, sizeof(dest_addr));
	if (read_dest(&family, dest_addr, &dest_port, sa) != 0)
		return 0;

	__u32 cap = clamp_cap(count);

	struct sendto_event *ev;
	ev = bpf_ringbuf_reserve(&critical_events, sizeof(*ev), 0);
	if (!ev) {
		inc_critical_drop_count();
		return 0;
	}

	__builtin_memset(ev, 0, offsetof(struct sendto_event, payload));
	ev->type = EVENT_SENDTO;
	ev->len = cap;
	ev->ts_ns = bpf_ktime_get_ns();
	ev->pid = pid;
	ev->tid = tid;
	ev->family = family;
	__builtin_memcpy(ev->dest_addr, dest_addr, 16);
	ev->dest_port = dest_port;
	ev->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
	bpf_probe_read_user(ev->payload, PAYLOAD_MAX, buf);

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

/* sendmsg(fd, msg, flags) — first iov; named dest → sendto layout, else write layout. */
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tracepoint__syscalls__sys_enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
	if (!monitored_task())
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	__u32 fd = (__u32)ctx->args[0];
	if (fd < 3)
		return 0;

	const struct user_msghdr *umsg = (const struct user_msghdr *)(unsigned long)ctx->args[1];
	if (!umsg)
		return 0;

	struct user_msghdr hdr;
	bpf_probe_read_user(&hdr, sizeof(hdr), umsg);
	if (!hdr.msg_iov || hdr.msg_iovlen == 0)
		return 0;

	struct iovec iov0;
	bpf_probe_read_user(&iov0, sizeof(iov0), hdr.msg_iov);
	if (!iov0.iov_base || iov0.iov_len == 0)
		return 0;

	__u32 cap = clamp_cap(iov0.iov_len);

	__u8 family = 0;
	__u8 dest_addr[16];
	__u16 dest_port = 0;
	__builtin_memset(dest_addr, 0, sizeof(dest_addr));
	int named = 0;
	if (hdr.msg_name && hdr.msg_namelen > 0) {
		if (read_dest(&family, dest_addr, &dest_port, (struct sockaddr *)hdr.msg_name) == 0)
			named = 1;
	}

	if (named) {
		struct sendto_event *ev;
		ev = bpf_ringbuf_reserve(&critical_events, sizeof(*ev), 0);
		if (!ev) {
			inc_critical_drop_count();
			return 0;
		}
		__builtin_memset(ev, 0, offsetof(struct sendto_event, payload));
		ev->type = EVENT_SENDMSG;
		ev->len = cap;
		ev->ts_ns = bpf_ktime_get_ns();
		ev->pid = pid;
		ev->tid = tid;
		ev->family = family;
		__builtin_memcpy(ev->dest_addr, dest_addr, 16);
		ev->dest_port = dest_port;
		ev->cgroup_id = bpf_get_current_cgroup_id();
		bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
		bpf_probe_read_user(ev->payload, PAYLOAD_MAX, iov0.iov_base);
		bpf_ringbuf_submit(ev, 0);
		return 0;
	}

	struct write_event *ev;
	ev = bpf_ringbuf_reserve(&critical_events, sizeof(*ev), 0);
	if (!ev) {
		inc_critical_drop_count();
		return 0;
	}
	__builtin_memset(ev, 0, offsetof(struct write_event, payload));
	ev->type = EVENT_SENDMSG;
	ev->len = cap;
	ev->ts_ns = bpf_ktime_get_ns();
	ev->pid = pid;
	ev->tid = tid;
	ev->fd = fd;
	ev->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
	bpf_probe_read_user(ev->payload, PAYLOAD_MAX, iov0.iov_base);
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
	if (!monitored_task())
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	const char *filename = (const char *)(unsigned long)ctx->args[1];
	if (!filename)
		return 0;

	struct openat_event *ev;
	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		inc_drop_count();
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->type = EVENT_OPENAT;
	ev->ts_ns = bpf_ktime_get_ns();
	ev->pid = pid;
	ev->tid = tid;
	ev->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
	long n = bpf_probe_read_user_str(ev->path, sizeof(ev->path), filename);
	if (n <= 0) {
		bpf_ringbuf_discard(ev, 0);
		return 0;
	}
	ev->path_len = (__u32)n;
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret) {
	if (ret != 0)
		return ret;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u64 cg = bpf_get_current_cgroup_id();

	__u8 *blocked = bpf_map_lookup_elem(&lsm_blocklist_pid, &pid);
	if (!blocked)
		blocked = bpf_map_lookup_elem(&lsm_blocklist_cgroup, &cg);
	if (!blocked || !*blocked)
		return 0;

	struct lsm_deny_event *ev;
	ev = bpf_ringbuf_reserve(&critical_events, sizeof(*ev), 0);
	if (!ev) {
		inc_critical_drop_count();
		return -EPERM;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->type = EVENT_LSM_DENY;
	ev->ts_ns = bpf_ktime_get_ns();
	ev->pid = pid;
	ev->tid = (__u32)pid_tgid;
	ev->cgroup_id = cg;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
	bpf_ringbuf_submit(ev, 0);

	return -EPERM;
}

char _license[] SEC("license") = "GPL";
