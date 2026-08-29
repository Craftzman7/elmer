// elmer.bpf.c — eBPF telemetry for the elmer blue team monitor.
//
// Design constraints:
//   - Tracepoints only: no kprobes, no CO-RE, no vmlinux.h. Works on any
//     kernel with ring buffer support (5.8+), with or without kernel BTF.
//   - One ring buffer shared by all programs; userspace distinguishes event
//     types via the leading kind field.
//   - exec events capture full argv (variable-length packing, bounded);
//     connect/bind events capture the peer address, port, and process.
#include "types_shim.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define COMM_LEN  16
#define FNAME_LEN 128
#define ARGV_LEN  512
#define ARG_CHUNK 128
#define MAX_ARGS  16

#define EXEC_KIND    1
#define CONNECT_KIND 2
#define BIND_KIND    3

// Tracepoint context for syscalls/sys_enter_* (tracefs format; the common
// header plus syscall id and six register-width arguments).
struct sys_enter_ctx {
	__u16 common_type;
	__u8  common_flags;
	__u8  common_preempt_count;
	__s32 common_pid;
	__s64 id;
	__u64 args[6];
};

struct exec_event {
	__u32 kind;
	__u32 tgid;
	__u32 pid;
	__u32 uid;
	__u32 gid;
	char comm[COMM_LEN];
	char filename[FNAME_LEN];
	__u32 argv_len;
	char argv[ARGV_LEN];
};

struct sock_event {
	__u32 kind;
	__u32 tgid;
	__u32 uid;
	__u16 family;
	__u16 port; // host byte order
	__u8  addr[16];
	char comm[COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

// Type anchors: the event structs are only referenced through ringbuf
// reserves (sizeof-folded), which clang prunes from BTF. Declaring them as
// map value types forces BTF emission so bpf2go -type can generate Go
// bindings. The maps are never used at runtime.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_event);
} type_anchor_exec SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sock_event);
} type_anchor_sock SEC(".maps");

// Userspace sockaddr layouts (UAPI-stable).
struct sockaddr_in {
	__u16 sin_family;
	__be16 sin_port;
	__u32 sin_addr;
	__u8 sin_zero[8];
};

struct sockaddr_in6 {
	__u16 sin6_family;
	__be16 sin6_port;
	__u32 sin6_flowinfo;
	__u8 sin6_addr[16];
	__u32 sin6_scope_id;
};

// do_exec captures an execve/execveat invocation. fname_idx/argv_idx are
// compile-time constants from the __always_inline call sites, so the
// verifier sees constant offsets into ctx->args.
static __always_inline int do_exec(struct sys_enter_ctx *ctx, int fname_idx, int argv_idx)
{
	struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();
	e->kind = EXEC_KIND;
	e->tgid = pid_tgid >> 32;
	e->pid = (__u32)pid_tgid;
	e->uid = (__u32)uid_gid;
	e->gid = uid_gid >> 32;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(e->filename, sizeof(e->filename),
				(const void *)ctx->args[fname_idx]);

	__u64 off = 0;
	// ctx->args[argv_idx] already holds the char** value itself — assign it,
	// don't dereference. argv[i] then lives at user address &argv[i].
	const char **argv = (const char **)ctx->args[argv_idx];
	if (argv) {
		for (int i = 0; i < MAX_ARGS; i++) {
			const char *argp = NULL;
			bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
			if (!argp)
				break;
			// Subtraction form (no addition) plus a 64-bit offset keeps the
			// verifier's range for off provably inside e->argv.
			if (off > ARGV_LEN - ARG_CHUNK)
				break;
			long n = bpf_probe_read_user_str(&e->argv[off], ARG_CHUNK, argp);
			if (n <= 0)
				break;
			if (n > ARG_CHUNK)
				n = ARG_CHUNK;
			off += n;
		}
	}
	e->argv_len = (__u32)off;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct sys_enter_ctx *ctx)
{
	return do_exec(ctx, 0, 1);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct sys_enter_ctx *ctx)
{
	return do_exec(ctx, 1, 2);
}

// do_sock captures connect()/bind() with the peer address. fd is args[0],
// the userspace sockaddr is args[1], addrlen args[2].
static __always_inline int do_sock(struct sys_enter_ctx *ctx, __u32 kind)
{
	__u16 family = 0;
	bpf_probe_read_user(&family, sizeof(family), (const void *)ctx->args[1]);
	if (family != 2 && family != 10) // AF_INET, AF_INET6
		return 0;

	struct sock_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->kind = kind;
	e->tgid = pid_tgid >> 32;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->family = family;
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	if (family == 2) {
		struct sockaddr_in sa = {};
		bpf_probe_read_user(&sa, sizeof(sa), (const void *)ctx->args[1]);
		e->port = bpf_ntohs(sa.sin_port);
		__builtin_memcpy(e->addr, &sa.sin_addr, 4);
	} else {
		struct sockaddr_in6 sa = {};
		bpf_probe_read_user(&sa, sizeof(sa), (const void *)ctx->args[1]);
		e->port = bpf_ntohs(sa.sin6_port);
		__builtin_memcpy(e->addr, &sa.sin6_addr, 16);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct sys_enter_ctx *ctx)
{
	return do_sock(ctx, CONNECT_KIND);
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct sys_enter_ctx *ctx)
{
	return do_sock(ctx, BIND_KIND);
}
