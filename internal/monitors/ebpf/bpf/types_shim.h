// Fixed-width type definitions normally provided by linux/types.h or
// vmlinux.h. Defining them here keeps elmer's BPF programs buildable with
// only clang and the vendored cilium/ebpf headers — no kernel headers, no
// BTF, no CO-RE.
#ifndef __ELMER_TYPES_SHIM_H
#define __ELMER_TYPES_SHIM_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

// Map types (linux/bpf.h) — only what elmer uses.
#define BPF_MAP_TYPE_ARRAY 1
#define BPF_MAP_TYPE_RINGBUF 27

#endif
