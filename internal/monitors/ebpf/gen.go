//go:build linux

package ebpf

// Regenerates the embedded BPF objects and Go bindings. Run via
// `make generate` (uses a Linux container because clang needs a BPF target).
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" -type exec_event -type sock_event elmerBpf ./bpf/elmer.bpf.c -- -I./bpf/include
