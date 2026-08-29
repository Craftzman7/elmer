// Package ebpf embeds elmer's BPF programs (compiled ahead of time via
// bpf2go) and exposes a loader/reader for them. The implementation files are
// linux-only; on other platforms this package is inert.
package ebpf
