//go:build linux

package monitors

import (
	"context"

	"elmer/internal/events"
	"elmer/internal/monitors/ebpf"
)

// EBPFMonitor surfaces execve/connect/bind tracepoint events. Call
// NewEBPFMonitor during startup: a non-nil error means the kernel or
// privileges don't allow BPF and the caller should fall back to netlink.
type EBPFMonitor struct {
	rt *ebpf.Runtime
}

func NewEBPFMonitor() (*EBPFMonitor, error) {
	rt, err := ebpf.Load()
	if err != nil {
		return nil, err
	}
	return &EBPFMonitor{rt: rt}, nil
}

func (m *EBPFMonitor) Name() string { return "ebpf" }

func (m *EBPFMonitor) Capabilities() []string {
	return []string{
		"execve/execveat tracing with full argv",
		"connect/bind tracing with peer address and pid",
	}
}

func (m *EBPFMonitor) Start(ctx context.Context, out chan<- events.Event) error {
	m.rt.Run(ctx, out)
	return nil
}

func (m *EBPFMonitor) Close() { m.rt.Close() }
