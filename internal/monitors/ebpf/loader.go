//go:build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"elmer/internal/events"
)

// Event kind values, matching EXEC_KIND/CONNECT_KIND/BIND_KIND in
// bpf/elmer.bpf.c.
const (
	kindExec    = 1
	kindConnect = 2
	kindBind    = 3
)

// Runtime holds loaded BPF objects, tracepoint links, and the ring buffer
// reader.
type Runtime struct {
	objs  elmerBpfObjects
	links []link.Link
	rd    *ringbuf.Reader
}

// Load loads the embedded bytecode and attaches the tracepoints. It requires
// root (or CAP_BPF/CAP_PERFMON) and a kernel with ring buffer support (5.8+).
// A non-nil error tells the caller to fall back to netlink/polling.
func Load() (*Runtime, error) {
	// Kernels before 5.11 account BPF memory against RLIMIT_MEMLOCK.
	unix.Prlimit(0, unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}, nil)

	var rt Runtime
	if err := loadElmerBpfObjects(&rt.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}
	rd, err := ringbuf.NewReader(rt.objs.Events)
	if err != nil {
		rt.Close()
		return nil, fmt.Errorf("ringbuf: %w", err)
	}
	rt.rd = rd
	for _, at := range []struct {
		prog *ebpf.Program
		tp   string
	}{
		{rt.objs.TraceExecve, "sys_enter_execve"},
		{rt.objs.TraceExecveat, "sys_enter_execveat"},
		{rt.objs.TraceConnect, "sys_enter_connect"},
		{rt.objs.TraceBind, "sys_enter_bind"},
	} {
		l, err := link.Tracepoint("syscalls", at.tp, at.prog, nil)
		if err != nil {
			rt.Close()
			return nil, fmt.Errorf("attach %s: %w", at.tp, err)
		}
		rt.links = append(rt.links, l)
	}
	return &rt, nil
}

// Close releases links, maps, and the ring buffer.
func (rt *Runtime) Close() {
	if rt.rd != nil {
		rt.rd.Close()
	}
	for _, l := range rt.links {
		l.Close()
	}
	rt.objs.Close()
}

// Run consumes ring buffer records until ctx is canceled, converting them to
// events on out. It always returns after ctx cancellation.
func (rt *Runtime) Run(ctx context.Context, out chan<- events.Event) {
	go func() {
		<-ctx.Done()
		rt.rd.Close()
	}()
	for {
		rec, err := rt.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		if ev, ok := parse(rec.RawSample); ok {
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}
}

func parse(b []byte) (events.Event, bool) {
	if len(b) < 4 {
		return events.Event{}, false
	}
	switch binary.LittleEndian.Uint32(b[0:4]) {
	case kindExec:
		if len(b) != int(unsafe.Sizeof(elmerBpfExecEvent{})) {
			return events.Event{}, false
		}
		e := (*elmerBpfExecEvent)(unsafe.Pointer(&b[0]))
		cmdline := strings.Join(argvStrings(u8(e.Argv[:e.ArgvLen])), " ")
		ev := events.Event{
			Time:     time.Now(),
			Severity: events.Info,
			Category: events.CatProcess,
			Title:    "exec",
			Host:     events.Host,
		}
		ev.With("pid", strconv.FormatUint(uint64(e.Tgid), 10))
		ev.With("uid", strconv.FormatUint(uint64(e.Uid), 10))
		ev.With("gid", strconv.FormatUint(uint64(e.Gid), 10))
		ev.With("comm", cstr(u8(e.Comm[:])))
		ev.With("exe", cstr(u8(e.Filename[:])))
		ev.With("cmdline", cmdline)
		return ev, true
	case kindConnect, kindBind:
		if len(b) != int(unsafe.Sizeof(elmerBpfSockEvent{})) {
			return events.Event{}, false
		}
		s := (*elmerBpfSockEvent)(unsafe.Pointer(&b[0]))
		ip := net.IP(s.Addr[:])
		if s.Family == 2 { // AF_INET
			ip = net.IP(s.Addr[:4])
		}
		title, action := "outbound connect", "connect"
		if binary.LittleEndian.Uint32(b[0:4]) == kindBind {
			title, action = "socket bound", "bind"
		}
		ev := events.Event{
			Time:     time.Now(),
			Severity: events.Info,
			Category: events.CatNetwork,
			Title:    title,
			Host:     events.Host,
		}
		ev.With("action", action)
		ev.With("pid", strconv.FormatUint(uint64(s.Tgid), 10))
		ev.With("uid", strconv.FormatUint(uint64(s.Uid), 10))
		ev.With("comm", cstr(u8(s.Comm[:])))
		ev.With("dst_ip", ip.String())
		ev.With("port", strconv.FormatUint(uint64(s.Port), 10))
		return ev, true
	}
	return events.Event{}, false
}

// u8 reinterprets an int8 slice (bpf2go's mapping of C char[]) as bytes.
func u8(b []int8) []byte {
	if len(b) == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&b[0])), len(b))
}

// cstr trims at the first NUL.
func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// argvStrings splits a NUL-separated argv blob; the final entry may be
// truncated without a terminator.
func argvStrings(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == 0 {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}
