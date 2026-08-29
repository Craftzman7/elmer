//go:build windows

package monitors

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"elmer/internal/config"
	"elmer/internal/events"
)

// ProcessMonitor consumes Security 4688 (process creation) events. When
// process auditing is off it falls back to CreateToolhelp32Snapshot polling
// (exe + pid only; command lines are unavailable that way).
type ProcessMonitor struct {
	cfg  *config.Config
	caps []string
}

func NewProcessMonitor(cfg *config.Config) *ProcessMonitor {
	return &ProcessMonitor{cfg: cfg}
}

func (m *ProcessMonitor) Name() string { return "process" }

func (m *ProcessMonitor) Capabilities() []string { return m.caps }

func (m *ProcessMonitor) Start(ctx context.Context, out chan<- events.Event) error {
	sub, err := evtSubscribe("Security", "*[System[(EventID=4688)]]")
	if err != nil {
		m.caps = append(m.caps, "4688 unavailable ("+err.Error()+"); Toolhelp32 polling")
		out <- DegradedNote("process: Security 4688 subscription failed (" + err.Error() +
			") — run `elmer harden` to enable process auditing; falling back to snapshot polling")
		return m.runToolhelp(ctx, out)
	}
	defer sub.close()
	m.caps = append(m.caps, "event log 4688 process creation (with command line if audited)")

	stop := ctx.Done()
	return runEvtLoop(stop, sub, func(doc string) {
		id, data, err := parseEvtXml(doc)
		if err != nil || id != 4688 {
			return
		}
		ev := events.Event{
			Time:     time.Now(),
			Severity: events.Info,
			Category: events.CatProcess,
			Title:    "exec",
			Host:     events.Host,
		}
		ev.With("user", data["SubjectDomainName"]+"\\"+data["SubjectUserName"])
		if p := data["NewProcessName"]; p != "" {
			ev.With("exe", p)
		}
		if c := data["CommandLine"]; c != "" {
			ev.With("cmdline", c)
		}
		if p := data["ProcessId"]; p != "" {
			ev.With("pid", trim0x(p))
		}
		if p := data["ParentProcessId"]; p != "" {
			ev.With("ppid", trim0x(p))
		}
		if exe, ok := ev.Fields["exe"]; ok && exe != "" {
			out <- ev
		}
	})
}

func trim0x(s string) string {
	return strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
}

// ---- Toolhelp32 snapshot polling fallback -----------------------------------

var (
	modkernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procCreateToolhelp32 = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW  = modkernel32.NewProc("Process32FirstW")
	procProcess32NextW   = modkernel32.NewProc("Process32NextW")
)

const th32csSnapProcess = 0x2

type processEntry32 struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [windows.MAX_PATH]uint16
}

func (m *ProcessMonitor) runToolhelp(ctx context.Context, out chan<- events.Event) error {
	prev := snapshotProcesses()
	t := time.NewTicker(m.cfg.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			cur := snapshotProcesses()
			for pid, name := range cur {
				if prev[pid] != name {
					ev := events.Event{
						Time:     time.Now(),
						Severity: events.Info,
						Category: events.CatProcess,
						Title:    "exec",
						Host:     events.Host,
					}
					ev.With("pid", fmt.Sprint(pid))
					ev.With("exe", name)
					out <- ev
				}
			}
			prev = cur
		}
	}
}

func snapshotProcesses() map[uint32]string {
	out := map[uint32]string{}
	h, _, _ := procCreateToolhelp32.Call(th32csSnapProcess, 0)
	if h == 0 {
		return out
	}
	defer windows.CloseHandle(windows.Handle(h))

	var e processEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	ok, _, _ := procProcess32FirstW.Call(h, uintptr(unsafe.Pointer(&e)))
	for ok != 0 {
		name := windows.UTF16ToString(e.ExeFile[:])
		if name != "" {
			out[e.ProcessID] = name
		}
		ok, _, _ = procProcess32NextW.Call(h, uintptr(unsafe.Pointer(&e)))
	}
	return out
}
