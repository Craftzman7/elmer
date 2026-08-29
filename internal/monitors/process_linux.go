//go:build linux

package monitors

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"elmer/internal/config"
	"elmer/internal/events"
	"elmer/internal/util"
)

// ProcessMonitor emits exec events. It is the fallback tier behind eBPF:
// when started with ebpfActive it becomes a no-op. Its own cascade is
// netlink proc connector (root) → /proc polling.
type ProcessMonitor struct {
	cfg        *config.Config
	ebpfActive bool
	caps       []string
}

func NewProcessMonitor(cfg *config.Config, ebpfActive bool) *ProcessMonitor {
	m := &ProcessMonitor{cfg: cfg, ebpfActive: ebpfActive}
	if ebpfActive {
		m.caps = []string{"idle: eBPF supplies exec events"}
	}
	return m
}

func (m *ProcessMonitor) Name() string { return "process" }

func (m *ProcessMonitor) Capabilities() []string { return m.caps }

func (m *ProcessMonitor) Start(ctx context.Context, out chan<- events.Event) error {
	if m.ebpfActive {
		<-ctx.Done()
		return nil
	}
	if err := m.runNetlink(ctx, out); err == nil {
		return nil
	} else {
		m.caps = append(m.caps, "netlink unavailable ("+err.Error()+"); polling /proc at "+
			m.cfg.PollInterval.String())
		out <- DegradedNote("process events degraded: netlink proc connector unavailable, " +
			"falling back to /proc polling at " + m.cfg.PollInterval.String())
	}
	return m.runPolling(ctx, out)
}

// ---- netlink proc connector ------------------------------------------------

// proc connector constants (linux/cn_proc.h)
const (
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1

	procEventFork = 0x00000001
	procEventExec = 0x00000004
	procEventUID  = 0x00000008
	procEventGID  = 0x00000010
	procEventExit = 0x80000000
)

func (m *ProcessMonitor) runNetlink(ctx context.Context, out chan<- events.Event) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_CONNECTOR)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: 1 << cnIdxProc,
	}); err != nil {
		return err
	}
	if err := subscribeProcConnector(fd); err != nil {
		return err
	}

	m.caps = append(m.caps, "netlink proc connector: exec/uid events")

	go func() { <-ctx.Done(); unix.Close(fd) }()

	buf := make([]byte, 4096)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("netlink read: %w", err)
		}
		m.parseNetlink(buf[:n], out)
	}
}

func subscribeProcConnector(fd int) error {
	// nlmsghdr(16) | cn_msg hdr(24: id.idx, id.val, seq, ack, len, flags, pad) | mcast_op(4)
	b := make([]byte, 16+24+4)
	binary.LittleEndian.PutUint32(b[0:], uint32(len(b))) // nlmsg_len
	binary.LittleEndian.PutUint16(b[4:], 2)              // nlmsg_type = NLMSG_DONE? (unused by kernel)
	binary.LittleEndian.PutUint16(b[6:], 0)              // flags
	binary.LittleEndian.PutUint32(b[8:], 0)              // seq
	binary.LittleEndian.PutUint32(b[12:], 0)             // pid
	off := 16
	binary.LittleEndian.PutUint32(b[off+0:], cnIdxProc) // cn_msg.id.idx
	binary.LittleEndian.PutUint32(b[off+4:], cnValProc) // cn_msg.id.val
	binary.LittleEndian.PutUint32(b[off+8:], 0)         // seq
	binary.LittleEndian.PutUint32(b[off+12:], 0)        // ack
	binary.LittleEndian.PutUint32(b[off+16:], 4)        // len
	// flags(1) + 3 pad
	binary.LittleEndian.PutUint32(b[off+20:], procCnMcastListen)
	return unix.Sendmsg(fd, b, nil, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, 0)
}

func (m *ProcessMonitor) parseNetlink(b []byte, out chan<- events.Event) {
	// Each datagram: nlmsghdr(16) + cn_msg(24) + proc_event
	const hdr = 16 + 24
	if len(b) < hdr+16 {
		return
	}
	off := hdr
	what := binary.LittleEndian.Uint32(b[off:])
	// cpu(4) + timestamp(8) then union
	p := off + 4 + 8
	now := time.Now()

	switch what {
	case procEventExec:
		pid := int(int32(binary.LittleEndian.Uint32(b[p:])))
		m.emitExec(now, pid, out)
	case procEventUID:
		pid := int(int32(binary.LittleEndian.Uint32(b[p:])))
		ruid := binary.LittleEndian.Uint32(b[p+4:])
		euid := binary.LittleEndian.Uint32(b[p+8:])
		if euid == 0 && ruid != 0 {
			out <- events.Event{
				Time:     now,
				Severity: events.High,
				Category: events.CatProcess,
				Title:    "setuid escalation to root",
				Message: fmt.Sprintf("pid %d raised euid from %d to 0",
					pid, ruid),
				Fields:    map[string]string{"pid": strconv.Itoa(pid), "uid": "0"},
				Technique: "T1548.001",
				Host:      events.Host,
				Key:       "setuid/" + strconv.Itoa(pid),
			}
		}
	}
}

// emitExec enriches a pid from /proc and emits an exec event.
func (m *ProcessMonitor) emitExec(now time.Time, pid int, out chan<- events.Event) {
	proc := filepath.Join("/proc", strconv.Itoa(pid))
	exe, _ := os.Readlink(proc + "/exe")
	cmdline := util.ReadCmdline(pid)
	status, err := os.ReadFile(proc + "/status")
	if err != nil {
		return // process already gone
	}
	uid, gid, ppid, comm := parseStatus(string(status))

	if exe == "" && cmdline == "" {
		return
	}
	ev := events.Event{
		Time:     now,
		Severity: events.Info,
		Category: events.CatProcess,
		Title:    "exec",
		Host:     events.Host,
	}
	ev.With("pid", strconv.Itoa(pid))
	if ppid > 0 {
		ev.With("ppid", strconv.Itoa(ppid))
	}
	ev.With("uid", strconv.Itoa(uid))
	ev.With("gid", strconv.Itoa(gid))
	ev.With("comm", comm)
	if exe != "" {
		ev.With("exe", exe)
	}
	if cmdline != "" {
		ev.With("cmdline", cmdline)
	}
	out <- ev
}

func parseStatus(s string) (uid, gid, ppid int, comm string) {
	for _, line := range strings.Split(s, "\n") {
		switch {
		case strings.HasPrefix(line, "Name:"):
			comm = strings.TrimSpace(line[5:])
		case strings.HasPrefix(line, "PPid:"):
			ppid, _ = strconv.Atoi(strings.TrimSpace(line[5:]))
		case strings.HasPrefix(line, "Uid:"):
			f := strings.Fields(line[4:])
			if len(f) > 0 {
				uid, _ = strconv.Atoi(f[0])
			}
		case strings.HasPrefix(line, "Gid:"):
			f := strings.Fields(line[4:])
			if len(f) > 0 {
				gid, _ = strconv.Atoi(f[0])
			}
		}
	}
	return
}

// ---- /proc polling fallback --------------------------------------------------

type procKey struct {
	exe, cmdline string
}

func (m *ProcessMonitor) runPolling(ctx context.Context, out chan<- events.Event) error {
	prev := scanProcs()
	t := time.NewTicker(m.cfg.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			cur := scanProcs()
			for pid, k := range cur {
				if pk, ok := prev[pid]; !ok || pk != k {
					m.emitExec(time.Now(), pid, out)
				}
			}
			prev = cur
		}
	}
}

func scanProcs() map[int]procKey {
	out := map[int]procKey{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if exe == "" {
			continue // kernel thread or gone
		}
		out[pid] = procKey{exe: exe, cmdline: util.ReadCmdline(pid)}
	}
	return out
}
