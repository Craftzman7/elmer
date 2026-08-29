//go:build linux

package monitors

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"elmer/internal/config"
	"elmer/internal/events"
	"elmer/internal/util"
)

// NetMonitor diffs /proc/net/tcp{,6} snapshots. With eBPF active it only
// reports a startup baseline and listener changes (connect events come from
// eBPF with better attribution); without eBPF it polls fast and reports
// outbound connects too.
type NetMonitor struct {
	cfg        *config.Config
	ebpfActive bool
	caps       []string
}

func NewNetMonitor(cfg *config.Config, ebpfActive bool) *NetMonitor {
	return &NetMonitor{cfg: cfg, ebpfActive: ebpfActive}
}

func (m *NetMonitor) Name() string { return "net" }

func (m *NetMonitor) Capabilities() []string { return m.caps }

type connKey struct {
	local, remote string
	state         string
}

type conn struct {
	key  connKey
	inode string
	uid  string
}

func (m *NetMonitor) Start(ctx context.Context, out chan<- events.Event) error {
	interval := time.Second
	if m.ebpfActive {
		interval = 5 * time.Second
		m.caps = append(m.caps, fmt.Sprintf("/proc/net poll at %s (listeners; connects via eBPF)", interval))
	} else {
		m.caps = append(m.caps, "/proc/net poll at 1s (listeners + connects)")
	}

	prev := snapshotConns()
	prevSet := connSet(prev)
	m.reportBaseline(ctx, out, prev)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			cur := snapshotConns()
			now := time.Now()
			for _, c := range cur {
				if prevSet[c.key] {
					continue
				}
				m.reportNew(now, out, c)
			}
			prev, prevSet = cur, connSet(cur)
		}
	}
}

func connSet(conns []conn) map[connKey]bool {
	set := make(map[connKey]bool, len(conns))
	for _, c := range conns {
		set[c.key] = true
	}
	return set
}

// reportBaseline reports external established connections found at startup.
func (m *NetMonitor) reportBaseline(ctx context.Context, out chan<- events.Event, conns []conn) {
	ipc, _ := util.NewIPCtx(m.cfg.InternalCIDR)
	for _, c := range conns {
		if c.key.state != "ESTABLISHED" {
			continue
		}
		rip, _, err := util.ParseAddrPort(c.key.remote)
		if err != nil || ipc == nil || ipc.Internal(rip) {
			continue
		}
		out <- m.connEvent(time.Now(), "outbound connect", c)
	}
}

func (m *NetMonitor) reportNew(now time.Time, out chan<- events.Event, c conn) {
	switch c.key.state {
	case "LISTEN":
		out <- m.connEvent(now, "socket bound", c)
	case "ESTABLISHED":
		if !m.ebpfActive {
			out <- m.connEvent(now, "outbound connect", c)
		}
	}
}

func (m *NetMonitor) connEvent(now time.Time, title string, c conn) events.Event {
	var localIP, remoteIP string
	var lport, rport int
	if i := strings.LastIndexByte(c.key.local, ':'); i > 0 {
		localIP = c.key.local[:i]
		lport, _ = strconv.Atoi(c.key.local[i+1:])
	}
	if i := strings.LastIndexByte(c.key.remote, ':'); i > 0 {
		remoteIP = c.key.remote[:i]
		rport, _ = strconv.Atoi(c.key.remote[i+1:])
	}

	ev := events.Event{
		Time:     now,
		Severity: events.Info,
		Category: events.CatNetwork,
		Title:    title,
		Host:     events.Host,
	}
	action := "connect"
	if title == "socket bound" {
		action = "bind"
	}
	ev.With("action", action)
	ev.With("local", net.JoinHostPort(localIP, strconv.Itoa(lport)))
	if remoteIP != "" {
		ev.With("dst_ip", remoteIP)
		ev.With("port", strconv.Itoa(rport))
	} else {
		// Listener: its local port is the interesting one.
		ev.With("dst_ip", localIP)
		ev.With("port", strconv.Itoa(lport))
	}
	ev.With("uid", c.uid)
	if pid := pidForInode(c.inode); pid != "" {
		ev.With("pid", pid)
	}
	return ev
}

func snapshotConns() []conn {
	var out []conn
	seen := map[connKey]bool{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"} {
		out = append(out, parseProcNet(f, seen)...)
	}
	return out
}

func parseProcNet(path string, seen map[connKey]bool) []conn {
	var out []conn
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		local, remote, state, uid, inode := fields[1], fields[2], fields[3], fields[7], fields[9]
		if state == "0A" {
			state = "LISTEN"
		} else if state == "01" {
			state = "ESTABLISHED"
		} else {
			continue // only LISTEN/ESTABLISHED interest us
		}
		k := connKey{local: local, remote: remote, state: state}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, conn{key: k, inode: inode, uid: uid})
	}
	return out
}

// pidForInode maps a socket inode to the owning pid by scanning /proc/*/fd.
func pidForInode(inode string) string {
	if inode == "" {
		return ""
	}
	target := "socket:[" + inode + "]"
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", e.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join("/proc", e.Name(), "fd", fd.Name()))
			if err == nil && link == target {
				return e.Name()
			}
		}
	}
	return ""
}
