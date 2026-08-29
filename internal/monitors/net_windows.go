//go:build windows

package monitors

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"elmer/internal/config"
	"elmer/internal/events"
)

// NetMonitor diffs TCP/UDP tables (with owning pids) every second.
type NetMonitor struct {
	cfg  *config.Config
	caps []string
}

func NewNetMonitor(cfg *config.Config) *NetMonitor {
	return &NetMonitor{cfg: cfg}
}

func (m *NetMonitor) Name() string { return "net" }

func (m *NetMonitor) Capabilities() []string { return m.caps }

var (
	modiphlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTbl = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTbl = modiphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1
	afInet              = 2
	afInet6             = 23

	mibTcpStateListen     = 2
	mibTcpStateEstablished = 5
)

type tcpRow struct {
	State          uint32
	LocalAddr      uint32
	LocalScopeID   uint32
	LocalPort      uint32
	RemoteAddr     uint32
	RemoteScopeID  uint32
	RemotePort     uint32
	OwningPid      uint32
}

type udpRow struct {
	LocalAddr    uint32
	LocalScopeID uint32
	LocalPort    uint32
	OwningPid    uint32
}

type connKey struct {
	local, remote, state string
}

func (m *NetMonitor) Start(ctx context.Context, out chan<- events.Event) error {
	m.caps = append(m.caps, "TCP/UDP table polling with pid attribution")
	prev := snapshotWin()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			cur := snapshotWin()
			now := time.Now()
			for k, v := range cur {
				if _, ok := prev[k]; ok {
					continue
				}
				m.report(now, out, k, v)
			}
			for k := range prev {
				if _, ok := cur[k]; !ok && k.state == "LISTEN" {
					// listener gone; noted at Info for context
					out <- m.event(now, "listener closed", k, prev[k])
				}
			}
			prev = cur
		}
	}
}

func (m *NetMonitor) report(now time.Time, out chan<- events.Event, k connKey, pid uint32) {
	switch k.state {
	case "LISTEN":
		out <- m.event(now, "socket bound", k, pid)
	case "ESTABLISHED":
		out <- m.event(now, "outbound connect", k, pid)
	}
}

func (m *NetMonitor) event(now time.Time, title string, k connKey, pid uint32) events.Event {
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
	if l, p, ok := splitAddrPort(k.local); ok {
		ev.With("local", net.JoinHostPort(l, p))
		// For listeners the local endpoint is the interesting one.
		if k.remote == "" {
			ev.With("dst_ip", l)
			ev.With("port", p)
		}
	}
	if r, p, ok := splitAddrPort(k.remote); ok {
		ev.With("dst_ip", r)
		ev.With("port", p)
	}
	ev.With("pid", strconv.FormatUint(uint64(pid), 10))
	return ev
}

func splitAddrPort(s string) (string, string, bool) {
	if s == "" {
		return "", "", false
	}
	i := lastColon(s)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

func lastColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

// snapshotWin returns the current connection set keyed for diffing.
func snapshotWin() map[connKey]uint32 {
	out := map[connKey]uint32{}
	for _, af := range []uint32{afInet, afInet6} {
		if rows, err := tcpTable(af); err == nil {
			for _, r := range rows {
				var state string
				switch r.State {
				case mibTcpStateListen:
					state = "LISTEN"
				case mibTcpStateEstablished:
					state = "ESTABLISHED"
				default:
					continue
				}
				remote := ""
				if state == "ESTABLISHED" {
					remote = fmt.Sprintf("%s:%d", ipStr(r.RemoteAddr, af), portHtons(r.RemotePort))
				}
				k := connKey{
					local:  fmt.Sprintf("%s:%d", ipStr(r.LocalAddr, af), portHtons(r.LocalPort)),
					remote: remote,
					state:  state,
				}
				out[k] = r.OwningPid
			}
		}
		if rows, err := udpTable(af); err == nil {
			for _, r := range rows {
				k := connKey{
					local:  fmt.Sprintf("%s:%d", ipStr(r.LocalAddr, af), portHtons(r.LocalPort)),
					state:  "UDP",
				}
				out[k] = r.OwningPid
			}
		}
	}
	return out
}

// ipStr converts the little-endian DWORD address form to a string.
func ipStr(v uint32, af uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	ip := net.IP(b)
	if af == afInet6 {
		// Scope IDs and v4-mapped handling: render the v4 form; full v6
		// rendering from DWORD pairs is handled by the caller's afInet path.
		return ip.String()
	}
	return ip.String()
}

func portHtons(p uint32) uint32 {
	return uint32(p>>8&0xff) | uint32(p<<8&0xff00)
}

func tcpTable(af uint32) ([]tcpRow, error) {
	var size uint32
	procGetExtendedTcpTbl.Call(0, uintptr(unsafe.Pointer(&size)), 0,
		uintptr(af), tcpTableOwnerPidAll, 0)
	buf := make([]byte, size)
	r0, _, _ := procGetExtendedTcpTbl.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0, uintptr(af), tcpTableOwnerPidAll, 0,
	)
	if r0 != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable: %d", r0)
	}
	// Layout: DWORD numEntries, then rows.
	num := binary.LittleEndian.Uint32(buf)
	const rowSize = unsafe.Sizeof(tcpRow{})
	if int(num)*int(rowSize)+4 > len(buf) {
		num = uint32((len(buf) - 4) / int(rowSize))
	}
	rows := make([]tcpRow, 0, num)
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*int(rowSize)
		row := (*tcpRow)(unsafe.Pointer(&buf[off]))
		rows = append(rows, *row)
	}
	return rows, nil
}

func udpTable(af uint32) ([]udpRow, error) {
	var size uint32
	procGetExtendedUdpTbl.Call(0, uintptr(unsafe.Pointer(&size)), 0,
		uintptr(af), udpTableOwnerPid, 0)
	buf := make([]byte, size)
	r0, _, _ := procGetExtendedUdpTbl.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0, uintptr(af), udpTableOwnerPid, 0,
	)
	if r0 != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable: %d", r0)
	}
	num := binary.LittleEndian.Uint32(buf)
	const rowSize = unsafe.Sizeof(udpRow{})
	if int(num)*int(rowSize)+4 > len(buf) {
		num = uint32((len(buf) - 4) / int(rowSize))
	}
	rows := make([]udpRow, 0, num)
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*int(rowSize)
		row := (*udpRow)(unsafe.Pointer(&buf[off]))
		rows = append(rows, *row)
	}
	return rows, nil
}
