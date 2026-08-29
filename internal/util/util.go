// Package util holds shared parsing helpers for procfs, addresses, and files.
package util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

// ParseHexIPv4 decodes the little-endian hex form used by /proc/net/tcp
// (e.g. "0100007F" = 127.0.0.1).
func ParseHexIPv4(s string) (net.IP, error) {
	if len(s) != 8 {
		return nil, fmt.Errorf("bad ipv4 hex %q", s)
	}
	b := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		off := i * 2
		var v int
		if _, err := fmt.Sscanf(s[off:off+2], "%x", &v); err != nil {
			return nil, err
		}
		b[3-i] = byte(v)
	}
	return b, nil
}

// ParseHexIPv6 decodes the /proc/net/tcp6 form: eight 4-hex groups, each
// group stored little-endian.
func ParseHexIPv6(s string) (net.IP, error) {
	if len(s) != 32 {
		return nil, fmt.Errorf("bad ipv6 hex %q", s)
	}
	ip := make(net.IP, 16)
	for g := 0; g < 8; g++ {
		for i := 0; i < 4; i++ {
			off := g*8 + i*2
			var v int
			if _, err := fmt.Sscanf(s[off:off+2], "%x", &v); err != nil {
				return nil, err
			}
			ip[g*4+3-i] = byte(v)
		}
	}
	return ip, nil
}

// ParseAddrPort splits "HEXIP:HEXPORT" from /proc/net into ip and port.
func ParseAddrPort(s string) (net.IP, int, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return nil, 0, fmt.Errorf("bad addr %q", s)
	}
	ipStr, portStr := s[:i], s[i+1:]
	var ip net.IP
	var err error
	switch len(ipStr) {
	case 8:
		ip, err = ParseHexIPv4(ipStr)
	case 32:
		ip, err = ParseHexIPv6(ipStr)
	default:
		return nil, 0, fmt.Errorf("bad addr %q", s)
	}
	if err != nil {
		return nil, 0, err
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%x", &port); err != nil {
		return nil, 0, err
	}
	return ip, port, nil
}

// IPCtx is a precompiled internal-network classifier.
type IPCtx struct{ nets []*net.IPNet }

func NewIPCtx(cidrs []string) (*IPCtx, error) {
	c := &IPCtx{}
	for _, s := range cidrs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("bad cidr %q: %w", s, err)
		}
		c.nets = append(c.nets, n)
	}
	return c, nil
}

// Internal reports whether the IP is inside any configured network.
func (c *IPCtx) Internal(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, n := range c.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ReadCmdline returns /proc/<pid>/cmdline as a space-joined string.
func ReadCmdline(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(b) == 0 {
		return ""
	}
	parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	return strings.Join(parts, " ")
}

// HashFile returns the SHA-256 of a file, or "" on error.
func HashFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// FirstField extracts field N (0-based) from a /proc/<pid>/stat line,
// handling comm values containing spaces and parens.
func FirstField(stat string, afterComm int) string {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 || i+2 > len(stat) {
		return ""
	}
	fields := strings.Fields(stat[i+2:])
	if afterComm >= len(fields) {
		return ""
	}
	return fields[afterComm]
}

// IsTTY reports whether f refers to a terminal.
func IsTTY(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

// ColorsEnabled honors NO_COLOR and TTY detection.
func ColorsEnabled(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return IsTTY(f)
}
