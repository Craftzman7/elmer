//go:build linux

package monitors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"elmer/internal/config"
	"elmer/internal/events"
	"elmer/internal/util"
)

// AuthMonitor tails /var/log/auth.log (or secure), falling back to
// journalctl on journald-only distros, and parses SSH/sudo/account events.
type AuthMonitor struct {
	cfg  *config.Config
	ipc  *util.IPCtx
	caps []string
}

func NewAuthMonitor(cfg *config.Config) *AuthMonitor {
	m := &AuthMonitor{cfg: cfg}
	m.ipc, _ = util.NewIPCtx(cfg.InternalCIDR)
	return m
}

func (m *AuthMonitor) Name() string { return "auth" }

func (m *AuthMonitor) Capabilities() []string { return m.caps }

var (
	reSSHFail = regexp.MustCompile(`Failed (password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	reSSHOK   = regexp.MustCompile(`Accepted (password|publickey|keyboard-interactive/pam) for (\S+) from (\S+) port (\d+)`)
	reSudo    = regexp.MustCompile(`sudo:\s+(\S+)\s+:.*COMMAND=(.*)$`)
	reNewUser = regexp.MustCompile(`(?:useradd|adduser)\[\d+\]: new user: name=(\S+),`)
	reSu      = regexp.MustCompile(`su\[\d+\]: Successful su for (\S+) by (\S+)`)
)

func (m *AuthMonitor) Start(ctx context.Context, out chan<- events.Event) error {
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && canRead(p) {
			m.caps = append(m.caps, "tailing "+p)
			return m.tailFile(ctx, out, p)
		}
	}
	// journald-only distro
	if _, err := exec.LookPath("journalctl"); err == nil {
		m.caps = append(m.caps, "journalctl -f (auth)")
		return m.tailJournal(ctx, out)
	}
	out <- DegradedNote("no readable auth log (tried /var/log/auth.log, /var/log/secure, journalctl)")
	<-ctx.Done()
	return nil
}

func canRead(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// tailFile follows a log file across rotations by dev/inode.
func (m *AuthMonitor) tailFile(ctx context.Context, out chan<- events.Event, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	f.Seek(0, io.SeekEnd)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		// Detect rotation: reopen if the on-disk file is no longer ours.
		st, err := f.Stat()
		if err != nil {
			return err
		}
		if nst, nerr := os.Stat(path); nerr != nil || !os.SameFile(st, nst) {
			nf, err := reopenRotated(ctx, path)
			if err != nil {
				return err
			}
			f.Close()
			f = nf
		}

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 64*1024)
		for sc.Scan() {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if ev, ok := m.parseLine(time.Now(), sc.Text()); ok {
				out <- ev
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// reopenRotated waits briefly for the replacement file after rotation.
func reopenRotated(ctx context.Context, path string) (*os.File, error) {
	for i := 0; i < 20; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
		if f, err := os.Open(path); err == nil {
			return f, nil
		}
	}
	return nil, fmt.Errorf("log %s did not reappear after rotation", path)
}

func (m *AuthMonitor) tailJournal(ctx context.Context, out chan<- events.Event) error {
	cmd := exec.CommandContext(ctx, "journalctl", "-f", "-o", "short",
		"_COMM=sshd", "_COMM=sudo", "_COMM=su", "_COMM=useradd", "_COMM=usermod", "_COMM=groupadd")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { <-ctx.Done(); cmd.Process.Kill() }()

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		if ev, ok := m.parseLine(time.Now(), sc.Text()); ok {
			select {
			case out <- ev:
			case <-ctx.Done():
				cmd.Process.Kill()
				return nil
			}
		}
	}
	return cmd.Wait()
}

// parseLine converts one auth log line into an event.
func (m *AuthMonitor) parseLine(now time.Time, line string) (events.Event, bool) {
	switch {
	case reSSHFail.MatchString(line):
		g := reSSHFail.FindStringSubmatch(line)
		ev := m.authEvent(now, "SSH auth failure", events.Medium, line)
		ev.With("user", g[2]).With("src_ip", hostOnly(g[3])).With("auth", "fail")
		return ev, true
	case reSSHOK.MatchString(line):
		g := reSSHOK.FindStringSubmatch(line)
		ip := net.ParseIP(hostOnly(g[3]))
		sev := events.Info
		if m.ipc != nil && ip != nil && !m.ipc.Internal(ip) {
			sev = events.High
		}
		ev := m.authEvent(now, "SSH login", sev, line)
		ev.With("user", g[2]).With("src_ip", hostOnly(g[3])).With("auth", "ok")
		return ev, true
	case reSudo.MatchString(line):
		g := reSudo.FindStringSubmatch(line)
		ev := m.authEvent(now, "sudo command", events.Info, line)
		ev.With("user", g[1]).With("command", g[2])
		return ev, true
	case reNewUser.MatchString(line):
		g := reNewUser.FindStringSubmatch(line)
		ev := m.authEvent(now, "user account created", events.Critical, line)
		ev.With("user", g[1])
		ev.Key = "newuser/" + g[1]
		return ev, true
	case reSu.MatchString(line):
		g := reSu.FindStringSubmatch(line)
		ev := m.authEvent(now, "su (switch user)", events.Medium, line)
		ev.With("user", g[1]).With("as", g[2])
		return ev, true
	}
	return events.Event{}, false
}

func (m *AuthMonitor) authEvent(now time.Time, title string, sev events.Severity, line string) events.Event {
	return events.Event{
		Time:     now,
		Severity: sev,
		Category: events.CatAuth,
		Title:    title,
		Message:  trimPrefix(line),
		Host:     events.Host,
	}
}

// trimPrefix strips the syslog timestamp and hostname for compact messages.
func trimPrefix(line string) string {
	// "Aug 29 13:02:11 host prog[123]: rest" or "Mon 2026-08-29 13:02:11 ..."
	parts := strings.SplitN(line, ": ", 2)
	if len(parts) == 2 && len(parts[0]) < 80 {
		return parts[1]
	}
	return line
}

// hostOnly strips a port from "1.2.3.4:5678" or keeps an IPv6 literal.
func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}
