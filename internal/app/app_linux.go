//go:build linux

package app

import (
	"context"
	"fmt"

	"elmer/internal/config"
	"elmer/internal/events"
	"elmer/internal/monitors"
)

// buildMonitors assembles the Linux monitor stack. The eBPF monitor is
// attempted first; its availability downgrades the process/net monitors.
func buildMonitors(ctx context.Context, cfg *config.Config, out chan<- events.Event) []monitors.Monitor {
	var list []monitors.Monitor

	ebpfActive := false
	if cfg.MonitorEnabled("ebpf") {
		if m, err := monitors.NewEBPFMonitor(); err == nil {
			list = append(list, m)
			ebpfActive = true
		} else {
			out <- monitors.DegradedNote("eBPF unavailable (" + err.Error() +
				"); falling back to netlink/polling")
		}
	}

	if cfg.MonitorEnabled("process") {
		list = append(list, monitors.NewProcessMonitor(cfg, ebpfActive))
	}
	if cfg.MonitorEnabled("auth") {
		list = append(list, monitors.NewAuthMonitor(cfg))
	}
	if cfg.MonitorEnabled("fim") {
		list = append(list, monitors.NewFileMonitor(cfg))
	}
	if cfg.MonitorEnabled("net") {
		list = append(list, monitors.NewNetMonitor(cfg, ebpfActive))
	}
	if cfg.MonitorEnabled("persistence") {
		list = append(list, monitors.NewPersistenceMonitor(cfg))
	}
	return list
}

// Harden prints platform hardening recommendations for better telemetry.
func Harden(cfg *config.Config) error {
	if !cfg.LogAllProcessEvents() {
		println("note: log_all_process_events is off in your config")
	}
	println(`Linux hardening for elmer:

1. Run as root (or grant CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN):
     elmer gets eBPF execve/connect/bind tracing with full argv.
   Without root it silently falls back to netlink (exec events only)
   or /proc polling.

2. Ensure tracefs is mounted for eBPF tracepoints (default on most distros):
     mount -t tracefs none /sys/kernel/tracing

3. For richer audit trails, enable auditd process auditing:
     apt-get install -y auditd
     auditctl -w /etc/passwd -p wa -k identity
     auditctl -w /etc/sudoers -p wa -k scope
     auditctl -w /var/spool/cron/ -p wa -k cron

4. Consider journald persistent storage so elmer's journalctl fallback
   survives reboots:
     mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal

5. Verify eBPF works on this box:
     elmer-ebpfcheck   (shipped alongside elmer; run as root)`)
	return nil
}

// Audit prints the current persistence surface and optionally rebaselines.
func Audit(cfg *config.Config, writeBaseline bool) error {
	s := monitors.CollectSnapshot()
	fmt.Println("== accounts ==")
	for name, v := range s.Users {
		fmt.Printf("  %-16s %s\n", name, v)
	}
	if len(s.UID0) > 0 {
		fmt.Printf("  uid-0 accounts: %v\n", s.UID0)
	}
	for user, marker := range s.ShadowHashes {
		if marker == "" {
			fmt.Printf("  !! %-13s NO PASSWORD\n", user)
		}
	}
	fmt.Println("== sudo rules of interest ==")
	for _, r := range s.SudoRules {
		fmt.Println("  " + r)
	}
	fmt.Println("== SUID/SGID binaries ==")
	for p := range s.SUID {
		fmt.Println("  " + p)
	}
	fmt.Println("== systemd units ==")
	for _, u := range s.Systemd {
		fmt.Println("  " + u)
	}
	fmt.Println("== cron files ==")
	for _, c := range s.Cron {
		fmt.Println("  " + c)
	}
	fmt.Println("== authorized_keys ==")
	for k, n := range s.SSHKeys {
		fmt.Printf("  %s (%d keys)\n", k, n)
	}
	if s.Preload {
		fmt.Println("!! /etc/ld.so.preload exists — inspect it for rootkits")
	}

	if writeBaseline {
		path, err := monitors.WriteBaseline(cfg)
		if err != nil {
			return err
		}
		fmt.Println("\nbaseline written:", path)
	}
	return nil
}
