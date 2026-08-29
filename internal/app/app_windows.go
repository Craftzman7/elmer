//go:build windows

package app

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"elmer/internal/config"
	"elmer/internal/events"
	"elmer/internal/monitors"
)

// buildMonitors assembles the Windows monitor stack.
func buildMonitors(ctx context.Context, cfg *config.Config, out chan<- events.Event) []monitors.Monitor {
	var list []monitors.Monitor
	if cfg.MonitorEnabled("process") {
		list = append(list, monitors.NewProcessMonitor(cfg))
	}
	if cfg.MonitorEnabled("auth") {
		list = append(list, monitors.NewAuthMonitor(cfg))
	}
	if cfg.MonitorEnabled("fim") {
		list = append(list, monitors.NewFileMonitor(cfg))
	}
	if cfg.MonitorEnabled("net") {
		list = append(list, monitors.NewNetMonitor(cfg))
	}
	if cfg.MonitorEnabled("persistence") {
		list = append(list, monitors.NewPersistenceMonitor(cfg))
	}
	return list
}

// Harden enables process-creation auditing (4688 with command lines) —
// elmer's richest Windows telemetry source. Requires an elevated terminal.
func Harden(cfg *config.Config) error {
	if !isAdmin() {
		fmt.Println("not elevated — run from an Administrator terminal to harden")
		os.Exit(1)
	}

	steps := []struct {
		name string
		args []string
	}{
		{"enable process creation auditing", []string{"/set", `/subcategory:"Process Creation"`, `/success:enable`}},
		{"include command line in 4688", []string{"add", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`, "/v", "ProcessCreationIncludeCmdLine_Enabled", "/t", "REG_DWORD", "/d", "1", "/f"}},
		{"enable logon failure auditing", []string{"/set", `/subcategory:"Logon"`, `/failure:enable`}},
	}
	for _, st := range steps {
		var cmd *exec.Cmd
		if st.args[0] == "add" {
			cmd = exec.Command("reg", st.args...)
		} else {
			cmd = exec.Command("auditpol", st.args...)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("FAILED %s: %v\n%s\n", st.name, err, out)
		} else {
			fmt.Printf("ok: %s\n", st.name)
		}
	}
	fmt.Println("\nelmer telemetry is now maximal. Restart elmer start.")
	return nil
}

func isAdmin() bool {
	_, err := os.ReadFile(`C:\Windows\System32\config\SECURITY`) // admin-only readable
	return err == nil
}

// Audit prints the current persistence surface and optionally rebaselines.
func Audit(cfg *config.Config, writeBaseline bool) error {
	s := monitors.CollectWinSnapshot()
	fmt.Println("== startup folder ==")
	for p := range s.Startup {
		fmt.Println("  " + p)
	}
	fmt.Println("== run keys ==")
	for k, v := range s.RunKeys {
		fmt.Printf("  %s = %s\n", k, v)
	}
	fmt.Println("== services (image paths) ==")
	for n, img := range s.Services {
		fmt.Printf("  %-24s %s\n", n, img)
	}
	fmt.Println("== scheduled tasks ==")
	for _, t := range s.Tasks {
		fmt.Println("  " + t)
	}
	fmt.Println("== local administrators ==")
	for _, a := range s.Admins {
		fmt.Println("  " + a)
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
