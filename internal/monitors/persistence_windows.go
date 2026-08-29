//go:build windows

package monitors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"elmer/internal/config"
	"elmer/internal/events"
)

// PersistenceMonitor periodically sweeps Windows persistence locations and
// diffs against a JSON baseline: startup folders, Run keys, services,
// scheduled tasks, and local administrators.
type PersistenceMonitor struct {
	cfg  *config.Config
	caps []string
}

func NewPersistenceMonitor(cfg *config.Config) *PersistenceMonitor {
	return &PersistenceMonitor{cfg: cfg}
}

func (m *PersistenceMonitor) Name() string { return "persistence" }

func (m *PersistenceMonitor) Capabilities() []string { return m.caps }

type PersistenceSnapshot struct {
	Time     string            `json:"time"`
	Startup  map[string]string `json:"startup"`  // file → size
	RunKeys  map[string]string `json:"runkeys"`  // key → command
	Services map[string]string `json:"services"` // name → image path
	Tasks    []string          `json:"tasks"`    // task names
	Admins   []string          `json:"admins"`   // local administrators
}

func (m *PersistenceMonitor) Start(ctx context.Context, out chan<- events.Event) error {
	m.caps = append(m.caps, fmt.Sprintf("sweep every %s (startup, run keys, services, tasks, admins)",
		m.cfg.SweepTime))

	path, err := m.cfg.StatePath("persistence-baseline.json")
	if err != nil {
		return err
	}
	baseline := loadWinSnapshot(path)
	if baseline == nil {
		baseline = CollectWinSnapshot()
		if err := saveWinSnapshot(path, baseline); err != nil {
			out <- DegradedNote("persistence: cannot write baseline: " + err.Error())
		} else {
			out <- events.Event{
				Time:     time.Now(),
				Severity: events.Low,
				Category: events.CatPersistence,
				Title:    "baseline created",
				Message:  "persistence sweep baseline written to " + path,
				Host:     events.Host,
			}
		}
		<-ctx.Done()
		return nil
	}

	t := time.NewTicker(m.cfg.SweepTime)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			for _, ev := range DiffPersistenceWin(baseline, CollectWinSnapshot()) {
				out <- ev
			}
		}
	}
}

// CollectWinSnapshot gathers the current Windows persistence surface.
func CollectWinSnapshot() *PersistenceSnapshot {
	s := &PersistenceSnapshot{
		Time:     time.Now().UTC().Format(time.RFC3339),
		Startup:  map[string]string{},
		RunKeys:  map[string]string{},
		Services: map[string]string{},
	}
	for _, d := range startupDirs() {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			s.Startup[filepath.Join(d, e.Name())] = fmt.Sprint(info.Size())
		}
	}
	s.RunKeys = readRunKeys()
	s.Services = readServices()
	s.Tasks = listTasks()
	s.Admins = listAdmins()
	sort.Strings(s.Tasks)
	sort.Strings(s.Admins)
	return s
}

func startupDirs() []string {
	var out []string
	for _, env := range []string{"ProgramData", "APPDATA"} {
		if base := os.Getenv(env); base != "" {
			out = append(out, filepath.Join(base,
				"Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
		}
	}
	return out
}

func readServices() map[string]string {
	out := map[string]string{}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services`, registry.READ)
	if err != nil {
		return out
	}
	names, _ := k.ReadSubKeyNames(-1)
	k.Close()
	for _, n := range names {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\`+n, registry.READ)
		if err != nil {
			continue
		}
		img, _, err := sk.GetStringValue("ImagePath")
		if err == nil && img != "" {
			out[n] = strings.ToLower(img)
		}
		sk.Close()
	}
	return out
}

// listTasks shells out to schtasks (present on all Windows installs).
func listTasks() []string {
	cmd := exec.Command("schtasks", "/query", "/fo", "csv", "/nh")
	b, err := cmd.Output()
	if err != nil {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, ","); i > 0 {
			name := strings.Trim(line[:i], "\"")
			if name != "" && name != "TaskName" {
				out = append(out, name)
			}
		}
	}
	return out
}

// listAdmins shells out to net localgroup.
func listAdmins() []string {
	cmd := exec.Command("net", "localgroup", "Administrators")
	b, err := cmd.Output()
	if err != nil {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "-") ||
			strings.HasPrefix(line, "Alias name") ||
			strings.HasPrefix(line, "Comment") ||
			strings.HasPrefix(line, "Members") ||
			strings.EqualFold(line, "The command completed successfully.") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// DiffPersistenceWin produces events for changes between snapshots.
func DiffPersistenceWin(old, cur *PersistenceSnapshot) []events.Event {
	var out []events.Event
	now := time.Now()
	add := func(sev events.Severity, title, msg, key, technique string) {
		out = append(out, events.Event{
			Time: now, Severity: sev, Category: events.CatPersistence,
			Title: title, Message: msg, Host: events.Host,
			Technique: technique, Key: key,
		})
	}

	for p := range cur.Startup {
		if _, ok := old.Startup[p]; !ok {
			add(events.High, "new startup folder item", p, "startup/"+p, "T1547.001")
		}
	}
	for k, v := range cur.RunKeys {
		if ov, ok := old.RunKeys[k]; !ok {
			add(events.High, "new Run key entry", k+" = "+v, "runkey/"+k, "T1547.001")
		} else if ov != v {
			add(events.Medium, "Run key value changed", k+" = "+v, "runkeychg/"+k, "T1547.001")
		}
	}
	for n, img := range cur.Services {
		if oimg, ok := old.Services[n]; !ok {
			add(events.Critical, "new service installed", n+": "+img, "svc/"+n, "T1543.003")
		} else if oimg != img {
			add(events.High, "service binary changed", n+": "+img, "svcbin/"+n, "T1543.003")
		}
	}
	for _, t := range cur.Tasks {
		if !winContains(old.Tasks, t) {
			add(events.High, "new scheduled task", t, "task/"+t, "T1053.005")
		}
	}
	for _, a := range cur.Admins {
		if !winContains(old.Admins, a) {
			add(events.Critical, "new local administrator", a, "admin/"+a, "T1098")
		}
	}
	return out
}

func winContains(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func loadWinSnapshot(path string) *PersistenceSnapshot {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var s PersistenceSnapshot
	if json.Unmarshal(b, &s) != nil {
		return nil
	}
	return &s
}

func saveWinSnapshot(path string, s *PersistenceSnapshot) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// WriteBaseline stores the current state as the new baseline.
func WriteBaseline(cfg *config.Config) (string, error) {
	path, err := cfg.StatePath("persistence-baseline.json")
	if err != nil {
		return "", err
	}
	if err := saveWinSnapshot(path, CollectWinSnapshot()); err != nil {
		return "", err
	}
	return path, nil
}
