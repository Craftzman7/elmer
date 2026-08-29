//go:build linux

package monitors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"elmer/internal/config"
	"elmer/internal/events"
	"elmer/internal/util"
)

// PersistenceMonitor periodically sweeps persistence locations (users,
// SUID binaries, systemd units, cron, kernel modules, SSH keys) and diffs
// against a baseline stored in the state dir.
type PersistenceMonitor struct {
	cfg  *config.Config
	caps []string
}

func NewPersistenceMonitor(cfg *config.Config) *PersistenceMonitor {
	return &PersistenceMonitor{cfg: cfg}
}

func (m *PersistenceMonitor) Name() string { return "persistence" }

func (m *PersistenceMonitor) Capabilities() []string { return m.caps }

// PersistenceSnapshot is the comparable state of a host's persistence
// surface. Exported so `elmer audit` can render and write baselines.
type PersistenceSnapshot struct {
	Time         string            `json:"time"`
	Users        map[string]string `json:"users"`      // name → uid:gid:shell
	ShadowHashes map[string]string `json:"shadow"`     // user → password hash marker
	UID0         []string          `json:"uid0"`       // accounts with uid 0
	SudoRules    []string          `json:"sudo"`       // raw sudoers lines (normalized)
	SUID         map[string]string `json:"suid"`       // path → sha256
	Systemd      []string          `json:"systemd"`    // unit names
	Cron         []string          `json:"cron"`       // cron file paths
	Modules      []string          `json:"modules"`    // loaded kernel module names
	SSHKeys      map[string]int    `json:"ssh_keys"`   // authorized_keys → line count
	Preload      bool              `json:"ld_preload"` // /etc/ld.so.preload exists
}

func (m *PersistenceMonitor) Start(ctx context.Context, out chan<- events.Event) error {
	m.caps = append(m.caps, fmt.Sprintf("sweep every %s (users, suid, systemd, cron, lkm, ssh keys)",
		m.cfg.SweepTime))

	path, err := m.cfg.StatePath("persistence-baseline.json")
	if err != nil {
		return err
	}
	baseline := loadSnapshot(path)
	if baseline == nil {
		baseline = CollectSnapshot()
		if err := saveSnapshot(path, baseline); err != nil {
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
			now := CollectSnapshot()
			for _, ev := range DiffPersistence(baseline, now) {
				out <- ev
			}
		}
	}
}

// CollectSnapshot gathers the current persistence surface.
func CollectSnapshot() *PersistenceSnapshot {
	s := &PersistenceSnapshot{
		Time:         time.Now().UTC().Format(time.RFC3339),
		Users:        map[string]string{},
		ShadowHashes: map[string]string{},
		SUID:         map[string]string{},
		SSHKeys:      map[string]int{},
	}
	// /etc/passwd
	if f, err := os.Open("/etc/passwd"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			p := strings.Split(sc.Text(), ":")
			if len(p) < 7 {
				continue
			}
			s.Users[p[0]] = p[2] + ":" + p[3] + ":" + p[6]
			if p[2] == "0" {
				s.UID0 = append(s.UID0, p[0])
			}
		}
		f.Close()
	}
	// /etc/shadow (hash marker only; never the hash itself)
	if f, err := os.Open("/etc/shadow"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			p := strings.Split(sc.Text(), ":")
			if len(p) < 2 {
				continue
			}
			h := p[1]
			if strings.HasPrefix(h, "$") {
				s.ShadowHashes[p[0]] = h[:strings.Index(h, "$")] + ":" + fmt.Sprint(len(h))
			} else {
				s.ShadowHashes[p[0]] = h
			}
		}
		f.Close()
	}
	s.SudoRules = collectSudoers()
	s.SUID = collectSUID()
	s.Systemd = listFiles("/etc/systemd/system", ".service", ".timer")
	s.Cron = listCron()
	s.Modules = listModules()
	for _, k := range authorizedKeyFiles() {
		s.SSHKeys[k] = countLines(k)
	}
	if _, err := os.Stat("/etc/ld.so.preload"); err == nil {
		s.Preload = true
	}
	sort.Strings(s.UID0)
	sort.Strings(s.Systemd)
	sort.Strings(s.Cron)
	sort.Strings(s.Modules)
	return s
}

func collectSudoers() []string {
	var out []string
	files := []string{"/etc/sudoers"}
	if ents, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range ents {
			files = append(files, filepath.Join("/etc/sudoers.d", e.Name()))
		}
	}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "NOPASSWD") || strings.Contains(line, " !") {
				out = append(out, f+" :: "+line)
			}
		}
		fh.Close()
	}
	sort.Strings(out)
	return out
}

func collectSUID() map[string]string {
	out := map[string]string{}
	for _, root := range []string{"/usr", "/bin", "/sbin", "/opt", "/tmp", "/var/tmp", "/dev/shm"} {
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.Mode()&04000 != 0 || info.Mode()&02000 != 0 {
				out[p] = util.HashFile(p)
			}
			return nil
		})
	}
	return out
}

func listFiles(dir string, suffixes ...string) []string {
	var out []string
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range ents {
		for _, sfx := range suffixes {
			if strings.HasSuffix(e.Name(), sfx) {
				out = append(out, e.Name())
			}
		}
	}
	return out
}

func listCron() []string {
	var out []string
	for _, d := range []string{"/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs"} {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			out = append(out, filepath.Join(d, e.Name()))
		}
	}
	return out
}

func listModules() []string {
	var out []string
	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if name, _, ok := strings.Cut(sc.Text(), " "); ok {
			out = append(out, name)
		}
	}
	return out
}

func authorizedKeyFiles() []string {
	var out []string
	dirs := []string{"/root"}
	if homes, err := filepath.Glob("/home/*"); err == nil {
		dirs = append(dirs, homes...)
	}
	for _, h := range dirs {
		ak := filepath.Join(h, ".ssh", "authorized_keys")
		if _, err := os.Stat(ak); err == nil {
			out = append(out, ak)
		}
	}
	return out
}

func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}

// DiffPersistence produces events for changes between two snapshots.
func DiffPersistence(old, new_ *PersistenceSnapshot) []events.Event {
	var out []events.Event
	now := time.Now()
	add := func(sev events.Severity, title, msg, key, technique string, fields map[string]string) {
		ev := events.Event{
			Time: now, Severity: sev, Category: events.CatPersistence,
			Title: title, Message: msg, Host: events.Host,
			Technique: technique, Key: key,
		}
		for k, v := range fields {
			ev.With(k, v)
		}
		out = append(out, ev)
	}

	// Users
	for name, v := range new_.Users {
		if ov, ok := old.Users[name]; !ok {
			add(events.Critical, "new user account", name+" ("+v+")",
				"user/"+name, "T1136.001", map[string]string{"user": name})
		} else if ov != v {
			add(events.High, "user account changed", name+": "+ov+" → "+v,
				"userchg/"+name, "T1098", map[string]string{"user": name})
		}
	}
	for name := range old.Users {
		if _, ok := new_.Users[name]; !ok {
			add(events.Medium, "user account deleted", name, "userdel/"+name, "T1531", nil)
		}
	}
	// UID 0
	for _, u := range new_.UID0 {
		if u != "root" && !contains(old.UID0, u) {
			add(events.Critical, "non-root account with uid 0", u, "uid0/"+u, "T1136", nil)
		}
	}
	// Shadow: hash changes and passwordless accounts. An empty shadow field
	// means the account can log in with no password at all.
	for user, marker := range new_.ShadowHashes {
		om, ok := old.ShadowHashes[user]
		if ok && om != marker {
			add(events.High, "password hash changed", user, "shadowchg/"+user, "T1098", nil)
		}
		if marker == "" && (!ok || om != "") {
			add(events.Critical, "account without password", user, "nopw/"+user, "T1098", nil)
		}
	}
	// SUID
	for p := range new_.SUID {
		if _, ok := old.SUID[p]; !ok {
			add(events.Critical, "new SUID/SGID binary", p, "suid/"+p, "T1548.001",
				map[string]string{"path": p})
		}
	}
	for p := range old.SUID {
		if _, ok := new_.SUID[p]; !ok {
			add(events.Medium, "SUID/SGID binary removed", p, "suiddel/"+p, "T1562", nil)
		}
	}
	// sudoers
	for _, r := range new_.SudoRules {
		if !contains(old.SudoRules, r) {
			add(events.High, "new sudo rule", r, "sudo/"+r, "T1548.003", nil)
		}
	}
	// systemd / cron
	for _, u := range new_.Systemd {
		if !contains(old.Systemd, u) {
			add(events.High, "new systemd unit", u, "systemd/"+u, "T1543.002", nil)
		}
	}
	for _, c := range new_.Cron {
		if !contains(old.Cron, c) {
			add(events.High, "new cron file", c, "cron/"+c, "T1053.003", nil)
		}
	}
	// kernel modules
	for _, mod := range new_.Modules {
		if !contains(old.Modules, mod) {
			add(events.Critical, "kernel module loaded", mod, "lkm/"+mod, "T1547.006", nil)
		}
	}
	// SSH keys
	for k, n := range new_.SSHKeys {
		if on, ok := old.SSHKeys[k]; !ok || n > on {
			add(events.Critical, "authorized_keys changed", fmt.Sprintf("%s: %d keys", k, n),
				"sshkey/"+k, "T1098.004", map[string]string{"path": k})
		}
	}
	// ld.so.preload
	if new_.Preload && !old.Preload {
		add(events.Critical, "/etc/ld.so.preload appeared", "userspace rootkit indicator",
			"preload", "T1546.012", nil)
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func loadSnapshot(path string) *PersistenceSnapshot {
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

func saveSnapshot(path string, s *PersistenceSnapshot) error {
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
	if err := saveSnapshot(path, CollectSnapshot()); err != nil {
		return "", err
	}
	return path, nil
}
