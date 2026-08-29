// Package config loads and validates the elmer YAML configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gopkg.in/yaml.v3"

	"elmer/internal/events"
)

type Config struct {
	PollInterval time.Duration `yaml:"poll_interval"`
	SweepTime    time.Duration `yaml:"sweep_interval"`
	StateDir     string        `yaml:"state_dir"`
	InternalCIDR []string      `yaml:"internal_cidrs"`
	DedupeCool   time.Duration `yaml:"dedupe_cooldown"`
	Heartbeat    time.Duration `yaml:"heartbeat"`
	// LogProcessEvents streams every exec at Info severity to stdout. A
	// pointer so an explicit `false` in the config survives defaults.
	LogProcessEvents *bool `yaml:"log_all_process_events"`

	Monitors map[string]*bool `yaml:"monitors"`

	FIM FIMConfig `yaml:"fim"`

	Alerts AlertsConfig `yaml:"alerts"`

	Rules    []RuleConfig `yaml:"rules"`
	Disabled []string     `yaml:"disabled_rules"`

	SuspiciousPorts []int    `yaml:"suspicious_listen_ports"`
	KnownBadFiles   []string `yaml:"known_bad_filenames"`

	// SSH failure thresholds.
	BruteForceWindow  time.Duration `yaml:"brute_force_window"`
	BruteFireCount    int           `yaml:"brute_force_count"`
	BruteForceHighCnt int           `yaml:"brute_force_high_count"`
}

type FIMConfig struct {
	// Paths ending in "/" are watched recursively (new subdirs gain watches).
	Paths        []string `yaml:"paths"`
	ExtraPaths   []string `yaml:"extra_paths"`
	ExcludePaths []string `yaml:"exclude_paths"`
}

type AlertsConfig struct {
	Discord DiscordConfig `yaml:"discord"`
	Ntfy    NtfyConfig    `yaml:"ntfy"`
	Webhook WebhookConfig `yaml:"webhook"`
}

type DiscordConfig struct {
	URL         string `yaml:"url"`
	Username    string `yaml:"username"`
	MinSeverity string `yaml:"min_severity"`

	BatchWindow time.Duration   `yaml:"batch_window"`
	minSev      events.Severity `yaml:"-"`
}

type NtfyConfig struct {
	URL         string          `yaml:"url"`
	Topic       string          `yaml:"topic"`
	Token       string          `yaml:"token"`
	MinSeverity string          `yaml:"min_severity"`
	minSev      events.Severity `yaml:"-"`
}

type WebhookConfig struct {
	URL         string          `yaml:"url"`
	Secret      string          `yaml:"secret"`
	MinSeverity string          `yaml:"min_severity"`
	minSev      events.Severity `yaml:"-"`
}

type RuleConfig struct {
	ID        string `yaml:"id"`
	Category  string `yaml:"category"` // empty matches any
	Target    string `yaml:"target"`   // process | path | line | any
	Pattern   string `yaml:"pattern"`
	Severity  string `yaml:"severity"`
	Title     string `yaml:"title"`
	Technique string `yaml:"technique"`
}

// MonitorEnabled resolves the on/off tri-state (nil = default on).
func (c *Config) MonitorEnabled(name string) bool {
	if c.Monitors == nil {
		return true
	}
	v, ok := c.Monitors[name]
	if !ok || v == nil {
		return true
	}
	return *v
}

// LogAllProcessEvents reports whether raw exec events stream to stdout.
func (c *Config) LogAllProcessEvents() bool {
	return c.LogProcessEvents == nil || *c.LogProcessEvents
}

func (d *DiscordConfig) Min() events.Severity { return d.minSev }
func (n *NtfyConfig) Min() events.Severity    { return n.minSev }
func (w *WebhookConfig) Min() events.Severity { return w.minSev }

// Load reads the config at path, applies defaults, and validates.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.ApplyDefaults(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Default returns a config with built-in defaults and no file.
func Default() (*Config, error) {
	cfg := &Config{}
	if err := cfg.ApplyDefaults(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ApplyDefaults fills unset fields and validates severity strings.
func (c *Config) ApplyDefaults() error {
	if c.PollInterval <= 0 {
		c.PollInterval = 250 * time.Millisecond
	}
	if c.SweepTime <= 0 {
		c.SweepTime = 5 * time.Minute
	}
	if c.StateDir == "" {
		if runtime.GOOS == "windows" {
			c.StateDir = `C:\ProgramData\elmer`
		} else {
			c.StateDir = "/var/lib/elmer"
		}
	}
	if len(c.InternalCIDR) == 0 {
		c.InternalCIDR = []string{
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
			"127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10", "fd00::/8",
		}
	}
	if c.DedupeCool <= 0 {
		c.DedupeCool = 60 * time.Second
	}
	if c.Heartbeat == 0 {
		c.Heartbeat = 5 * time.Minute
	}
	// Stream all execs by default: blue teamers asked for "monitor everything".
	if c.LogProcessEvents == nil {
		on := true
		c.LogProcessEvents = &on
	}
	if c.Alerts.Discord.Username == "" {
		c.Alerts.Discord.Username = "elmer"
	}
	if c.Alerts.Discord.BatchWindow == 0 {
		c.Alerts.Discord.BatchWindow = 5 * time.Second
	}
	if c.Alerts.Ntfy.URL == "" {
		c.Alerts.Ntfy.URL = "https://ntfy.sh"
	}
	if len(c.SuspiciousPorts) == 0 {
		c.SuspiciousPorts = []int{4444, 5555, 1337, 31337, 9001, 9002, 8000, 8081}
	}
	if len(c.KnownBadFiles) == 0 {
		c.KnownBadFiles = []string{
			"chisel", "frpc", "frps", "iodine", "dnscat2", "hydra",
			"medusa", "mimikatz", "rubeus", "seatbelt", "winpeas", "linpeas",
			"pspy", "socat", "ncat", "nc64", "plink", "hak5", "empire",
			"cobalt", "sliver", "meterpreter",
		}
	}
	if c.BruteForceWindow <= 0 {
		c.BruteForceWindow = 2 * time.Minute
	}
	if c.BruteFireCount <= 0 {
		c.BruteFireCount = 5
	}
	if c.BruteForceHighCnt <= 0 {
		c.BruteForceHighCnt = 20
	}
	if c.FIM.Paths == nil {
		c.FIM.Paths = DefaultFIMPaths()
	}
	c.FIM.Paths = append(c.FIM.Paths, c.FIM.ExtraPaths...)

	var err error
	if c.Alerts.Discord.minSev, err = sevOr(c.Alerts.Discord.MinSeverity, events.High); err != nil {
		return err
	}
	if c.Alerts.Ntfy.minSev, err = sevOr(c.Alerts.Ntfy.MinSeverity, events.High); err != nil {
		return err
	}
	if c.Alerts.Webhook.minSev, err = sevOr(c.Alerts.Webhook.MinSeverity, events.Medium); err != nil {
		return err
	}
	return nil
}

func sevOr(s string, def events.Severity) (events.Severity, error) {
	if s == "" {
		return def, nil
	}
	return events.ParseSeverity(s)
}

// DefaultFIMPaths returns the platform default file-integrity watch set.
func DefaultFIMPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\Windows\System32\drivers\etc\`,
			`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\`,
			`C:\Windows\Tasks\`,
			`C:\Windows\System32\GroupPolicy\Machine\Scripts\`,
		}
	}
	return []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/group",
		"/etc/sudoers",
		"/etc/sudoers.d/",
		"/etc/ssh/sshd_config",
		"/etc/ssh/sshd_config.d/",
		"/root/.ssh/",
		"/root/.bashrc",
		"/root/.profile",
		"/home/*/.ssh/",
		"/home/*", // top level: .bashrc, .profile, dropped binaries
		"/etc/profile.d/",
		"/etc/crontab",
		"/etc/cron.d/",
		"/var/spool/cron/",
		"/etc/systemd/system/",
		"/usr/lib/systemd/system/",
		"/etc/rc.local",
		"/etc/hosts",
		"/etc/resolv.conf",
		"/etc/ld.so.preload",
		"/usr/bin",
		"/usr/sbin",
		"/usr/local/bin/",
		"/opt/",
		"/tmp",
		"/dev/shm",
		"/var/tmp",
	}
}

// Discover finds the config file: explicit path, $ELMER_CONFIG, ./elmer.yaml,
// then /etc/elmer/elmer.yaml (or %ProgramData%\elmer\elmer.yaml).
func Discover() string {
	candidates := []string{}
	if p := os.Getenv("ELMER_CONFIG"); p != "" {
		candidates = append(candidates, p)
	}
	candidates = append(candidates, "elmer.yaml")
	if runtime.GOOS == "windows" {
		candidates = append(candidates, `C:\ProgramData\elmer\elmer.yaml`)
	} else {
		candidates = append(candidates, "/etc/elmer/elmer.yaml")
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// StatePath joins a filename under the state dir, creating the dir.
func (c *Config) StatePath(name string) (string, error) {
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(c.StateDir, name), nil
}
