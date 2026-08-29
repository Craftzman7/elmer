// Package detect evaluates monitor events against the rule set: regex
// matching, filename blocklists, sanity heuristics, and threshold
// correlation. Monitors assign baseline severities; the engine only
// escalates.
package detect

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"elmer/internal/config"
	"elmer/internal/events"
	"elmer/internal/util"
)

// Rule targets.
const (
	TargetProcess = "process" // exe + " " + cmdline
	TargetPath    = "path"    // file path
	TargetLine    = "line"    // message / log line
	TargetAny     = "any"
)

type Rule struct {
	ID        string
	Title     string
	Technique string
	Category  string
	Target    string
	Pattern   *regexp.Regexp
	Severity  events.Severity
}

// ruleDef is the pre-compiled form used for built-in rule definitions.
type ruleDef struct {
	ID        string
	Title     string
	Technique string
	Category  string
	Target    string
	Pattern   string
	Severity  events.Severity
}

type Engine struct {
	rules     []*Rule
	fileRules []*Rule // compiled from known_bad_filenames
	brute     *events.Threshold
	cfg       *config.Config
	ipc       *util.IPCtx
	suspPorts map[int]bool
}

// NewEngine compiles built-in and config rules.
func NewEngine(cfg *config.Config) (*Engine, error) {
	e := &Engine{cfg: cfg}
	disabled := map[string]bool{}
	for _, id := range cfg.Disabled {
		disabled[id] = true
	}

	for _, def := range builtinRules {
		if disabled[def.ID] {
			continue
		}
		r, err := buildRule(def.ID, def.Title, def.Technique, def.Category,
			def.Target, def.Pattern, def.Severity)
		if err != nil {
			return nil, fmt.Errorf("builtin rule %s: %w", def.ID, err)
		}
		e.rules = append(e.rules, r)
	}

	for _, c := range cfg.Rules {
		if c.Pattern == "" {
			continue
		}
		title := c.Title
		if title == "" {
			title = "custom rule match: " + c.ID
		}
		target := c.Target
		if target == "" {
			target = TargetProcess
		}
		sev, err := events.ParseSeverity(c.Severity)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", c.ID, err)
		}
		r, err := buildRule(c.ID, title, c.Technique, c.Category, target, c.Pattern, sev)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", c.ID, err)
		}
		e.rules = append(e.rules, r)
	}

	// Known attacker tool filenames: anchored basename match against both
	// process exe and file paths, tolerating common extensions/packing.
	for _, name := range cfg.KnownBadFiles {
		re, err := regexp.Compile(`(?i)(^|[\\/])` + regexp.QuoteMeta(name) + `(\.[a-z0-9]{1,5})?$`)
		if err != nil {
			return nil, err
		}
		e.fileRules = append(e.fileRules, &Rule{
			ID:        "badfile-" + name,
			Title:     "Known attacker tool: " + name,
			Target:    TargetAny,
			Pattern:   re,
			Severity:  events.High,
			Technique: "T1587",
		})
	}

	e.brute = events.NewThreshold(cfg.BruteForceWindow,
		events.ThresholdLevel{Count: cfg.BruteFireCount, Severity: events.Medium,
			Title: "SSH brute force suspected"},
		events.ThresholdLevel{Count: cfg.BruteForceHighCnt, Severity: events.High,
			Title: "SSH brute force in progress"},
	)
	// Best effort: a bad CIDR just disables network classification.
	e.ipc, _ = util.NewIPCtx(cfg.InternalCIDR)
	e.suspPorts = map[int]bool{}
	for _, p := range cfg.SuspiciousPorts {
		e.suspPorts[p] = true
	}
	return e, nil
}

func buildRule(id, title, technique, category, target, pattern string, sev events.Severity) (*Rule, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &Rule{
		ID: id, Title: title, Technique: technique, Category: category,
		Target: target, Pattern: re, Severity: sev,
	}, nil
}

// Evaluate returns the events to dispatch: the original (possibly escalated)
// plus any correlation findings. A nil first element drops the event.
func (e *Engine) Evaluate(ev events.Event) []events.Event {
	var out []events.Event

	switch ev.Category {
	case events.CatProcess:
		e.applyRules(&ev, TargetProcess,
			strings.TrimSpace(ev.Field("exe")+" "+ev.Field("cmdline")))
		e.checkWorldWritable(&ev)
	case events.CatFile:
		e.applyRules(&ev, TargetPath, ev.Field("path"))
	case events.CatAuth:
		e.applyRules(&ev, TargetLine, ev.Message)
		out = append(out, e.correlateAuth(&ev)...)
	case events.CatNetwork:
		e.classifyNet(&ev)
	}
	if ev.Severity > events.Info || e.passThrough(ev) {
		out = append(out, ev)
	}
	return out
}

// passThrough decides which Info events still reach dispatchers.
func (e *Engine) passThrough(ev events.Event) bool {
	if ev.Category == events.CatProcess {
		return e.cfg.LogAllProcessEvents()
	}
	return true
}

func (e *Engine) applyRules(ev *events.Event, target, haystack string) {
	if haystack == "" {
		return
	}
	var best *Rule
	for _, r := range e.rules {
		if r.Category != "" && r.Category != ev.Category {
			continue
		}
		if r.Target != TargetAny && r.Target != target {
			continue
		}
		if !r.Pattern.MatchString(haystack) {
			continue
		}
		if best == nil || r.Severity > best.Severity ||
			(r.Severity == best.Severity && r.ID < best.ID) {
			best = r
		}
	}
	for _, r := range e.fileRules {
		if r.Pattern.MatchString(haystack) &&
			(best == nil || r.Severity > best.Severity) {
			best = r
		}
	}
	if best != nil && best.Severity > ev.Severity {
		ev.Title = best.Title
		ev.Severity = best.Severity
		if best.Technique != "" {
			ev.Technique = best.Technique
		}
		if ev.Key == "" {
			ev.Key = best.ID + "/" + haystackKey(haystack)
		}
	}
}

func haystackKey(s string) string {
	if len(s) > 80 {
		return s[:80]
	}
	return s
}

// checkWorldWritable flags root executing binaries from /tmp-style dirs.
func (e *Engine) checkWorldWritable(ev *events.Event) {
	exe := ev.Field("exe")
	uid := ev.Field("uid")
	if exe == "" || (uid != "0" && !strings.HasPrefix(uid, "0 ")) {
		return
	}
	for _, p := range []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"} {
		if strings.HasPrefix(exe, p) {
			if ev.Severity < events.High {
				ev.Severity = events.High
				ev.Title = "root executed binary from world-writable dir"
				ev.Technique = "T1068"
				ev.Key = "wwx/" + exe
			}
			return
		}
	}
}

// correlateAuth runs the brute-force threshold on failed SSH auth events.
func (e *Engine) correlateAuth(ev *events.Event) []events.Event {
	if ev.Field("auth") != "fail" || ev.Field("src_ip") == "" {
		return nil
	}
	lv := e.brute.Hit(ev.Field("src_ip"), ev.Time)
	if lv == nil {
		return nil
	}
	return []events.Event{{
		Time:     ev.Time,
		Severity: lv.Severity,
		Category: events.CatAuth,
		Title:    lv.Title,
		Message:  fmt.Sprintf("%d failed logins from %s within %s (last user: %s)",
			lv.Count, ev.Field("src_ip"), e.cfg.BruteForceWindow, ev.Field("user")),
		Fields:   map[string]string{"src_ip": ev.Field("src_ip")},
		Technique: "T1110",
		Key:      "bruteforce/" + ev.Field("src_ip"),
	}}
}

// classifyNet escalates connect/bind events (from eBPF or the /proc poller)
// based on suspicious ports, external destinations, and root ownership.
func (e *Engine) classifyNet(ev *events.Event) {
	if e.ipc == nil {
		return
	}
	port, _ := strconv.Atoi(ev.Field("port"))
	dst := ev.Field("dst_ip")
	ip := net.ParseIP(dst)
	if ip == nil {
		return
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	external := !e.ipc.Internal(ip)
	root := ev.Field("uid") == "0"

	switch ev.Field("action") {
	case "connect":
		switch {
		case e.suspPorts[port]:
			ev.Severity = events.Critical
			ev.Title = "Connection to suspicious port"
			ev.Technique = "T1571"
			ev.Key = "suspconn/" + dst + "/" + strconv.Itoa(port)
		case external && root:
			ev.Severity = events.High
			ev.Title = "Root process connected to external network"
			ev.Technique = "T1071"
			ev.Key = "extconn/" + dst
		case external:
			ev.Severity = events.Medium
			ev.Title = "Outbound connection to external network"
			ev.Key = "extconn/" + dst
		}
	case "bind":
		if e.suspPorts[port] {
			ev.Severity = events.High
			ev.Title = "Socket bound to suspicious port"
			ev.Technique = "T1571"
			ev.Key = "suspbind/" + strconv.Itoa(port)
		}
	}
}
