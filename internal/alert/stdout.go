package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"elmer/internal/events"
	"elmer/internal/util"
)

// Stdout prints events to stdout: colored one-liners by default, NDJSON with
// --json for jq piping. It also emits the periodic heartbeat line.
type Stdout struct {
	json      bool
	color     bool
	heartbeat time.Duration
	mu        sync.Mutex
}

func NewStdout(jsonOut bool) *Stdout {
	return &Stdout{json: jsonOut, color: util.ColorsEnabled(os.Stdout)}
}

func (s *Stdout) Name() string { return "stdout" }

func (s *Stdout) SetHeartbeat(d time.Duration) { s.heartbeat = d }

func (s *Stdout) Start(ctx context.Context) {
	if s.heartbeat <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(s.heartbeat)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.line(events.Event{
					Time:     time.Now(),
					Severity: events.Info,
					Category: events.CatElmer,
					Title:    "heartbeat",
					Message:  "elmer is running",
					Host:     events.Host,
				})
			}
		}
	}()
}

func (s *Stdout) Send(_ context.Context, ev events.Event) error {
	s.line(ev)
	return nil
}

func (s *Stdout) line(ev events.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.json {
		b, err := json.Marshal(ev)
		if err != nil {
			return
		}
		fmt.Println(string(b))
		return
	}
	sev := ev.Severity.String()
	if s.color {
		fmt.Printf("%s %s%-8s%s %-9s %s", ev.Time.Format("15:04:05"),
			ev.Severity.Color(), sev, events.ColorReset, ev.Category, ev.Title)
	} else {
		fmt.Printf("%s %-8s %-9s %s", ev.Time.Format("15:04:05"), sev, ev.Category, ev.Title)
	}
	if ev.Message != "" {
		fmt.Printf(": %s", ev.Message)
	}
	// Curated inline fields so one-liners stay actionable.
	var parts []string
	for _, k := range []string{"path", "exe", "cmdline", "dst_ip", "port", "user", "src_ip", "command"} {
		if v := ev.Field(k); v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	if len(parts) > 0 {
		fmt.Printf(" [%s]", strings.Join(parts, " "))
	}
	if ev.Host != "" {
		fmt.Printf(" (%s)", ev.Host)
	}
	fmt.Println()
}
