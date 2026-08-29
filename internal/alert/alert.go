// Package alert fans events out to alert channels. Each dispatcher runs in
// its own goroutine with a bounded queue, so a hung webhook can never stall
// the pipeline or starve other channels.
package alert

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"elmer/internal/config"
	"elmer/internal/events"
)

// Dispatcher delivers events to one channel.
type Dispatcher interface {
	Name() string
	Send(ctx context.Context, ev events.Event) error
}

// Starter dispatchers have background work (e.g. heartbeats) started by the
// manager.
type Starter interface {
	Start(ctx context.Context)
}

// Manager fans events out to all dispatchers, filtering by minimum severity
// per channel.
type Manager struct {
	disp []disp
}

type disp struct {
	d       Dispatcher
	min     events.Severity
	queue   chan events.Event
	dropped atomic.Int64
}

func NewManager(cfg *config.Config, jsonOut bool) *Manager {
	m := &Manager{}

	stdout := NewStdout(jsonOut)
	stdout.SetHeartbeat(cfg.Heartbeat)
	m.add(stdout, events.Info)

	if cfg.Alerts.Discord.URL != "" {
		m.add(NewDiscord(cfg.Alerts.Discord), cfg.Alerts.Discord.Min())
	}
	if cfg.Alerts.Ntfy.Topic != "" {
		m.add(NewNtfy(cfg.Alerts.Ntfy), cfg.Alerts.Ntfy.Min())
	}
	if cfg.Alerts.Webhook.URL != "" {
		m.add(NewWebhook(cfg.Alerts.Webhook), cfg.Alerts.Webhook.Min())
	}
	return m
}

func (m *Manager) add(d Dispatcher, min events.Severity) {
	m.disp = append(m.disp, disp{d: d, min: min, queue: make(chan events.Event, 256)})
}

// Names lists active channel names (for the startup banner).
func (m *Manager) Names() []string {
	var out []string
	for i := range m.disp {
		out = append(out, m.disp[i].d.Name())
	}
	return out
}

// Dispatch delivers an event to every channel at or above its min severity.
// It never blocks: full queues drop their oldest event.
func (m *Manager) Dispatch(ev events.Event) {
	for i := range m.disp {
		d := &m.disp[i]
		if ev.Severity < d.min {
			continue
		}
		select {
		case d.queue <- ev:
		default:
			// Drop-oldest keeps freshest alerts flowing.
			select {
			case old := <-d.queue:
				_ = old
				d.dropped.Add(1)
			default:
			}
			select {
			case d.queue <- ev:
			default:
			}
		}
	}
}

// Run starts all workers and blocks until ctx is canceled.
func (m *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := range m.disp {
		d := &m.disp[i]
		if st, ok := d.d.(Starter); ok {
			st.Start(ctx)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.worker(ctx, d)
		}()
	}
	wg.Wait()
}

func (m *Manager) worker(ctx context.Context, d *disp) {
	lastDropNote := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-d.queue:
			sendWithRetry(ctx, d.d, ev)
			// Report drops at most once per 30s per channel.
			if n := d.dropped.Swap(0); n > 0 && time.Since(lastDropNote) > 30*time.Second {
				lastDropNote = time.Now()
				fmt.Fprintf(os.Stderr, "[elmer] %s: dropped %d alerts while backlogged\n",
					d.d.Name(), n)
			}
		}
	}
}

// sendWithRetry retries with exponential backoff; a channel being down never
// wedges the worker permanently.
func sendWithRetry(ctx context.Context, d Dispatcher, ev events.Event) {
	backoff := time.Second
	for attempt := 0; attempt < 3; attempt++ {
		if err := d.Send(ctx, ev); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 5
	}
}
