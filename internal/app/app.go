// Package app wires monitors, the detection engine, and alert dispatchers
// into the elmer pipeline.
package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"elmer/internal/alert"
	"elmer/internal/config"
	"elmer/internal/detect"
	"elmer/internal/events"
	"elmer/internal/monitors"
)

// Options controls a run.
type Options struct {
	ConfigPath string
	JSON       bool
}

// LoadConfig resolves and loads the configuration, applying defaults when
// no file exists.
func LoadConfig(path string) (*config.Config, string, error) {
	if path == "" {
		path = config.Discover()
	}
	if path == "" {
		cfg, err := config.Default()
		return cfg, "(built-in defaults)", err
	}
	cfg, err := config.Load(path)
	return cfg, path, err
}

// Run executes the main pipeline until SIGINT/SIGTERM.
func Run(cfg *config.Config, jsonOut bool, cfgPath string) error {
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	engine, err := detect.NewEngine(cfg)
	if err != nil {
		return fmt.Errorf("detection engine: %w", err)
	}
	alerts := alert.NewManager(cfg, jsonOut)

	evch := make(chan events.Event, 1024)
	ms := buildMonitors(ctx, cfg, evch)

	if !jsonOut {
		banner(cfg, cfgPath, ms, alerts, os.Stderr)
	}

	for _, m := range ms {
		mm := m
		go func() {
			if err := mm.Start(ctx, evch); err != nil {
				fmt.Fprintf(os.Stderr, "[elmer] monitor %s stopped: %v\n", mm.Name(), err)
			}
		}()
	}
	var closers []io.Closer
	for _, m := range ms {
		if c, ok := m.(io.Closer); ok {
			closers = append(closers, c)
		}
	}
	defer func() {
		for _, c := range closers {
			c.Close()
		}
	}()

	go alerts.Run(ctx)

	dedupe := events.NewDedupe(cfg.DedupeCool)
	for {
		select {
		case <-ctx.Done():
			if !jsonOut {
				fmt.Fprintln(os.Stderr, "\n[elmer] shutting down")
			}
			return nil
		case ev := <-evch:
			for _, out := range engine.Evaluate(ev) {
				if dedupe.Suppressed(&out, time.Now()) {
					continue
				}
				alerts.Dispatch(out)
			}
		}
	}
}

func banner(cfg *config.Config, cfgPath string, ms []monitors.Monitor, alerts *alert.Manager, w io.Writer) {
	fmt.Fprintf(w, "elmer — blue team host monitor\n")
	fmt.Fprintf(w, "  host:    %s\n", events.Host)
	fmt.Fprintf(w, "  config:  %s\n", cfgPath)
	fmt.Fprintf(w, "  alerts:  %v\n", alerts.Names())
	fmt.Fprintf(w, "  monitors:\n")
	for _, m := range ms {
		fmt.Fprintf(w, "    %-12s %s\n", m.Name(), strings.Join(m.Capabilities(), ", "))
	}
	fmt.Fprintf(w, "  (no listening sockets; outbound alert connections only)\n")
}

// TestAlerts dispatches a synthetic event through every configured channel.
func TestAlerts(cfg *config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	alerts := alert.NewManager(cfg, false)
	go alerts.Run(ctx)

	alerts.Dispatch(events.Event{
		Time:     time.Now(),
		Severity: events.Critical,
		Category: events.CatElmer,
		Title:    "elmer test alert",
		Message:  "This is a synthetic alert to verify your channels. If you can read this, delivery works.",
		Fields:   map[string]string{"host": events.Host},
		Host:     events.Host,
	})

	// Give dispatchers time to flush (discord batches up to batch_window).
	time.Sleep(cfg.Alerts.Discord.BatchWindow + 5*time.Second)
	return nil
}
