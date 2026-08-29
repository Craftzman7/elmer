//go:build !linux && !windows

package app

import (
	"context"
	"fmt"

	"elmer/internal/config"
	"elmer/internal/events"
	"elmer/internal/monitors"
)

// buildMonitors on unsupported platforms returns nothing: elmer monitors
// Linux and Windows hosts.
func buildMonitors(ctx context.Context, cfg *config.Config, out chan<- events.Event) []monitors.Monitor {
	return nil
}

func Harden(cfg *config.Config) error {
	return fmt.Errorf("elmer monitors Linux and Windows hosts only")
}

func Audit(cfg *config.Config, writeBaseline bool) error {
	return fmt.Errorf("elmer monitors Linux and Windows hosts only")
}
