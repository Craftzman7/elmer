// Package monitors defines the Monitor interface implemented by every
// platform telemetry source, plus small shared helpers.
package monitors

import (
	"context"
	"time"

	"elmer/internal/events"
)

// Monitor is one telemetry source. Start blocks until ctx is canceled or a
// fatal error occurs; events flow to out. Start returning nil means a clean
// shutdown.
type Monitor interface {
	Name() string
	Start(ctx context.Context, out chan<- events.Event) error
	// Capabilities lists what this instance actually provides, shown in the
	// startup banner (e.g. "execve+argv tracing" or degraded-mode notes).
	Capabilities() []string
}

// DegradedNote builds the standard "monitor degraded" event.
func DegradedNote(msg string) events.Event {
	return events.Event{
		Time:     time.Now(),
		Severity: events.Low,
		Category: events.CatElmer,
		Title:    "monitor degraded",
		Message:  msg,
		Host:     events.Host,
	}
}
