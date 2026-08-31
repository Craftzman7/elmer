// Package events defines the event model shared by all monitors, the
// detection engine, and the alert dispatchers.
package events

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Severity ranks an event's importance. Order matters: comparisons use it.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "UNKNOWN"
	}
	return severityNames[s]
}

// ParseSeverity accepts the lowercase names used in the YAML config.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return Info, nil
	case "low":
		return Low, nil
	case "medium", "med":
		return Medium, nil
	case "high":
		return High, nil
	case "critical", "crit":
		return Critical, nil
	}
	return Info, fmt.Errorf("invalid severity %q", s)
}

// ANSI color per severity.
func (s Severity) Color() string {
	switch s {
	case Critical:
		return "\x1b[1;97;41m" // bold white on red
	case High:
		return "\x1b[1;31m" // bold red
	case Medium:
		return "\x1b[33m" // yellow
	case Low:
		return "\x1b[34m" // blue
	default:
		return "\x1b[2m" // dim
	}
}

const ColorReset = "\x1b[0m"

// Categories.
const (
	CatProcess     = "process"
	CatAuth        = "auth"
	CatFile        = "file"
	CatNetwork     = "network"
	CatPersistence = "persistence"
	CatAudit       = "audit"
	CatElmer       = "elmer"
)

// Event is a single observation from a monitor or a finding from the
// detection engine.
type Event struct {
	Time      time.Time         `json:"time"`
	Severity  Severity          `json:"severity"`
	Category  string            `json:"category"`
	Title     string            `json:"title"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
	Technique string            `json:"technique,omitempty"`
	Host      string            `json:"host,omitempty"`
	// Key is the dedupe identity. If empty, dedupe uses Title+Category.
	Key string `json:"-"`
}

// With sets a field and returns the event for chaining.
func (e *Event) With(k, v string) *Event {
	if e.Fields == nil {
		e.Fields = map[string]string{}
	}
	e.Fields[k] = v
	return e
}

func (e *Event) Field(k string) string {
	if e.Fields == nil {
		return ""
	}
	return e.Fields[k]
}

// Summary renders the canonical one-line form used by the stdout dispatcher.
func (e *Event) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %-8s %-11s %s", e.Time.Format("15:04:05"),
		e.Severity, e.Category, e.Title)
	if e.Message != "" {
		b.WriteString(": ")
		b.WriteString(e.Message)
	}
	return b.String()
}

// Flat returns a merged map of Fields plus scalar members, useful for JSON
// NDJSON output and webhook payloads.
func (e *Event) Flat() map[string]any {
	m := map[string]any{
		"time":     e.Time.UTC().Format(time.RFC3339Nano),
		"severity": e.Severity.String(),
		"category": e.Category,
		"title":    e.Title,
		"message":  e.Message,
	}
	if e.Technique != "" {
		m["technique"] = e.Technique
	}
	if e.Host != "" {
		m["host"] = e.Host
	}
	for k, v := range e.Fields {
		m[k] = v
	}
	return m
}

// MarshalJSON renders the flat form (value receiver so it survives boxing).
func (e Event) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.Flat())
}

// Hostname is resolved once and stamped on outgoing events.
var Host = func() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}()
