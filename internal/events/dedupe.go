package events

import (
	"sync"
	"time"
)

// Dedupe suppresses repeated alerts sharing the same key within a cooldown
// window, so a persistent C2 connection or a chatty rule does not spam every
// alert channel. Raw Info-level stream events are not deduped.
type Dedupe struct {
	mu       sync.Mutex
	cooldown time.Duration
	last     map[string]time.Time
}

func NewDedupe(cooldown time.Duration) *Dedupe {
	return &Dedupe{cooldown: cooldown, last: map[string]time.Time{}}
}

// Suppressed reports whether an event with this key should be dropped.
// Events without an explicit Key (raw Info stream) always pass through.
// It records the timestamp when it returns false.
func (d *Dedupe) Suppressed(e *Event, now time.Time) bool {
	if e.Key == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.last[e.Key]; ok && now.Sub(t) < d.cooldown {
		return true
	}
	d.last[e.Key] = now
	if len(d.last) > 4096 { // crude prune; competition box lifetimes are short
		d.last = map[string]time.Time{e.Key: now}
	}
	return false
}

// Threshold tracks a sliding-window count per key (e.g. SSH failures per
// source IP) and reports when a count crosses a level. It never decrements a
// level until the window drains, so escalating alerts fire once each.
type Threshold struct {
	mu     sync.Mutex
	window time.Duration
	levels []ThresholdLevel
	series map[string][]time.Time
}

type ThresholdLevel struct {
	Count    int
	Severity Severity
	Title    string
}

func NewThreshold(window time.Duration, levels ...ThresholdLevel) *Threshold {
	return &Threshold{window: window, levels: levels, series: map[string][]time.Time{}}
}

// Hit records one occurrence at now and returns the level whose count was
// just reached, or nil. Hit is called once per occurrence, so the count
// increments by one and each level fires exactly once per window; when the
// window drains, a fresh burst re-crosses and re-fires.
func (t *Threshold) Hit(key string, now time.Time) *ThresholdLevel {
	t.mu.Lock()
	defer t.mu.Unlock()

	times := t.series[key]
	cutoff := now.Add(-t.window)
	kept := times[:0]
	for _, ts := range times {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	t.series[key] = append(kept, now)
	count := len(t.series[key])

	for i := range t.levels {
		if count == t.levels[i].Count {
			return &t.levels[i]
		}
	}
	return nil
}
