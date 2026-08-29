package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"elmer/internal/config"
	"elmer/internal/events"
)

// Discord posts alerts as webhook embeds, batching bursts within a short
// window into one message. Rate limits (429) are honored via Retry-After.
type Discord struct {
	cfg    config.DiscordConfig
	client *http.Client

	mu      sync.Mutex
	pending []events.Event
}

func NewDiscord(cfg config.DiscordConfig) *Discord {
	return &Discord{cfg: cfg, client: &http.Client{Timeout: 15 * time.Second}}
}

func (d *Discord) Name() string { return "discord" }

// Start begins the batching flush loop.
func (d *Discord) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(d.cfg.BatchWindow)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				d.flush()
			}
		}
	}()
}

func (d *Discord) Send(ctx context.Context, ev events.Event) error {
	d.mu.Lock()
	d.pending = append(d.pending, ev)
	d.mu.Unlock()
	return nil
}

func (d *Discord) flush() {
	d.mu.Lock()
	batch := d.pending
	d.pending = nil
	d.mu.Unlock()
	if len(batch) == 0 {
		return
	}

	const maxEmbeds = 10
	for start := 0; start < len(batch); start += maxEmbeds {
		end := start + maxEmbeds
		if end > len(batch) {
			end = len(batch)
		}
		if err := d.post(batch[start:end]); err != nil {
			fmt.Printf("[elmer] discord: %v\n", err)
		}
	}
}

type discordMsg struct {
	Username string         `json:"username,omitempty"`
	Embeds   []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Color       int           `json:"color"`
	Footer      discordFooter `json:"footer"`
	Timestamp   string        `json:"timestamp"`
}

type discordFooter struct {
	Text string `json:"text"`
}

func severityColor(s events.Severity) int {
	switch s {
	case events.Critical:
		return 0xe74c3c
	case events.High:
		return 0xe67e22
	case events.Medium:
		return 0xf1c40f
	case events.Low:
		return 0x3498db
	default:
		return 0x95a5a6
	}
}

func embedFor(ev events.Event) discordEmbed {
	var b strings.Builder
	if ev.Message != "" {
		b.WriteString(ev.Message)
	}
	if ev.Host != "" {
		fmt.Fprintf(&b, "\n**host:** %s", ev.Host)
	}
	for k, v := range ev.Fields {
		fmt.Fprintf(&b, "\n**%s:** %s", k, v)
	}
	desc := b.String()
	if len(desc) > 4000 {
		desc = desc[:3997] + "..."
	}
	return discordEmbed{
		Title:       fmt.Sprintf("[%s] %s", ev.Severity, ev.Title),
		Description: desc,
		Color:       severityColor(ev.Severity),
		Footer:      discordFooter{Text: "elmer" + techniqueSuffix(ev)},
		Timestamp:   ev.Time.UTC().Format(time.RFC3339),
	}
}

func techniqueSuffix(ev events.Event) string {
	if ev.Technique == "" {
		return ""
	}
	return " · " + ev.Technique
}

func (d *Discord) post(batch []events.Event) error {
	msg := discordMsg{Username: d.cfg.Username}
	for _, ev := range batch {
		msg.Embeds = append(msg.Embeds, embedFor(ev))
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	backoff := 2 * time.Second
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequest(http.MethodPost, d.cfg.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := d.client.Do(req)
		if err != nil {
			return err
		}
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			resp.Body.Close()
			return nil
		case resp.StatusCode == http.StatusTooManyRequests:
			after := backoff
			if v := resp.Header.Get("Retry-After"); v != "" {
				if secs, err := strconv.Atoi(v); err == nil {
					after = time.Duration(secs) * time.Second
				}
			}
			resp.Body.Close()
			time.Sleep(after)
			backoff *= 2
			continue
		default:
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return fmt.Errorf("discord webhook: %s: %s", resp.Status, b)
		}
	}
	return fmt.Errorf("discord webhook: still rate limited after retries")
}
