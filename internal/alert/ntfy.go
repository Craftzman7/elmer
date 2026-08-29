package alert

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"elmer/internal/config"
	"elmer/internal/events"
)

// Ntfy pushes alerts to a phone via ntfy.sh or a self-hosted server.
type Ntfy struct {
	cfg    config.NtfyConfig
	client *http.Client
}

func NewNtfy(cfg config.NtfyConfig) *Ntfy {
	return &Ntfy{cfg: cfg, client: &http.Client{Timeout: 15 * time.Second}}
}

func (n *Ntfy) Name() string { return "ntfy" }

func ntfyPriority(s events.Severity) int {
	switch s {
	case events.Critical:
		return 5
	case events.High:
		return 4
	case events.Medium:
		return 3
	case events.Low:
		return 2
	default:
		return 1
	}
}

func ntfyTags(s events.Severity) string {
	switch s {
	case events.Critical:
		return "rotating_light"
	case events.High:
		return "fire"
	case events.Medium:
		return "warning"
	default:
		return "information_source"
	}
}

func (n *Ntfy) Send(ctx context.Context, ev events.Event) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s", ev.Title, ev.Message)
	if ev.Host != "" {
		fmt.Fprintf(&b, "\nhost: %s", ev.Host)
	}
	for _, k := range []string{"pid", "uid", "user", "src_ip", "dst_ip", "port", "path", "comm", "exe", "cmdline"} {
		if v := ev.Field(k); v != "" {
			fmt.Fprintf(&b, "\n%s: %s", k, v)
		}
	}

	url := strings.TrimRight(n.cfg.URL, "/") + "/" + n.cfg.Topic
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(b.String()))
	if err != nil {
		return err
	}
	req.Header.Set("Title", fmt.Sprintf("[%s] %s @ %s", ev.Severity, ev.Title, events.Host))
	req.Header.Set("Priority", fmt.Sprint(ntfyPriority(ev.Severity)))
	req.Header.Set("Tags", ntfyTags(ev.Severity))
	if n.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+n.cfg.Token)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy: %s", resp.Status)
	}
	return nil
}
