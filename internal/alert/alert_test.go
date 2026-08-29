package alert

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"elmer/internal/config"
	"elmer/internal/events"
)

func testEvent(sev events.Severity) events.Event {
	return events.Event{
		Time:     time.Now(),
		Severity: sev,
		Category: events.CatProcess,
		Title:    "test event",
		Message:  "something happened",
		Fields:   map[string]string{"pid": "42"},
		Host:     "box01",
	}
}

func TestWebhookSignature(t *testing.T) {
	var gotSig, gotBody atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody.Store(string(b))
		gotSig.Store(r.Header.Get("X-Elmer-Signature"))
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := config.WebhookConfig{URL: srv.URL, Secret: "s3cret"}
	wh := NewWebhook(cfg)
	if err := wh.Send(context.Background(), testEvent(events.High)); err != nil {
		t.Fatal(err)
	}

	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write([]byte(gotBody.Load().(string)))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig.Load().(string) != want {
		t.Fatalf("signature %q, want %q", gotSig.Load(), want)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(gotBody.Load().(string)), &decoded); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if decoded["title"] != "test event" || decoded["host"] != "box01" {
		t.Fatalf("unexpected body: %v", decoded)
	}
}

func TestDiscordBatchAnd429(t *testing.T) {
	var mu sync.Mutex
	posts := 0
	embeds := 0
	saw429 := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var msg discordMsg
		json.Unmarshal(b, &msg)
		mu.Lock()
		posts++
		embeds += len(msg.Embeds)
		mu.Unlock()
		if posts == 1 && !saw429 {
			saw429 = true
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := config.DiscordConfig{URL: srv.URL, Username: "elmer", BatchWindow: 30 * time.Millisecond}
	d := NewDiscord(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	for i := 0; i < 5; i++ {
		if err := d.Send(ctx, testEvent(events.High)); err != nil {
			t.Fatal(err)
		}
	}
	// Wait for at least two flush cycles.
	time.Sleep(120 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if posts == 0 || embeds < 5 {
		t.Fatalf("posts=%d embeds=%d, want >=1 posts and >=5 embeds", posts, embeds)
	}
	if !saw429 {
		t.Fatal("429 path never exercised")
	}
}

func TestManagerFiltering(t *testing.T) {
	var mu sync.Mutex
	var received []events.Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var ev map[string]any
		json.Unmarshal(b, &ev)
		mu.Lock()
		received = append(received, events.Event{Title: ev["title"].(string)})
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Alerts.Webhook = config.WebhookConfig{URL: srv.URL, MinSeverity: "high"}
	if err := cfg.ApplyDefaults(); err != nil { // recompute min severity
		t.Fatal(err)
	}

	m := NewManager(cfg, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	m.Dispatch(testEvent(events.Info))   // filtered out
	m.Dispatch(testEvent(events.Medium)) // filtered out
	m.Dispatch(testEvent(events.High))   // delivered
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("delivered %d events, want 1 (severity filtering broken)", len(received))
	}
}

func TestManagerDropOldest(t *testing.T) {
	// A channel that never answers: workers block in Send, queue fills,
	// dispatch keeps going without deadlock.
	blocking := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer blocking.Close()

	cfg, _ := config.Default()
	cfg.Alerts.Webhook = config.WebhookConfig{URL: blocking.URL, MinSeverity: "info"}
	cfg.ApplyDefaults() // recompute min severity

	m := NewManager(cfg, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 600; i++ {
			m.Dispatch(testEvent(events.High))
		}
	}()
	select {
	case <-done:
		// All dispatches returned without blocking: drop-oldest works.
	case <-time.After(5 * time.Second):
		t.Fatal("Dispatch blocked on a wedged channel")
	}
}
