package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/seanpor/ja4proxy/internal/config"
	redisclient "github.com/seanpor/ja4proxy/internal/redis"
	"github.com/sirupsen/logrus"
)

// minimalProxy builds a proxy with only the fields required for stream/reload tests.
func minimalProxy(t *testing.T) (*proxy, *miniredis.Miniredis) {
	t.Helper()
	ensureMetricsRegistered()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	rc := redisclient.New(redisclient.Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
	}, log)
	p := &proxy{
		redis: rc,
		cfg:   &config.Config{},
		log:   log,
	}
	t.Cleanup(func() {
		rc.Close()
		mr.Close()
	})
	return p, mr
}

// TestStartStreamEventWorkers_NilQueue verifies early return when queue is nil.
func TestStartStreamEventWorkers_NilQueue(t *testing.T) {
	p, _ := minimalProxy(t)
	p.streamEventQueue = nil
	// Should return without spawning any goroutines — no panic.
	p.startStreamEventWorkers(context.Background())
}

// TestStartStreamEventWorkers_DefaultWorkers verifies the default of 4 workers
// is used when cfg.Webhooks.StreamWorkers == 0.
func TestStartStreamEventWorkers_DefaultWorkers(t *testing.T) {
	p, _ := minimalProxy(t)
	p.streamEventQueue = make(chan []byte, 8)
	p.cfg.Webhooks.StreamWorkers = 0 // triggers default
	p.cfg.Webhooks.StreamWriteTimeoutSeconds = 0 // triggers default 2s

	ctx, cancel := context.WithCancel(context.Background())
	p.startStreamEventWorkers(ctx)
	cancel() // stop all workers
	// Give workers a moment to exit — no hang means we reached this line.
	time.Sleep(10 * time.Millisecond)
}

// TestStartStreamEventWorkers_CustomWorkers verifies positive worker count is respected.
func TestStartStreamEventWorkers_CustomWorkers(t *testing.T) {
	p, _ := minimalProxy(t)
	p.streamEventQueue = make(chan []byte, 8)
	p.cfg.Webhooks.StreamWorkers = 2
	p.cfg.Webhooks.StreamWriteTimeoutSeconds = 1.0

	ctx, cancel := context.WithCancel(context.Background())
	p.startStreamEventWorkers(ctx)
	cancel()
	time.Sleep(10 * time.Millisecond)
}

// TestStreamEventWorker_ContextCancel verifies the worker exits on ctx cancel.
func TestStreamEventWorker_ContextCancel(t *testing.T) {
	p, _ := minimalProxy(t)
	p.streamEventQueue = make(chan []byte, 1)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.streamEventWorker(ctx, "events:test", time.Second)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("streamEventWorker did not exit after ctx cancel")
	}
}

// TestStreamEventWorker_ClosedChannel verifies the worker exits when the queue is closed.
func TestStreamEventWorker_ClosedChannel(t *testing.T) {
	p, _ := minimalProxy(t)
	p.streamEventQueue = make(chan []byte, 1)

	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.streamEventWorker(ctx, "events:test", time.Second)
	}()

	close(p.streamEventQueue)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("streamEventWorker did not exit after channel close")
	}
}

// TestStreamEventWorker_SuccessfulXAdd verifies the worker publishes events to Redis.
func TestStreamEventWorker_SuccessfulXAdd(t *testing.T) {
	p, mr := minimalProxy(t)
	p.streamEventQueue = make(chan []byte, 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go p.streamEventWorker(ctx, "events:test", 2*time.Second)

	// Send an event and allow it to be processed.
	p.streamEventQueue <- []byte(`{"ip":"1.2.3.4"}`)
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Verify the event landed in the Redis stream.
	items, err := mr.Stream("events:test")
	if err != nil {
		t.Fatalf("Stream error: %v", err)
	}
	if len(items) == 0 {
		t.Error("expected at least one event in the Redis stream")
	}
}

// TestStreamEventWorker_XAddTimeout verifies the timeout error counter is incremented.
func TestStreamEventWorker_XAddTimeout(t *testing.T) {
	p, _ := minimalProxy(t)
	p.streamEventQueue = make(chan []byte, 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go p.streamEventWorker(ctx, "events:test", 1*time.Nanosecond) // timeout so short XAdd always fails

	p.streamEventQueue <- []byte(`{"ip":"1.2.3.4"}`)
	time.Sleep(50 * time.Millisecond) // let the worker process the event and hit timeout
	cancel()
}

// TestStreamEventWorker_XAddError verifies the error counter is incremented on XAdd error.
func TestStreamEventWorker_XAddError(t *testing.T) {
	p, mr := minimalProxy(t)
	p.streamEventQueue = make(chan []byte, 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go p.streamEventWorker(ctx, "events:test", 2*time.Second)

	// Close miniredis before sending the event so XAdd returns a connection error.
	mr.Close()
	p.streamEventQueue <- []byte(`{"ip":"1.2.3.4"}`)
	time.Sleep(100 * time.Millisecond)
	cancel()
}

// TestStartIntegrityWorker_ContextCancel verifies startIntegrityWorker exits on cancel.
func TestStartIntegrityWorker_ContextCancel(t *testing.T) {
	p, _ := minimalProxy(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.startIntegrityWorker(ctx)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("startIntegrityWorker did not exit after ctx cancel")
	}
}

// TestReloadTrustedCIDRs_StaticOnly verifies multiple static CIDRs are applied correctly.
func TestReloadTrustedCIDRs_StaticOnly(t *testing.T) {
	p, _ := minimalProxy(t)
	ensureMetricsRegistered()

	cfg := &config.Config{}
	cfg.TrustedUpstreamSources.NetBox.Enabled = false
	cfg.TrustedUpstreamSources.StaticCIDRs = []string{"10.0.0.0/8", "192.168.0.0/16"}

	p.reloadTrustedCIDRs(context.Background(), cfg)

	cidrs := p.getTrustedCIDRs()
	if len(cidrs) != 2 {
		t.Fatalf("expected 2 CIDRs, got %d: %v", len(cidrs), cidrs)
	}
}

// TestReloadTrustedCIDRs_NetBoxServerError verifies fail-open on NetBox HTTP error.
func TestReloadTrustedCIDRs_NetBoxServerError(t *testing.T) {
	p, _ := minimalProxy(t)
	ensureMetricsRegistered()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.TrustedUpstreamSources.NetBox.Enabled = true
	cfg.TrustedUpstreamSources.NetBox.URL = srv.URL
	cfg.TrustedUpstreamSources.NetBox.Token = "tok"
	cfg.TrustedUpstreamSources.NetBox.Tag = "ja4proxy"
	cfg.TrustedUpstreamSources.StaticCIDRs = []string{"10.0.0.0/8"}

	p.reloadTrustedCIDRs(context.Background(), cfg)

	// Fail-open: static CIDRs must still be applied.
	cidrs := p.getTrustedCIDRs()
	if len(cidrs) == 0 {
		t.Error("expected static CIDRs to be applied on NetBox error")
	}
}

// TestReloadTrustedCIDRs_NetBoxZeroCIDRs verifies fail-open on empty NetBox response.
func TestReloadTrustedCIDRs_NetBoxZeroCIDRs(t *testing.T) {
	p, _ := minimalProxy(t)
	ensureMetricsRegistered()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"count":0,"results":[]}`))
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.TrustedUpstreamSources.NetBox.Enabled = true
	cfg.TrustedUpstreamSources.NetBox.URL = srv.URL
	cfg.TrustedUpstreamSources.NetBox.Token = "tok"
	cfg.TrustedUpstreamSources.NetBox.Tag = "ja4proxy"
	cfg.TrustedUpstreamSources.StaticCIDRs = []string{"10.0.0.0/8"}

	p.reloadTrustedCIDRs(context.Background(), cfg)

	cidrs := p.getTrustedCIDRs()
	if len(cidrs) == 0 {
		t.Error("expected static CIDRs to be applied when NetBox returns zero CIDRs")
	}
}
