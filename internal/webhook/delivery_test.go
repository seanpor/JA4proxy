// Package webhook provides HMAC-signed ECS payload delivery to configured
// webhook endpoints, with retry and dead-letter queue support.
// These tests verify Dispatcher behaviour against a mock HTTP server and
// an in-process miniredis instance.
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// newTestDispatcher creates a Dispatcher wired to a miniredis instance.
// The caller is responsible for closing mr.
func newTestDispatcher(t *testing.T, cfg DispatcherConfig) (*Dispatcher, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	d, err := NewDispatcher(cfg, rc, log)
	if err != nil {
		mr.Close()
		t.Fatalf("NewDispatcher: %v", err)
	}
	return d, mr
}

// computeExpectedSignature returns the expected HMAC-SHA256 hex signature for
// the given payload and secret, using the same algorithm the Dispatcher must use.
func computeExpectedSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// ── basic delivery ────────────────────────────────────────────────────────────

func TestDispatcher_SuccessfulDelivery_PostsToURL(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: "test-secret", Events: []string{"block"}},
		},
		StreamKey:     "events:connection",
		RetryAttempts: 1,
		RetryBackoff:  10 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{
		ID:        "evt-001",
		EventType: "block",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      map[string]interface{}{"source.ip": "10.0.0.1", "event.action": "block"},
	}
	if err := d.Deliver(event); err != nil {
		t.Fatalf("Deliver returned error: %v", err)
	}

	if len(received) == 0 {
		t.Fatal("expected HTTP server to receive a POST body, got nothing")
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("received body is not valid JSON: %v\nraw: %s", err, received)
	}
}

func TestDispatcher_SuccessfulDelivery_ContentTypeJSON(t *testing.T) {
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: "s3cr3t", Events: []string{"block"}},
		},
		StreamKey:     "events:connection",
		RetryAttempts: 1,
		RetryBackoff:  10 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{EventType: "block", ID: "001", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if err := d.Deliver(event); err != nil {
		t.Fatalf("Deliver error: %v", err)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want 'application/json'", gotContentType)
	}
}

// ── HMAC signature ────────────────────────────────────────────────────────────

// TestDispatcher_HMACSignature_Present removed — fully subsumed by
// TestDispatcher_HMACSignature_Correct which checks presence AND correctness.

func TestDispatcher_HMACSignature_Correct(t *testing.T) {
	const secret = "webhook-secret-key"
	var gotSignature string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSignature = r.Header.Get("X-JA4Proxy-Signature")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: secret, Events: []string{"block"}},
		},
		StreamKey:     "events:connection",
		RetryAttempts: 1,
		RetryBackoff:  10 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{
		EventType: "block",
		ID:        "sig-test-001",
		Timestamp: "2026-04-07T12:00:00Z",
		Data:      map[string]interface{}{"source.ip": "1.2.3.4"},
	}
	if err := d.Deliver(event); err != nil {
		t.Fatalf("Deliver error: %v", err)
	}

	// The HMAC is computed over the payload WITHOUT the signature field.
	// Parse the received body, remove the signature key, re-marshal to get
	// the canonical body that was signed, then verify.
	var parsedBody map[string]interface{}
	if err := json.Unmarshal(gotBody, &parsedBody); err != nil {
		t.Fatalf("received body is not valid JSON: %v\nraw: %s", err, gotBody)
	}
	delete(parsedBody, "signature")
	bodyForHMAC, err := json.Marshal(parsedBody)
	if err != nil {
		t.Fatalf("re-marshal body without signature: %v", err)
	}
	expected := computeExpectedSignature(secret, bodyForHMAC)
	if gotSignature != expected {
		t.Errorf("HMAC mismatch:\ngot:  %s\nwant: %s\nbody used for HMAC: %s", gotSignature, expected, bodyForHMAC)
	}
}

// ── retry on non-2xx ─────────────────────────────────────────────────────────

func TestDispatcher_RetryOn503_ThreeAttempts(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&callCount, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: "s", Events: []string{"block"}},
		},
		StreamKey:     "events:connection",
		RetryAttempts: 3,
		RetryBackoff:  5 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{EventType: "block", ID: "retry-001", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if err := d.Deliver(event); err != nil {
		t.Fatalf("Deliver should succeed after retries, got error: %v", err)
	}
	if atomic.LoadInt32(&callCount) != 3 {
		t.Errorf("expected exactly 3 HTTP calls (2 failures + 1 success), got %d", callCount)
	}
}

func TestDispatcher_RetryUsesExponentialBackoff(t *testing.T) {
	// This test injects a sleepFn to avoid wall-clock timing flakiness.
	// It records durations passed to sleepFn and asserts each successive call
	// receives a strictly longer duration than the previous one.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	var sleepDurations []time.Duration
	sleepFn := func(d time.Duration) {
		sleepDurations = append(sleepDurations, d)
	}

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: "s", Events: []string{"block"}},
		},
		StreamKey:     "events:connection",
		RetryAttempts: 3,
		RetryBackoff:  20 * time.Millisecond,
		SleepFn:       sleepFn,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{EventType: "block", ID: "backoff-001", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	d.Deliver(event) //nolint:errcheck

	// With 3 attempts, there should be 2 inter-attempt sleeps.
	if len(sleepDurations) < 2 {
		t.Fatalf("expected ≥2 sleepFn calls for 3 retry attempts, got %d", len(sleepDurations))
	}
	for i := 1; i < len(sleepDurations); i++ {
		if sleepDurations[i] <= sleepDurations[i-1] {
			t.Errorf("backoff should grow: sleep[%d] (%v) must be > sleep[%d] (%v)",
				i, sleepDurations[i], i-1, sleepDurations[i-1])
		}
	}
}

// ── dead-letter queue ─────────────────────────────────────────────────────────

func TestDispatcher_DLQ_WrittenAfterExhaustedRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: "s", Events: []string{"ban"}},
		},
		StreamKey:     "events:connection",
		DLQStreamKey:  "webhooks:dlq",
		RetryAttempts: 2,
		RetryBackoff:  5 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{
		EventType: "ban",
		ID:        "dlq-test-001",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      map[string]interface{}{"source.ip": "10.1.2.3"},
	}
	// We expect an error returned since all retries failed
	d.Deliver(event) //nolint:errcheck

	// The event should have been written to the DLQ stream.
	// Use a real Redis client to inspect the miniredis instance.
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rc.Close()
	dlqLen, err := rc.XLen(context.Background(), "webhooks:dlq").Result()
	if err != nil {
		t.Fatalf("could not read DLQ stream length from miniredis: %v", err)
	}
	if dlqLen == 0 {
		t.Error("DLQ stream 'webhooks:dlq' should have 1 entry after exhausted retries, got 0")
	}
}

func TestDispatcher_DLQ_ContainsOriginalEventData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: "s", Events: []string{"block"}},
		},
		StreamKey:     "events:connection",
		DLQStreamKey:  "webhooks:dlq",
		RetryAttempts: 1,
		RetryBackoff:  5 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{
		EventType: "block",
		ID:        "dlq-data-001",
		Timestamp: "2026-04-07T00:00:00Z",
		Data:      map[string]interface{}{"source.ip": "5.6.7.8"},
	}
	d.Deliver(event) //nolint:errcheck

	// Read from DLQ and verify the original event payload is in the "payload" field.
	// If the implementation uses a different field name, this test must fail loudly
	// so the discrepancy is immediately visible — no silent fallback searching.
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rc.Close()
	entries, err := rc.XRange(context.Background(), "webhooks:dlq", "-", "+").Result()
	if err != nil {
		t.Fatalf("XRange on DLQ: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("DLQ is empty after failed delivery")
	}
	rawPayload, ok := entries[0].Values["payload"]
	if !ok {
		t.Fatalf("DLQ entry missing 'payload' field; got fields: %v", entries[0].Values)
	}
	rawPayloadStr, ok := rawPayload.(string)
	if !ok {
		t.Fatalf("DLQ 'payload' field is not a string, got %T", rawPayload)
	}
	// payload should be JSON that contains the original event ID
	var payloadMap map[string]interface{}
	if err := json.Unmarshal([]byte(rawPayloadStr), &payloadMap); err != nil {
		t.Fatalf("DLQ 'payload' field is not valid JSON: %v\nraw: %q", err, rawPayloadStr)
	}
	if payloadMap["id"] != "dlq-data-001" {
		t.Errorf("DLQ payload.id = %v, want 'dlq-data-001'", payloadMap["id"])
	}
}

// ── event type filtering ──────────────────────────────────────────────────────

func TestDispatcher_EventFilter_DeliversBanEvent(t *testing.T) {
	var delivered bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: "s", Events: []string{"block", "ban"}},
		},
		StreamKey:     "events:connection",
		RetryAttempts: 1,
		RetryBackoff:  5 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{EventType: "ban", ID: "filter-001", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if err := d.Deliver(event); err != nil {
		t.Fatalf("Deliver ban event error: %v", err)
	}
	if !delivered {
		t.Error("ban event should have been delivered (it matches the filter)")
	}
}

func TestDispatcher_EventFilter_SkipsFlaggedEvent(t *testing.T) {
	var delivered bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: "s", Events: []string{"block", "ban"}},
		},
		StreamKey:     "events:connection",
		RetryAttempts: 1,
		RetryBackoff:  5 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{EventType: "flagged", ID: "filter-002", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	// Should return nil (silently dropped, not an error)
	if err := d.Deliver(event); err != nil {
		t.Fatalf("Deliver of filtered event should not error, got: %v", err)
	}
	if delivered {
		t.Error("flagged event should NOT have been delivered (not in filter list)")
	}
}

func TestDispatcher_EventFilter_AllowsAllWhenEventsListEmpty(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: "s", Events: nil}, // empty = deliver all
		},
		StreamKey:     "events:connection",
		RetryAttempts: 1,
		RetryBackoff:  5 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	for _, evType := range []string{"allow", "flagged", "block", "ban"} {
		event := WebhookEvent{EventType: evType, ID: "all-" + evType, Timestamp: time.Now().UTC().Format(time.RFC3339)}
		d.Deliver(event) //nolint:errcheck
	}
	if atomic.LoadInt32(&callCount) != 4 {
		t.Errorf("expected all 4 events to be delivered when filter is empty, got %d", callCount)
	}
}

// ── payload structure ─────────────────────────────────────────────────────────

func TestDispatcher_PayloadStructure(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: "payload-secret", Events: []string{"block"}},
		},
		StreamKey:     "events:connection",
		RetryAttempts: 1,
		RetryBackoff:  5 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{
		EventType: "block",
		ID:        "struct-001",
		Timestamp: "2026-04-07T15:00:00Z",
		Data:      map[string]interface{}{"source.ip": "9.9.9.9", "event.action": "block"},
	}
	if err := d.Deliver(event); err != nil {
		t.Fatalf("Deliver error: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("payload is not valid JSON: %v\nraw: %s", err, gotBody)
	}

	requiredTopLevelFields := []string{"id", "timestamp", "event_type", "signature", "data"}
	for _, field := range requiredTopLevelFields {
		if _, ok := payload[field]; !ok {
			t.Errorf("payload missing required field %q\npayload: %v", field, payload)
		}
	}

	if payload["id"] != "struct-001" {
		t.Errorf("payload.id = %v, want 'struct-001'", payload["id"])
	}
	if payload["event_type"] != "block" {
		t.Errorf("payload.event_type = %v, want 'block'", payload["event_type"])
	}
	if payload["timestamp"] != "2026-04-07T15:00:00Z" {
		t.Errorf("payload.timestamp = %v, want '2026-04-07T15:00:00Z'", payload["timestamp"])
	}
	data, ok := payload["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("payload.data should be an object, got %T", payload["data"])
	}
	if data["source.ip"] != "9.9.9.9" {
		t.Errorf("payload.data.source.ip = %v, want '9.9.9.9'", data["source.ip"])
	}
}

func TestDispatcher_SignatureInPayloadMatchesHeader(t *testing.T) {
	const secret = "cross-check-secret"
	var gotHeader, gotBodySig string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-JA4Proxy-Signature")
		body, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("handler received non-JSON body: %v\nraw: %s", err, body)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if sig, ok := payload["signature"].(string); ok {
			gotBodySig = sig
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: secret, Events: []string{"block"}},
		},
		StreamKey:     "events:connection",
		RetryAttempts: 1,
		RetryBackoff:  5 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{EventType: "block", ID: "cross-001", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if err := d.Deliver(event); err != nil {
		t.Fatalf("Deliver error: %v", err)
	}
	if gotHeader == "" {
		t.Fatal("X-JA4Proxy-Signature header was empty")
	}
	if gotBodySig == "" {
		t.Fatal("payload.signature was empty")
	}
	if gotHeader != gotBodySig {
		t.Errorf("header signature %q != payload signature %q", gotHeader, gotBodySig)
	}
}

// ── multiple endpoints ────────────────────────────────────────────────────────

func TestDispatcher_MultipleEndpoints_BothReceive(t *testing.T) {
	var count1, count2 int32
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count1, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count2, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv2.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv1.URL, Secret: "s1", Events: []string{"ban"}},
			{URL: srv2.URL, Secret: "s2", Events: []string{"ban"}},
		},
		StreamKey:     "events:connection",
		RetryAttempts: 1,
		RetryBackoff:  5 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{EventType: "ban", ID: "multi-001", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if err := d.Deliver(event); err != nil {
		t.Fatalf("Deliver error: %v", err)
	}
	if atomic.LoadInt32(&count1) != 1 {
		t.Errorf("endpoint 1 should have received 1 delivery, got %d", count1)
	}
	if atomic.LoadInt32(&count2) != 1 {
		t.Errorf("endpoint 2 should have received 1 delivery, got %d", count2)
	}
}

// ── context cancellation ──────────────────────────────────────────────────────

func TestDispatcher_RespectsCancelledContext(t *testing.T) {
	// Start a dispatcher's run loop in a goroutine, cancel the context, and
	// assert the goroutine exits within 1 second.
	cfg := DispatcherConfig{
		Endpoints:     []WebhookEndpoint{},
		StreamKey:     "events:connection",
		RetryAttempts: 1,
		RetryBackoff:  5 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.Run(ctx) //nolint:errcheck
	}()

	cancel()

	select {
	case <-done:
		// goroutine exited cleanly
	case <-time.After(1 * time.Second):
		t.Error("dispatcher Run goroutine did not exit within 1 second after context cancellation")
	}
}

// ── Redis Stream integration ──────────────────────────────────────────────────

func TestDispatcher_ReadsFromRedisStream(t *testing.T) {
	// Publish an event to the Redis Stream before the dispatcher starts,
	// then start the dispatcher run loop and verify the mock HTTP server
	// receives the event within a short timeout.
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: "stream-secret", Events: nil}, // nil = deliver all
		},
		StreamKey:     "events:connection",
		RetryAttempts: 1,
		RetryBackoff:  5 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	// XADD an event to the stream before starting the run loop.
	event := WebhookEvent{
		EventType: "block",
		ID:        "stream-test-001",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      map[string]interface{}{"source.ip": "192.0.2.1"},
	}
	eventJSON, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal event: %v", err)
	}
	mr.XAdd("events:connection", "*", []string{"event", string(eventJSON)})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		d.Run(ctx) //nolint:errcheck
	}()

	// The dispatcher should pick up the event and POST it within 500ms.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if received.Load() >= 1 {
			return // success
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("mock HTTP server did not receive the streamed event within 500ms (received %d)", received.Load())
}

// ── timeout on slow endpoint ──────────────────────────────────────────────────

func TestDispatcher_TimeoutOnSlowEndpoint(t *testing.T) {
	// The mock server deliberately sleeps longer than the configured timeout.
	// The dispatcher must return a timeout error rather than hanging.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: "s", Events: []string{"block"}},
		},
		StreamKey:      "events:connection",
		RetryAttempts:  1,
		RetryBackoff:   5 * time.Millisecond,
		TimeoutSeconds: 0.1, // 100ms — shorter than the server's 200ms sleep
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{EventType: "block", ID: "timeout-001", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	err := d.Deliver(event)
	if err == nil {
		t.Error("Deliver should return a timeout error when endpoint is slower than TimeoutSeconds")
	}
}

// ── per-endpoint retry config ─────────────────────────────────────────────────

// TestDispatcher_PerEndpointRetryConfig verifies that each endpoint uses its
// own RetryAttempts value rather than the global DispatcherConfig default.
// Two endpoints are configured: one with 2 retry attempts, one with 4.
// Both point to a server that always returns 503. We count HTTP hits per
// endpoint using atomic counters and assert the expected hit counts.
func TestDispatcher_PerEndpointRetryConfig(t *testing.T) {
	var hits1, hits2 atomic.Int32

	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits1.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits2.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv2.Close()

	noSleep := func(time.Duration) {} // instant retries for test speed

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{
				ID:            "ep1",
				URL:           srv1.URL,
				Secret:        "s1",
				RetryAttempts: 2, // override global
			},
			{
				ID:            "ep2",
				URL:           srv2.URL,
				Secret:        "s2",
				RetryAttempts: 4, // override global
			},
		},
		StreamKey:     "events:connection",
		RetryAttempts: 10, // global default — must NOT apply when per-endpoint is set
		RetryBackoff:  time.Millisecond,
		SleepFn:       noSleep,
	}

	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{
		ID:        "per-ep-001",
		EventType: "block",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      map[string]interface{}{"source.ip": "10.0.0.1"},
	}

	_ = d.Deliver(event) // expected to fail; we care about attempt counts

	if got := hits1.Load(); got != 2 {
		t.Errorf("endpoint 1: expected 2 attempts (RetryAttempts=2), got %d", got)
	}
	if got := hits2.Load(); got != 4 {
		t.Errorf("endpoint 2: expected 4 attempts (RetryAttempts=4), got %d", got)
	}
}
