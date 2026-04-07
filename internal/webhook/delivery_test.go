// Package webhook provides HMAC-signed ECS payload delivery to configured
// webhook endpoints, with retry and dead-letter queue support.
// These tests verify Dispatcher behaviour against a mock HTTP server and
// an in-process miniredis instance.
package webhook

import (
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
	d, err := NewDispatcher(cfg, mr.Addr(), log)
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

func TestDispatcher_HMACSignature_Present(t *testing.T) {
	var gotSignature string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSignature = r.Header.Get("X-JA4Proxy-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: "my-secret", Events: []string{"ban"}},
		},
		StreamKey:     "events:connection",
		RetryAttempts: 1,
		RetryBackoff:  10 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{EventType: "ban", ID: "002", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if err := d.Deliver(event); err != nil {
		t.Fatalf("Deliver error: %v", err)
	}
	if gotSignature == "" {
		t.Fatal("X-JA4Proxy-Signature header was not set")
	}
	if len(gotSignature) < 7 || gotSignature[:7] != "sha256=" {
		t.Errorf("X-JA4Proxy-Signature should start with 'sha256=', got %q", gotSignature)
	}
}

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

	expected := computeExpectedSignature(secret, gotBody)
	if gotSignature != expected {
		t.Errorf("HMAC mismatch:\ngot:  %s\nwant: %s\nbody: %s", gotSignature, expected, gotBody)
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
	var callTimes []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callTimes = append(callTimes, time.Now())
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	cfg := DispatcherConfig{
		Endpoints: []WebhookEndpoint{
			{URL: srv.URL, Secret: "s", Events: []string{"block"}},
		},
		StreamKey:     "events:connection",
		RetryAttempts: 3,
		RetryBackoff:  20 * time.Millisecond,
	}
	d, mr := newTestDispatcher(t, cfg)
	defer mr.Close()

	event := WebhookEvent{EventType: "block", ID: "backoff-001", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	// Ignore error; we expect failure after retries
	d.Deliver(event) //nolint:errcheck

	if len(callTimes) < 3 {
		t.Fatalf("expected ≥3 retry calls, got %d", len(callTimes))
	}
	// Verify each gap is larger than the previous (exponential backoff)
	gap1 := callTimes[1].Sub(callTimes[0])
	gap2 := callTimes[2].Sub(callTimes[1])
	// Second gap should be >= first gap (exponential means it grows)
	if gap2 < gap1 {
		t.Errorf("backoff should be exponential: gap2 (%v) should be >= gap1 (%v)", gap2, gap1)
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

	// The event should have been written to the DLQ stream
	dlqLen, err := mr.XLen("webhooks:dlq")
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

	// Read from DLQ and verify the event ID is preserved
	entries, err := mr.XRange("webhooks:dlq", "-", "+")
	if err != nil {
		t.Fatalf("XRange on DLQ: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("DLQ is empty after failed delivery")
	}
	// Each entry is a map of field → value
	entry := entries[0].Fields
	rawPayload, ok := entry["payload"]
	if !ok {
		// Some implementations store as "event_id" or "data"
		rawPayload, ok = entry["event_id"]
		if !ok {
			// Accept any field that contains the event ID
			found := false
			for _, v := range entry {
				if v == "dlq-data-001" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("DLQ entry fields %v do not contain the original event ID 'dlq-data-001'", entry)
			}
			return
		}
	}
	if rawPayload != "dlq-data-001" {
		// payload might be JSON — check if it contains the event ID
		if !jsonContains(rawPayload, "dlq-data-001") {
			t.Errorf("DLQ payload %q does not reference original event ID 'dlq-data-001'", rawPayload)
		}
	}
}

// jsonContains checks if a JSON string contains the given substring anywhere.
func jsonContains(jsonStr, substr string) bool {
	return len(jsonStr) >= len(substr) && (jsonStr == substr || len(jsonStr) > 0 && contains(jsonStr, substr))
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
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
		json.Unmarshal(body, &payload) //nolint:errcheck
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
