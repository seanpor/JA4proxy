// Package webhook provides HMAC-signed ECS payload delivery to configured
// webhook endpoints, with retry and dead-letter queue support.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// WebhookEndpoint describes a single outbound webhook target.
//
// JA4PROXY-2026-0051 — the Secret field is a long-lived HMAC signing key.
// Leaking it to logs, metrics, or crash dumps would let an attacker forge
// webhook payloads to downstream SIEM/SOAR systems. The String, GoString,
// Format, and MarshalJSON methods all redact Secret so the only code path
// that can observe it is the HMAC computation in computeHMAC. Callers
// MUST use fmt.Sprintf / json.Marshal rather than reflect-dumping the
// struct; every logrus WithField("endpoint", ep) call will therefore
// emit the redacted form automatically.
type WebhookEndpoint struct {
	ID     string
	URL    string
	Secret string
	Events []string // nil or empty means deliver all event types
	// Per-endpoint overrides. Zero means "use DispatcherConfig global default".
	RetryAttempts       int
	RetryBackoffSeconds float64
	TimeoutSeconds      float64
}

// redactedSecret is the sentinel emitted in place of Secret whenever a
// WebhookEndpoint is stringified or JSON-marshalled. It is deliberately
// short so it does not balloon log lines, and deliberately distinctive
// so a grep of a log line for "REDACTED" flags an unexpected leak.
const redactedSecret = "[REDACTED]"

// String implements fmt.Stringer. Secret is never included.
func (e WebhookEndpoint) String() string {
	return fmt.Sprintf("WebhookEndpoint{ID:%q URL:%q Secret:%s Events:%v}",
		e.ID, e.URL, redactedSecret, e.Events)
}

// GoString implements fmt.GoStringer so "%#v" does not leak the secret.
func (e WebhookEndpoint) GoString() string {
	return e.String()
}

// Format implements fmt.Formatter. Handles %v, %+v, and %s uniformly so
// that a future logrus field reference cannot accidentally bypass the
// redaction by picking a different verb. Any verb behaves like %s.
func (e WebhookEndpoint) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(e.String()))
}

// MarshalJSON implements json.Marshaler. Secret is replaced with the
// redaction sentinel so json.Marshal(endpoint) cannot leak credentials
// into config dumps, API responses, or structured logs.
func (e WebhookEndpoint) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID                  string   `json:"id"`
		URL                 string   `json:"url"`
		Secret              string   `json:"secret"`
		Events              []string `json:"events"`
		RetryAttempts       int      `json:"retry_attempts,omitempty"`
		RetryBackoffSeconds float64  `json:"retry_backoff_seconds,omitempty"`
		TimeoutSeconds      float64  `json:"timeout_seconds,omitempty"`
	}{
		ID:                  e.ID,
		URL:                 e.URL,
		Secret:              redactedSecret,
		Events:              e.Events,
		RetryAttempts:       e.RetryAttempts,
		RetryBackoffSeconds: e.RetryBackoffSeconds,
		TimeoutSeconds:      e.TimeoutSeconds,
	})
}

// WebhookEvent is a single event to be dispatched.
type WebhookEvent struct {
	ID        string
	Timestamp string
	EventType string
	Data      map[string]interface{}
}

// DispatcherConfig configures a Dispatcher.
type DispatcherConfig struct {
	Endpoints    []WebhookEndpoint
	StreamKey    string
	DLQStreamKey string
	// RetryAttempts is the total number of delivery attempts per endpoint.
	RetryAttempts int
	// RetryBackoff is the initial sleep between retries; doubles each attempt.
	RetryBackoff time.Duration
	// TimeoutSeconds is the HTTP client timeout for each individual attempt.
	TimeoutSeconds float64
	// SleepFn is an injectable sleep function used for retry backoff.
	// Defaults to time.Sleep when nil.
	SleepFn func(time.Duration)
}

// Dispatcher dispatches WebhookEvents to configured endpoints and
// optionally reads from a Redis Stream to drive delivery.
type Dispatcher struct {
	cfg    DispatcherConfig
	rc     redis.UniversalClient
	log    *logrus.Logger
	client *http.Client
	sleep  func(time.Duration)
}

// NewDispatcher creates a new Dispatcher connected to the Redis instance at addr.
func NewDispatcher(cfg DispatcherConfig, addr string, log *logrus.Logger) (*Dispatcher, error) {
	rc := redis.NewClient(&redis.Options{Addr: addr})
	sleepFn := cfg.SleepFn
	if sleepFn == nil {
		sleepFn = time.Sleep
	}
	timeout := 30 * time.Second
	if cfg.TimeoutSeconds > 0 {
		timeout = time.Duration(cfg.TimeoutSeconds * float64(time.Second))
	}
	return &Dispatcher{
		cfg:    cfg,
		rc:     rc,
		log:    log,
		client: &http.Client{Timeout: timeout},
		sleep:  sleepFn,
	}, nil
}

// Close drops references to the configured webhook secrets so the Go
// garbage collector is free to reclaim the underlying memory at its next
// cycle. JA4PROXY-2026-0051 — strings in Go cannot be forcibly zeroed
// (they are immutable and may have been deduplicated), but dropping the
// only references we hold is the strongest guarantee the runtime
// provides without unsafe pointer surgery. Callers should invoke Close
// on shutdown and before dumping process state for debugging.
func (d *Dispatcher) Close() {
	for i := range d.cfg.Endpoints {
		d.cfg.Endpoints[i].Secret = ""
	}
}

// Deliver sends the event to all matching endpoints.
// Returns the last delivery error (if all endpoints fail after retries).
// Returns nil immediately if the event is filtered out by all endpoints.
func (d *Dispatcher) Deliver(event WebhookEvent) error {
	var lastErr error
	for _, ep := range d.cfg.Endpoints {
		if !d.shouldDeliver(ep, event) {
			continue
		}
		if err := d.deliverToEndpoint(ep, event); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// shouldDeliver returns true if the event should be sent to the given endpoint.
func (d *Dispatcher) shouldDeliver(ep WebhookEndpoint, event WebhookEvent) bool {
	if len(ep.Events) == 0 {
		return true
	}
	for _, t := range ep.Events {
		if t == event.EventType {
			return true
		}
	}
	return false
}

// deliverToEndpoint attempts delivery with retries, writing to DLQ on failure.
// Per-endpoint retry/backoff/timeout values override the global DispatcherConfig
// defaults when non-zero.
func (d *Dispatcher) deliverToEndpoint(ep WebhookEndpoint, event WebhookEvent) error {
	// Resolve per-endpoint retry attempts with global fallback.
	maxAttempts := ep.RetryAttempts
	if maxAttempts == 0 {
		maxAttempts = d.cfg.RetryAttempts
	}
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	// Resolve per-endpoint backoff with global fallback.
	backoffSeconds := ep.RetryBackoffSeconds
	if backoffSeconds == 0 {
		backoffSeconds = d.cfg.RetryBackoff.Seconds()
	}
	backoff := time.Duration(backoffSeconds * float64(time.Second))

	// Build a per-call HTTP client so each endpoint can have its own timeout.
	timeout := ep.TimeoutSeconds
	if timeout == 0 {
		timeout = d.cfg.TimeoutSeconds
	}
	if timeout == 0 {
		timeout = 30
	}
	client := &http.Client{Timeout: time.Duration(timeout * float64(time.Second))}

	// Build the payload once so the signature is consistent.
	// We sign the final payload (with signature field set to computed value).
	// Two-pass: first build payload without signature, compute HMAC, then add.
	payloadMap := map[string]interface{}{
		"id":         event.ID,
		"timestamp":  event.Timestamp,
		"event_type": event.EventType,
		"data":       event.Data,
	}
	// Compute HMAC over a stable JSON encoding.
	payloadForHMAC, err := json.Marshal(payloadMap)
	if err != nil {
		return fmt.Errorf("webhook: marshal payload: %w", err)
	}
	sig := computeHMAC(ep.Secret, payloadForHMAC)

	// Add signature to the payload.
	payloadMap["signature"] = sig

	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return fmt.Errorf("webhook: marshal signed payload: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			d.sleep(backoff)
			backoff *= 2
		}
		if err := d.doHTTPPost(client, ep, payloadBytes, sig); err != nil {
			lastErr = err
			if d.log != nil {
				d.log.WithError(err).WithField("attempt", attempt+1).
					Warn("webhook: delivery attempt failed")
			}
			continue
		}
		return nil // success
	}

	// All retries exhausted — write to DLQ.
	if d.cfg.DLQStreamKey != "" {
		dlqPayload, _ := json.Marshal(payloadMap)
		ctx := context.Background()
		d.rc.XAdd(ctx, &redis.XAddArgs{
			Stream: d.cfg.DLQStreamKey,
			Values: map[string]interface{}{"payload": string(dlqPayload)},
		})
	}
	return lastErr
}

// doHTTPPost performs a single HTTP POST attempt using the provided client.
func (d *Dispatcher) doHTTPPost(client *http.Client, ep WebhookEndpoint, payload []byte, sig string) error {
	req, err := http.NewRequest(http.MethodPost, ep.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("webhook: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-JA4Proxy-Signature", sig)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// computeHMAC returns "sha256=" + hex-encoded HMAC-SHA256 of payload with secret.
func computeHMAC(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Run reads events from the configured Redis Stream and delivers them.
// It exits when ctx is cancelled.
func (d *Dispatcher) Run(ctx context.Context) {
	lastID := "0" // start from the oldest unread entry
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		streams, err := d.rc.XRead(ctx, &redis.XReadArgs{
			Streams: []string{d.cfg.StreamKey, lastID},
			Count:   10,
			Block:   200 * time.Millisecond,
		}).Result()
		if err != nil {
			if err == context.Canceled || err == redis.Nil {
				return
			}
			// Transient error — check ctx and retry
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		for _, stream := range streams {
			for _, msg := range stream.Messages {
				lastID = msg.ID
				eventJSON, ok := msg.Values["event"].(string)
				if !ok {
					continue
				}
				var event WebhookEvent
				if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
					continue
				}
				d.Deliver(event) //nolint:errcheck,gosec // fire-and-forget delivery from stream replay
			}
		}
	}
}
