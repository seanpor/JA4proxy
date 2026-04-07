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
type WebhookEndpoint struct {
	ID     string
	URL    string
	Secret string
	Events []string // nil or empty means deliver all event types
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
func (d *Dispatcher) deliverToEndpoint(ep WebhookEndpoint, event WebhookEvent) error {
	maxAttempts := d.cfg.RetryAttempts
	if maxAttempts < 1 {
		maxAttempts = 1
	}

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

	backoff := d.cfg.RetryBackoff
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			d.sleep(backoff)
			backoff *= 2
		}
		if err := d.doHTTPPost(ep, payloadBytes, sig); err != nil {
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

// doHTTPPost performs a single HTTP POST attempt.
func (d *Dispatcher) doHTTPPost(ep WebhookEndpoint, payload []byte, sig string) error {
	req, err := http.NewRequest(http.MethodPost, ep.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("webhook: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-JA4Proxy-Signature", sig)

	resp, err := d.client.Do(req)
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
				d.Deliver(event) //nolint:errcheck
			}
		}
	}
}
