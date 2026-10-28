package webhook

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"pgregory.net/rapid"
)

// ---------------------------------------------------------------------------
// Native Go Fuzz Targets
// ---------------------------------------------------------------------------

// FuzzIsPrivateIP verifies that isPrivateIP never panics on arbitrary IP strings or byte slices.
func FuzzIsPrivateIP(f *testing.F) {
	seeds := []string{
		"127.0.0.1", "::1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", "240.0.0.1", "8.8.8.8", "1.1.1.1", "2001:4860:4860::8888",
		"0.0.0.0", "255.255.255.255", "invalid-ip", "", "::ffff:127.0.0.1",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, ipStr string) {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			_ = isPrivateIP(ip)
			_ = isReservedIPv4(ip)
		}
	})
}

func newLocalIPv4Server(h http.Handler) *httptest.Server {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	ts := &httptest.Server{
		Listener: l,
		Config:   &http.Server{Handler: h},
	}
	ts.Start()
	return ts
}

// FuzzWebhookEventDelivery verifies that Deliver handles arbitrary event types,
// event IDs, and payload maps without crashing or panicking.
func FuzzWebhookEventDelivery(f *testing.F) {
	f.Add("evt-1", "connection.blocked", "192.168.1.100", "t13d1516h2_8daaf6152771_b186095e22b6")
	f.Add("", "", "", "")
	f.Add("long-id-1234567890", "ip.banned", "2001:db8::1", "")

	nullLogger := logrus.New()
	if !testing.Verbose() {
		nullLogger.SetOutput(&nullWriter{})
	}

	server := newLocalIPv4Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ep := WebhookEndpoint{
		ID:            "ep-fuzz",
		URL:           server.URL,
		Secret:        "test-secret",
		RetryAttempts: 1,
	}

	disp, err := NewDispatcher(DispatcherConfig{
		Endpoints:      []WebhookEndpoint{ep},
		TimeoutSeconds: 1,
	}, nil, nullLogger)
	if err != nil {
		f.Fatalf("NewDispatcher error: %v", err)
	}

	f.Fuzz(func(t *testing.T, id, eventType, clientIP, ja4 string) {
		event := WebhookEvent{
			ID:        id,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: eventType,
			Data: map[string]interface{}{
				"client.ip": clientIP,
				"ja4":       ja4,
			},
		}

		_ = disp.Deliver(event)
	})
}

type nullWriter struct{}

func (nullWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

// ---------------------------------------------------------------------------
// Rapid Property-Based Invariant Tests
// ---------------------------------------------------------------------------

// TestProperty_WebhookEndpointSecretRedaction verifies that under arbitrary string
// serialization (String, GoString, json.Marshal, fmt.Sprintf), the raw secret is never exposed.
func TestProperty_WebhookEndpointSecretRedaction(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		id := rapid.StringMatching(`[a-zA-Z0-9_\-]{1,20}`).Draw(rt, "id")
		url := rapid.StringMatching(`https?://[a-zA-Z0-9.\-]{1,30}/[a-z]{0,10}`).Draw(rt, "url")
		// Draw a distinct, non-empty secret of at least 8 characters
		secret := rapid.StringMatching(`[a-zA-Z0-9!@#$%^&*()_+]{8,32}`).Draw(rt, "secret")

		ep := WebhookEndpoint{
			ID:     id,
			URL:    url,
			Secret: secret,
		}

		str := ep.String()
		gostr := ep.GoString()
		fmtStr := fmt.Sprintf("%v %s %+v %#v", ep, ep, ep, ep)

		jsonBytes, err := json.Marshal(ep)
		if err != nil {
			rt.Fatalf("json.Marshal failed: %v", err)
		}
		jsonStr := string(jsonBytes)

		// Verification 1: Secret must never be in any string representation
		for name, val := range map[string]string{
			"String()":     str,
			"GoString()":   gostr,
			"Sprintf()":    fmtStr,
			"json.Marshal": jsonStr,
		} {
			if strings.Contains(val, secret) {
				rt.Fatalf("%s leaked raw secret %q in: %s", name, secret, val)
			}
			if !strings.Contains(val, redactedSecret) {
				rt.Fatalf("%s does not contain %q in: %s", name, redactedSecret, val)
			}
		}

		// Verification 2: Close drops reference
		disp := &Dispatcher{
			cfg: DispatcherConfig{
				Endpoints: []WebhookEndpoint{ep},
			},
		}
		disp.Close()
		if disp.cfg.Endpoints[0].Secret != "" {
			rt.Fatalf("Dispatcher.Close() did not clear endpoint Secret")
		}
	})
}

// TestProperty_EventFilteringInvariants verifies that endpoints with non-empty event filters
// strictly receive matching event types, while endpoints with empty filters receive all event types.
func TestProperty_EventFilteringInvariants(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		allTypes := []string{"connection.blocked", "ip.banned", "dial.changed", "config.reloaded"}
		numFilters := rapid.IntRange(0, 3).Draw(rt, "numFilters")

		var filterList []string
		for i := 0; i < numFilters; i++ {
			filterList = append(filterList, rapid.SampledFrom(allTypes).Draw(rt, "filter"))
		}

		ep := WebhookEndpoint{
			ID:     "ep-test",
			Events: filterList,
		}

		disp := &Dispatcher{}

		testEvent := WebhookEvent{
			EventType: rapid.SampledFrom(allTypes).Draw(rt, "testEventType"),
		}

		should := disp.shouldDeliver(ep, testEvent)

		if len(filterList) == 0 {
			if !should {
				rt.Fatalf("empty event filter did not deliver event: %s", testEvent.EventType)
			}
		} else {
			inFilter := false
			for _, f := range filterList {
				if f == testEvent.EventType {
					inFilter = true
					break
				}
			}
			if should != inFilter {
				rt.Fatalf("event filtering mismatch: event=%s, filter=%v, expected=%v, got=%v",
					testEvent.EventType, filterList, inFilter, should)
			}
		}
	})
}

// TestProperty_SSRFIPClassification verifies the boundary correctness of isPrivateIP.
func TestProperty_SSRFIPClassification(t *testing.T) {
	// Ensure JA4PROXY_TEST_ALLOW_LOOPBACK is temporarily unset to test real SSRF classification
	orig := os.Getenv("JA4PROXY_TEST_ALLOW_LOOPBACK")
	os.Unsetenv("JA4PROXY_TEST_ALLOW_LOOPBACK")
	defer func() {
		if orig != "" {
			os.Setenv("JA4PROXY_TEST_ALLOW_LOOPBACK", orig)
		}
	}()

	rapid.Check(t, func(rt *rapid.T) {
		// Category 0: Loopback 127.x.x.x
		// Category 1: Private 10.x.x.x, 192.168.x.x, 172.16-31.x.x
		// Category 2: Reserved 240.x.x.x - 255.x.x.x
		// Category 3: Public IPs (e.g. 8.8.8.8, 1.1.1.1, etc.)
		category := rapid.IntRange(0, 3).Draw(rt, "category")

		var ip net.IP
		switch category {
		case 0:
			b := rapid.Byte().Draw(rt, "loopbackOctet")
			ip = net.IPv4(127, 0, 0, b)
		case 1:
			subcat := rapid.IntRange(0, 2).Draw(rt, "privRange")
			switch subcat {
			case 0:
				ip = net.IPv4(10, rapid.Byte().Draw(rt, "b1"), rapid.Byte().Draw(rt, "b2"), rapid.Byte().Draw(rt, "b3"))
			case 1:
				ip = net.IPv4(192, 168, rapid.Byte().Draw(rt, "b2"), rapid.Byte().Draw(rt, "b3"))
			case 2:
				oct2 := byte(rapid.IntRange(16, 31).Draw(rt, "b1"))
				ip = net.IPv4(172, oct2, rapid.Byte().Draw(rt, "b2"), rapid.Byte().Draw(rt, "b3"))
			}
		case 2:
			firstOctet := byte(rapid.IntRange(240, 255).Draw(rt, "reservedOctet"))
			ip = net.IPv4(firstOctet, rapid.Byte().Draw(rt, "b1"), rapid.Byte().Draw(rt, "b2"), rapid.Byte().Draw(rt, "b3"))
		case 3:
			firstOctet := byte(rapid.SampledFrom([]int{8, 9, 20, 93, 104, 142, 151}).Draw(rt, "pubOctet"))
			ip = net.IPv4(firstOctet, rapid.Byte().Draw(rt, "b1"), rapid.Byte().Draw(rt, "b2"), rapid.Byte().Draw(rt, "b3"))
		}

		isPriv := isPrivateIP(ip)
		if category <= 2 && !isPriv {
			rt.Fatalf("expected private/reserved for %s, got false", ip.String())
		}
		if category == 3 && isPriv {
			rt.Fatalf("expected public for %s, got true", ip.String())
		}
	})
}

// ---------------------------------------------------------------------------
// Micro-Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkComputeHMAC(b *testing.B) {
	secret := "secret-key-for-webhook-delivery-benchmark-32b"
	payload := []byte(`{"id":"evt-12345","timestamp":"2026-10-28T22:00:00Z","event_type":"connection.blocked","data":{"client.ip":"198.51.100.42","ja4":"t13d1516h2_8daaf6152771_b186095e22b6"}}`)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sig := computeHMAC(secret, payload)
		if len(sig) == 0 {
			b.Fatal("empty signature")
		}
	}
}

func BenchmarkDeliverEventEndToEnd(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var deliveredCount atomic.Int64
	ep := WebhookEndpoint{
		ID:            "bench-ep",
		URL:           server.URL,
		Secret:        "bench-secret-32-bytes-long-key!",
		RetryAttempts: 1,
	}

	mr, err := miniredis.Run()
	if err != nil {
		b.Fatalf("miniredis error: %v", err)
	}
	defer mr.Close()

	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	nullLog := logrus.New()
	nullLog.SetOutput(nullWriter{})

	disp, err := NewDispatcher(DispatcherConfig{
		Endpoints:      []WebhookEndpoint{ep},
		TimeoutSeconds: 5,
	}, rc, nullLog)
	if err != nil {
		b.Fatalf("NewDispatcher error: %v", err)
	}

	event := WebhookEvent{
		ID:        "evt-bench",
		Timestamp: "2026-10-28T22:00:00Z",
		EventType: "connection.blocked",
		Data: map[string]interface{}{
			"client.ip": "203.0.113.19",
			"ja4":       "t13d1516h2_8daaf6152771_b186095e22b6",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := disp.Deliver(event); err != nil {
			b.Fatalf("Deliver error: %v", err)
		}
		deliveredCount.Add(1)
	}
}
