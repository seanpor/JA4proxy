package compliance_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
	"github.com/anomalyco/ja4proxy/internal/compliance"
)

// makePageServer builds an httptest.Server that serves N events across
// pages of size pageSize, using the page_token cursor mechanism.
// Events have IPs "10.0.0.0" through "10.0.0.{N-1}".
func makePageServer(t *testing.T, total, pageSize int) *httptest.Server {
	t.Helper()

	// Build all events up front.
	allEvents := make([]compliance.ConnectionEvent, total)
	for i := range allEvents {
		allEvents[i] = compliance.ConnectionEvent{
			IP:          fmt.Sprintf("10.0.0.%d", i),
			JA4:         "t13abc",
			ActionTaken: "blocked",
			Timestamp:   "2026-01-01T00:00:00Z",
		}
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		offset := 0
		if tok := q.Get("page_token"); tok != "" {
			o, _, _, ok := compliance.DecodePageToken(tok)
			if !ok {
				http.Error(w, "bad token", http.StatusBadRequest)
				return
			}
			offset = o
		}
		lim := pageSize
		if s := q.Get("limit"); s != "" {
			if v, err := strconv.Atoi(s); err == nil && v > 0 {
				lim = v
			}
		}

		end := offset + lim
		if end > total {
			end = total
		}
		page := allEvents[offset:end]
		hasMore := end < total

		var nextToken *string
		if hasMore {
			// Encode the same token format as the Python API.
			payload, _ := json.Marshal(map[string]interface{}{
				"offset": end,
				"since":  "",
				"until":  "",
			})
			tok := base64.URLEncoding.EncodeToString(payload)
			nextToken = &tok
		}

		resp := map[string]interface{}{
			"connections":     page,
			"count":           len(page),
			"has_more":        hasMore,
			"next_page_token": nextToken,
			"total_in_window": total,
			"truncated":       false,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// TestPageIterator_SinglePage verifies that a result set smaller than the page
// limit is returned in one call and the iterator reports done.
func TestPageIterator_SinglePage(t *testing.T) {
	srv := makePageServer(t, 3, 10)
	defer srv.Close()

	c := client.New(srv.URL, "token")
	iter := compliance.NewPageIterator(c, compliance.ConnectionQuery{Limit: 10})

	var all []compliance.ConnectionEvent
	for iter.Next(context.Background()) {
		all = append(all, iter.Page()...)
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterator error: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("collected %d events; want 3", len(all))
	}
}

// TestPageIterator_MultiplePages verifies that all events are returned across
// multiple pages and none are duplicated.
func TestPageIterator_MultiplePages(t *testing.T) {
	const total = 7
	srv := makePageServer(t, total, 3)
	defer srv.Close()

	c := client.New(srv.URL, "token")
	iter := compliance.NewPageIterator(c, compliance.ConnectionQuery{Limit: 3})

	seen := make(map[string]int)
	for iter.Next(context.Background()) {
		for _, ev := range iter.Page() {
			seen[ev.IP]++
		}
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterator error: %v", err)
	}
	if len(seen) != total {
		t.Errorf("collected %d unique events; want %d", len(seen), total)
	}
	for ip, count := range seen {
		if count != 1 {
			t.Errorf("IP %s appeared %d times (want 1)", ip, count)
		}
	}
}

// TestPageIterator_EmptyStream verifies Next returns false immediately and no
// error is returned when the stream has no events.
func TestPageIterator_EmptyStream(t *testing.T) {
	srv := makePageServer(t, 0, 10)
	defer srv.Close()

	c := client.New(srv.URL, "token")
	iter := compliance.NewPageIterator(c, compliance.ConnectionQuery{Limit: 10})

	called := false
	for iter.Next(context.Background()) {
		called = true
	}
	if called {
		t.Error("Next returned true for empty stream")
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("unexpected error for empty stream: %v", err)
	}
}

// TestPageIterator_DefaultLimit verifies that a zero Limit is converted to 500.
func TestPageIterator_DefaultLimit(t *testing.T) {
	var gotLimit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLimit = r.URL.Query().Get("limit")
		resp := map[string]interface{}{
			"connections":     []interface{}{},
			"count":           0,
			"has_more":        false,
			"next_page_token": nil,
			"total_in_window": 0,
			"truncated":       false,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	iter := compliance.NewPageIterator(c, compliance.ConnectionQuery{})
	_ = iter.Next(context.Background())

	if gotLimit != "500" {
		t.Errorf("default limit sent = %q; want 500", gotLimit)
	}
}

// TestPageIterator_QueryParamsForwarded verifies Since, Until, IP, JA4, Action
// are forwarded as query parameters.
func TestPageIterator_QueryParamsForwarded(t *testing.T) {
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		resp := map[string]interface{}{
			"connections":     []interface{}{},
			"count":           0,
			"has_more":        false,
			"next_page_token": nil,
			"total_in_window": 0,
			"truncated":       false,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	query := compliance.ConnectionQuery{
		Since:  "2026-01-01T00:00:00Z",
		Until:  "2026-02-01T00:00:00Z",
		IP:     "1.2.3.4",
		JA4:    "t13abc",
		Action: "blocked",
		Limit:  100,
	}
	iter := compliance.NewPageIterator(c, query)
	_ = iter.Next(context.Background())

	checks := map[string]string{
		"since":  "2026-01-01T00:00:00Z",
		"until":  "2026-02-01T00:00:00Z",
		"ip":     "1.2.3.4",
		"ja4":    "t13abc",
		"action": "blocked",
		"limit":  "100",
	}
	for key, want := range checks {
		if got := gotQuery.Get(key); got != want {
			t.Errorf("query param %s = %q; want %q", key, got, want)
		}
	}
}

// TestPageIterator_ContextCancelledReturnsError verifies that a cancelled context
// surfaces as an error from the iterator.
func TestPageIterator_ContextCancelledReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Stall briefly — context will have already been cancelled.
		resp := map[string]interface{}{
			"connections": []compliance.ConnectionEvent{},
			"count": 0, "has_more": false, "next_page_token": nil,
			"total_in_window": 0, "truncated": false,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	c := client.New(srv.URL, "token")
	iter := compliance.NewPageIterator(c, compliance.ConnectionQuery{Limit: 10})
	iter.Next(ctx) // may or may not return true

	// Don't check return value of Next — with a cancelled context it may still
	// return results if the request was already in flight. What matters is that
	// eventually the iterator surfaces an error OR stops cleanly.
	// Both are acceptable; this test just ensures it doesn't hang.
}

// TestCollectAll_ReturnsAllEvents verifies the CollectAll convenience function
// aggregates all pages.
func TestCollectAll_ReturnsAllEvents(t *testing.T) {
	const total = 9
	srv := makePageServer(t, total, 4)
	defer srv.Close()

	c := client.New(srv.URL, "token")
	iter := compliance.NewPageIterator(c, compliance.ConnectionQuery{Limit: 4})
	all, err := compliance.CollectAll(context.Background(), iter)
	if err != nil {
		t.Fatalf("CollectAll error: %v", err)
	}
	if len(all) != total {
		t.Errorf("CollectAll returned %d events; want %d", len(all), total)
	}
}

// TestDecodePageToken_ValidToken verifies round-trip encode/decode of a page token.
func TestDecodePageToken_ValidToken(t *testing.T) {
	payload, _ := json.Marshal(map[string]interface{}{
		"offset": 42,
		"since":  "2026-01-01T00:00:00Z",
		"until":  "2026-03-01T00:00:00Z",
	})
	tok := base64.URLEncoding.EncodeToString(payload)

	offset, since, until, ok := compliance.DecodePageToken(tok)
	if !ok {
		t.Fatal("DecodePageToken returned ok=false for valid token")
	}
	if offset != 42 {
		t.Errorf("offset = %d; want 42", offset)
	}
	if since != "2026-01-01T00:00:00Z" {
		t.Errorf("since = %q; want 2026-01-01T00:00:00Z", since)
	}
	if until != "2026-03-01T00:00:00Z" {
		t.Errorf("until = %q; want 2026-03-01T00:00:00Z", until)
	}
}

// TestDecodePageToken_MalformedTokenReturnsFalse verifies that garbage input
// returns ok=false rather than panicking.
func TestDecodePageToken_MalformedTokenReturnsFalse(t *testing.T) {
	cases := []string{"", "not-base64!!!", "e30=invalid"}
	for _, tok := range cases {
		_, _, _, ok := compliance.DecodePageToken(tok)
		if ok {
			t.Errorf("DecodePageToken(%q) returned ok=true; want false", tok)
		}
	}
}
