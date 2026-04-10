// phase-63 review-fix: unit tests for classifyConnError. Locks the source-aware
// classification contract so on-call sees the right error_type label and the
// availability SLI runbook step 1 ("topk by error_type") is actionable.
package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestClassifyConnError(t *testing.T) {
	// Build a real net.OpError carrying an i/o timeout, the way Go's net
	// package produces them — string-matching on err.Error() must work.
	timeoutErr := &net.OpError{Op: "read", Err: &timeoutError{}}

	cases := []struct {
		name   string
		source string
		err    error
		want   string
	}{
		{"nil error → unknown", "client_read", nil, "unknown"},

		// client_read source
		{"client read timeout", "client_read", timeoutErr, "client_read_timeout"},
		{"client read deadline exceeded", "client_read", context.DeadlineExceeded, "client_read_timeout"},
		{"client read generic error", "client_read", errors.New("connection reset by peer"), "client_read_error"},

		// backend_dial source
		{"backend dial timeout", "backend_dial", timeoutErr, "backend_dial_timeout"},
		{"backend connection refused", "backend_dial", errors.New("dial tcp 10.0.0.1:443: connect: connection refused"), "backend_refused"},
		{"backend no route", "backend_dial", errors.New("dial tcp: no route to host"), "backend_refused"},
		{"backend dial generic error", "backend_dial", errors.New("network is unreachable"), "backend_dial_error"},

		// redis source
		{"redis timeout", "redis", timeoutErr, "redis_timeout"},
		{"redis deadline exceeded", "redis", context.DeadlineExceeded, "redis_timeout"},
		{"redis generic error", "redis", errors.New("WRONGTYPE Operation against a key"), "redis_error"},

		// oom is universal
		{"oom from any source", "client_read", errors.New("runtime: out of memory"), "oom"},

		// unknown source falls through
		{"unknown source timeout", "weird", timeoutErr, "timeout"},
		{"unknown source other", "weird", errors.New("kaboom"), "unknown"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyConnError(tc.source, tc.err)
			if got != tc.want {
				t.Errorf("classifyConnError(%q, %v) = %q, want %q", tc.source, tc.err, got, tc.want)
			}
		})
	}
}

// timeoutError implements net.Error with Timeout()=true so net.OpError.Error()
// renders as "...: i/o timeout", matching what Go's runtime produces.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// Compile-time guard that timeoutError satisfies net.Error so net.OpError uses
// it correctly.
var _ net.Error = timeoutError{}

// silence unused import on time when refactored
var _ = time.Second
