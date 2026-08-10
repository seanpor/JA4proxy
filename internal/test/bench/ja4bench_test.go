// Copyright 2026 Anomaly Collective
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at:
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under the License.
package bench

import (
	"strings"
	"testing"
	"time"
)

// newResult returns a BenchResult with a non-zero duration so Calculate() can
// derive throughput without dividing by zero.
func newResult() *BenchResult {
	start := time.Now().Add(-10 * time.Second)
	return &BenchResult{StartTime: start, EndTime: start.Add(10 * time.Second)}
}

// TestStatus covers the verdict that RunBenchmark turns into an exit code.
//
// Before Phase 800 this verdict was only ever printed — `ja4p test benchmark`
// exited 0 no matter what, so `make bench-macro` reported success after making
// zero connections and logging thousands of 'connection refused' errors.
func TestStatus(t *testing.T) {
	tests := []struct {
		name       string
		result     func() *BenchResult
		wantErr    bool
		wantSubstr string
	}{
		{
			name: "zero connections with errors is a failure",
			result: func() *BenchResult {
				r := newResult()
				r.Errors = 2880
				r.LastError = "dial tcp 127.0.0.1:10381: connect: connection refused"
				return r
			},
			wantErr:    true,
			wantSubstr: "no successful connections",
		},
		{
			// Regression guard: the old check was `total == 0 && r.Errors > 0`,
			// so a run that connected zero times AND recorded zero errors fell
			// through to the false-positive branch and reported PASSED.
			name: "zero connections with zero errors is still a failure",
			result: func() *BenchResult {
				return newResult()
			},
			wantErr:    true,
			wantSubstr: "no successful connections",
		},
		{
			name: "good traffic all allowed passes",
			result: func() *BenchResult {
				r := newResult()
				r.TotalGood = 1000
				r.GoodAllowed = 1000
				return r
			},
			wantErr: false,
		},
		{
			name: "any blocked good traffic is a failure",
			result: func() *BenchResult {
				r := newResult()
				r.TotalGood = 1000
				r.GoodAllowed = 999
				r.GoodBlocked = 1
				return r
			},
			wantErr:    true,
			wantSubstr: "false positives",
		},
		{
			// Documents existing behaviour: false negatives (bad traffic
			// allowed) are reported but do not fail the run, because the dial
			// defaults to 0 (monitor mode) where allowing bad traffic is
			// expected. Only false positives fail. Unchanged by Phase 800.
			name: "false negatives alone do not fail the run",
			result: func() *BenchResult {
				r := newResult()
				r.TotalGood = 500
				r.GoodAllowed = 500
				r.TotalBad = 500
				r.BadAllowed = 500
				return r
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.result().Status()

			if tt.wantErr && err == nil {
				t.Fatal("expected a non-nil error, got nil (this is what let a failed benchmark exit 0)")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
			if tt.wantSubstr != "" && !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Errorf("error %q does not mention %q", err, tt.wantSubstr)
			}
		})
	}
}

// TestRatesAreZeroWhenNoTrafficSent pins the guard that stops the benchmark
// reporting a reassuring 0.00% computed from zero samples.
func TestRatesAreZeroWhenNoTrafficSent(t *testing.T) {
	r := newResult()

	if got := r.FalsePositiveRate(); got != 0 {
		t.Errorf("FalsePositiveRate with no good traffic: got %v, want 0", got)
	}
	if got := r.FalseNegativeRate(); got != 0 {
		t.Errorf("FalseNegativeRate with no bad traffic: got %v, want 0", got)
	}
	// The rate being 0 must NOT be readable as success — Status() is the verdict.
	if err := r.Status(); err == nil {
		t.Error("a run with no traffic must fail Status() despite 0% rates")
	}
}

func TestRatesAreComputedCorrectly(t *testing.T) {
	r := newResult()
	r.TotalGood = 200
	r.GoodAllowed = 190
	r.GoodBlocked = 10
	r.TotalBad = 50
	r.BadAllowed = 5
	r.BadBlocked = 45

	if got, want := r.FalsePositiveRate(), 5.0; got != want {
		t.Errorf("FalsePositiveRate: got %v, want %v", got, want)
	}
	if got, want := r.FalseNegativeRate(), 10.0; got != want {
		t.Errorf("FalseNegativeRate: got %v, want %v", got, want)
	}
}
