// Phase 62 — Adversarial corpus regression test for the production
// ClientHello parser. This test is the deterministic counterpart to the
// coverage-guided fuzzer in cmd/proxy/fuzz_test.go: it runs in every normal
// `go test ./...` pass and asserts that every known-bad input shape held in
// tests/adversarial/corpus/ either returns an error or a partial result —
// never a panic, never a hang.
package tls

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// adversarialCorpusGlobs lists the candidate paths for the adversarial corpus
// directory. Tests run from internal/tls/ when invoked via `go test`, but
// the same suite is sometimes invoked from the repo root.
var adversarialCorpusGlobs = []string{
	"../../tests/adversarial/corpus/*.bin",
	"tests/adversarial/corpus/*.bin",
}

// findCorpusFixtures returns the resolved list of *.bin files. It returns an
// empty slice (and never an error) if the corpus directory does not exist —
// the test will skip rather than fail in that case.
func findCorpusFixtures(t *testing.T) []string {
	t.Helper()
	for _, pattern := range adversarialCorpusGlobs {
		matches, err := filepath.Glob(pattern)
		if err == nil && len(matches) > 0 {
			return matches
		}
	}
	return nil
}

// TestParseClientHello_AdversarialCorpus drives ParseClientHello with each
// fixture under tests/adversarial/corpus/. Every fixture must satisfy three
// invariants:
//
//   - The parser must not panic on the input.
//   - The parser must return within 100 ms (no infinite loops on malformed
//     length prefixes).
//   - The parser must not return both a non-nil result and an error.
//
// New fixtures committed to the corpus directory are picked up automatically.
func TestParseClientHello_AdversarialCorpus(t *testing.T) {
	matches := findCorpusFixtures(t)
	if len(matches) == 0 {
		t.Skip("no adversarial corpus fixtures found on disk")
	}
	for _, path := range matches {
		path := path
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			type result struct {
				info *ClientHelloInfo
				err  error
			}
			done := make(chan result, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("ParseClientHello panicked on %s: %v", name, r)
						done <- result{}
					}
				}()
				info, err := ParseClientHello(data)
				done <- result{info: info, err: err}
			}()

			select {
			case res := <-done:
				if res.info != nil && res.err != nil {
					t.Errorf("parser returned both result and error on %s: info=%+v err=%v", name, res.info, res.err)
				}
			case <-time.After(100 * time.Millisecond):
				t.Errorf("parser hung on %s (>100ms) — possible infinite loop", name)
			}
		})
	}
}
