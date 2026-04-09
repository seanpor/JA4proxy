// Phase 62 — JA4 fingerprint corpus regression test.
//
// This test loads every known-good ClientHello fixture from
// tests/fixtures/clienthello/, computes the Go-side JA4 fingerprint, and
// asserts the result matches a checked-in golden file. It is the
// false-positive guardrail for the Go production parser: any silent change
// to the parser, the GREASE filter, or the JA4 hash routine that would
// alter a real-browser fingerprint fails this test loudly.
//
// To regenerate the golden file after a deliberate JA4 algorithm change:
//
//	GOROOT=/snap/go/current go test -run TestJA4_FPCorpus_NoRegression \
//	    ./internal/tls/ -args -update
//
// The "-args -update" form is required so the Go test driver passes the
// -update flag through to the test binary instead of treating it as one of
// its own flags. Commit the updated testdata/ja4_fp_golden.txt alongside the
// code change.
package tls

import (
	"bufio"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "regenerate ja4_fp_golden.txt from current fixtures")

const (
	ja4GoldenPath = "testdata/ja4_fp_golden.txt"
)

// fpFixtureGlobs is the set of candidate paths for the known-good
// ClientHello fixture directory. The test runs from internal/tls/.
var fpFixtureGlobs = []string{
	"../../tests/fixtures/clienthello/*.bin",
	"tests/fixtures/clienthello/*.bin",
}

// findFPFixtures returns the resolved list of *.bin files. Empty slice if no
// fixtures are present (test will skip).
func findFPFixtures() []string {
	for _, pattern := range fpFixtureGlobs {
		matches, err := filepath.Glob(pattern)
		if err == nil && len(matches) > 0 {
			sort.Strings(matches)
			return matches
		}
	}
	return nil
}

// loadJA4Golden parses a golden file with one "<fixture> <ja4>" entry per
// line. Comment lines (#) and blank lines are ignored.
func loadJA4Golden(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open golden %s: %v", path, err)
	}
	defer f.Close()
	out := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		out[parts[0]] = parts[1]
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scan golden: %v", err)
	}
	return out
}

// writeJA4Golden writes a freshly computed golden file. Used by -update mode.
func writeJA4Golden(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# JA4 fingerprint regression corpus — phase 62\n")
	b.WriteString("# Format: <fixture-filename> <ja4-string>\n")
	b.WriteString("# Regenerate: go test -run TestJA4_FPCorpus_NoRegression ./internal/tls/ -args -update\n")
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString(" ")
		b.WriteString(entries[k])
		b.WriteString("\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write golden: %v", err)
	}
}

// TestJA4_FPCorpus_NoRegression locks in the Go-computed JA4 string for
// every fixture under tests/fixtures/clienthello/. Run with -update to
// regenerate after a deliberate fingerprint change.
func TestJA4_FPCorpus_NoRegression(t *testing.T) {
	fixtures := findFPFixtures()
	if len(fixtures) == 0 {
		t.Skip("no clienthello fixtures found on disk")
	}

	current := map[string]string{}
	for _, path := range fixtures {
		name := filepath.Base(path)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		info, err := ParseClientHello(data)
		if err != nil {
			t.Logf("fixture %s does not parse cleanly (%v) — skipping", name, err)
			continue
		}
		current[name] = ComputeJA4(info)
	}

	if *updateGolden {
		writeJA4Golden(t, ja4GoldenPath, current)
		t.Logf("wrote %d entries to %s", len(current), ja4GoldenPath)
		return
	}

	golden := loadJA4Golden(t, ja4GoldenPath)
	if len(golden) == 0 {
		t.Fatalf("golden file %s is empty — run with -update to populate", ja4GoldenPath)
	}

	// Every golden entry must match the current computation.
	for name, want := range golden {
		t.Run(name, func(t *testing.T) {
			got, ok := current[name]
			if !ok {
				t.Fatalf("fixture %s in golden but missing from disk or no longer parses", name)
			}
			if got != want {
				t.Errorf("JA4 drift on %s:\n  want %s\n  got  %s", name, want, got)
			}
		})
	}

	// New fixtures discovered on disk that are not in the golden file
	// should fail the test loudly so the regenerator is run consciously.
	for name := range current {
		if _, ok := golden[name]; !ok {
			t.Errorf("fixture %s parses but is missing from golden file — run with -update", name)
		}
	}
}
