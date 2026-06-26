package tls

// TestFixtureReplay_StableDecisions replaces the former Go/Python live parity
// harness (Gap 2 from Phase 15). That test required both proxies running in
// parallel; the Python proxy has since been deleted, so direct comparison is no
// longer possible.
//
// This test instead verifies that the parse+fingerprint pipeline produces
// identical, deterministic output on every invocation for each fixture in
// tests/fixtures/clienthello/. Running it twice and comparing results is the
// Go-only analogue of the original parity goal: catch non-determinism in JA4
// computation (map-iteration order, hash-seed variance, etc.) that would cause
// inconsistent allow/block decisions across proxy instances.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const fixtureDir = "../../tests/fixtures/clienthello"
const fixtureRuns = 3 // number of times each fixture is re-processed

func TestFixtureReplay_StableDecisions(t *testing.T) {
	jsonPath := filepath.Join(fixtureDir, "known_ja4.json")
	data, err := os.ReadFile(jsonPath)
	if os.IsNotExist(err) {
		t.Skipf("fixture index %s not found", jsonPath)
		return
	}
	if err != nil {
		t.Fatalf("read %s: %v", jsonPath, err)
	}

	var expected map[string]string
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatalf("parse %s: %v", jsonPath, err)
	}
	if len(expected) == 0 {
		t.Skip("no fixtures defined in known_ja4.json")
	}

	for name := range expected {
		name := name
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(fixtureDir, name+".bin")
			binData, err := os.ReadFile(path)
			if os.IsNotExist(err) {
				t.Errorf("fixture binary %s not found", path)
				return
			}
			if err != nil {
				t.Fatalf("%s: read: %v", name, err)
			}

			// Run parse+fingerprint fixtureRuns times and assert identical output.
			type result struct {
				ja4 string
				sni string
			}
			var first result
			for i := 0; i < fixtureRuns; i++ {
				info, err := ParseClientHello(binData)
				if err != nil {
					t.Fatalf("%s run %d: parse error: %v", name, i, err)
				}
				got := result{
					ja4: ComputeJA4(info),
					sni: info.SNI,
				}
				if i == 0 {
					first = got
					continue
				}
				if got != first {
					t.Errorf("%s: non-deterministic output between run 0 and run %d:\n  run 0: %+v\n  run %d: %+v",
						name, i, first, i, got)
				}
			}

			// Also assert against the known-good expected fingerprint.
			if first.ja4 != expected[name] {
				t.Errorf("%s: JA4 = %q; want %q", name, first.ja4, expected[name])
			}
		})
	}

	// Verify every .bin file in the directory has a known_ja4.json entry.
	// This catches new captures added without updating the expected fingerprints.
	bins, err := filepath.Glob(filepath.Join(fixtureDir, "*.bin"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, bin := range bins {
		name := filepath.Base(bin[:len(bin)-4]) // strip .bin
		if _, ok := expected[name]; !ok {
			t.Errorf("fixture %s has no entry in known_ja4.json; add its expected JA4 fingerprint", name)
		}
	}
}
