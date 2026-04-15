package security

// Phase 203d — TDD red: dgaConfidence() byte-for-byte parity with Python dga_score().
// Source of truth: src/security/sni_analyzer.py (dga_score).
//
// Fixture:
//   - tests/fixtures/dga/hostnames.txt    — one hostname per line, # = comment
//   - tests/fixtures/dga/expected_scores.json — map[hostname]float64 from Python
//
// This test will FAIL against the current Go implementation because Go's
// algorithm diverges (consecutive-consonant rule, different entropy thresholds,
// no _SKIP_PREFIXES, no digit-regex).

import (
	"bufio"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureRoot walks up from the test file until it finds tests/fixtures/dga.
func fixtureRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "tests", "fixtures", "dga")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate tests/fixtures/dga from %s", wd)
	return ""
}

func loadHostnames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open hostnames: %v", err)
	}
	defer f.Close()
	var hosts []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hosts = append(hosts, line)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan hostnames: %v", err)
	}
	return hosts
}

func loadExpected(t *testing.T, path string) map[string]float64 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read expected: %v", err)
	}
	m := map[string]float64{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal expected: %v", err)
	}
	return m
}

func TestDGAConfidence_ParityWithPythonGolden(t *testing.T) {
	root := fixtureRoot(t)
	hosts := loadHostnames(t, filepath.Join(root, "hostnames.txt"))
	expected := loadExpected(t, filepath.Join(root, "expected_scores.json"))

	if len(hosts) < 80 {
		t.Fatalf("fixture corpus too small: %d hosts; need ≥ 80", len(hosts))
	}

	const tol = 1e-9
	for _, host := range hosts {
		host := host
		want, ok := expected[host]
		if !ok {
			t.Errorf("hostname %q in hostnames.txt but missing from expected_scores.json", host)
			continue
		}
		t.Run(host, func(t *testing.T) {
			got := dgaConfidence(host)
			if math.Abs(got-want) > tol {
				t.Errorf("dgaConfidence(%q) = %.17g; want %.17g (|Δ|=%.3g, tol=%.0e)",
					host, got, want, math.Abs(got-want), tol)
			}
		})
	}
}

func TestDGAConfidence_EmptyString_IsZero(t *testing.T) {
	// Python: _get_primary_label("") → "", len < 6 → 0.0
	if got := dgaConfidence(""); got != 0.0 {
		t.Errorf("dgaConfidence(\"\") = %v; want 0.0", got)
	}
}

func TestDGAConfidence_ShortLabel_IsZero(t *testing.T) {
	// Python: len(label) < _MIN_DGA_LABEL_LEN(6) → 0.0
	cases := []string{"a", "ab", "abc.com", "short.io", "ab.de"}
	for _, h := range cases {
		h := h
		t.Run(h, func(t *testing.T) {
			if got := dgaConfidence(h); got != 0.0 {
				t.Errorf("dgaConfidence(%q) = %v; want 0.0 (label shorter than MIN_DGA_LABEL_LEN)", h, got)
			}
		})
	}
}

func TestDGAConfidence_SkipPrefixes_PicksNextLabel(t *testing.T) {
	// Python _SKIP_PREFIXES = {"www","mail","m","api","static","cdn","img","assets"}
	// dgaConfidence("www.google.com") must equal dgaConfidence("google.com").
	pairs := []struct{ a, b string }{
		{"www.google.com", "google.com"},
		{"api.github.com", "github.com"},
		{"cdn.cloudflare.com", "cloudflare.com"},
		{"mail.google.com", "google.com"},
	}
	for _, p := range pairs {
		p := p
		t.Run(p.a+"_vs_"+p.b, func(t *testing.T) {
			got := dgaConfidence(p.a)
			want := dgaConfidence(p.b)
			if math.Abs(got-want) > 1e-9 {
				t.Errorf("dgaConfidence(%q)=%v; dgaConfidence(%q)=%v; should be equal "+
					"(skip prefixes must be stripped)", p.a, got, p.b, want)
			}
		})
	}
}
