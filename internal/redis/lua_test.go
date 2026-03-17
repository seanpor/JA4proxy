package redis

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSlidingWindowScript_MatchesFile verifies the embedded fallback script is
// byte-identical to scripts/sliding_window.lua in the repo root.
func TestSlidingWindowScript_MatchesFile(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(filename), "..", "..")
	luaPath := filepath.Join(repoRoot, "scripts", "sliding_window.lua")

	data, err := os.ReadFile(luaPath)
	if err != nil {
		t.Skipf("scripts/sliding_window.lua not found (%v); skipping byte-identity check", err)
	}

	fileContent := string(data)

	// Normalise line endings for comparison
	normalise := func(s string) string {
		return strings.ReplaceAll(strings.TrimSpace(s), "\r\n", "\n")
	}

	if normalise(fileContent) != normalise(slidingWindowLua) {
		t.Error("embedded slidingWindowLua does not match scripts/sliding_window.lua")
		t.Logf("file len=%d, embedded len=%d", len(fileContent), len(slidingWindowLua))
	}
}

// TestSlidingWindowScript_NonEmpty verifies the script is non-empty.
func TestSlidingWindowScript_NonEmpty(t *testing.T) {
	if strings.TrimSpace(SlidingWindowScript) == "" {
		t.Error("SlidingWindowScript is empty")
	}
}

// TestSlidingWindowScript_ContainsKeyElements checks the script has expected
// Redis commands that make it a valid sliding window implementation.
func TestSlidingWindowScript_ContainsKeyElements(t *testing.T) {
	checks := []string{
		"ZADD",
		"ZREMRANGEBYSCORE",
		"ZCARD",
		"EXPIRE",
		"INCR",
		"KEYS[1]",
		"KEYS[2]",
		"ARGV[1]",
		"ARGV[2]",
		"ARGV[3]",
	}
	for _, needle := range checks {
		if !strings.Contains(SlidingWindowScript, needle) {
			t.Errorf("SlidingWindowScript missing expected element %q", needle)
		}
	}
}
