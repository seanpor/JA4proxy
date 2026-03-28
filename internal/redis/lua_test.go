package redis

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSlidingWindowScript_MatchesFile verifies the embedded script is
// byte-identical to internal/redis/scripts/sliding_window.lua.
func TestSlidingWindowScript_MatchesFile(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	luaPath := filepath.Join(filepath.Dir(filename), "scripts", "sliding_window.lua")

	data, err := os.ReadFile(luaPath)
	if err != nil {
		t.Skipf("internal/redis/scripts/sliding_window.lua not found (%v); skipping", err)
	}

	fileContent := string(data)

	normalise := func(s string) string {
		return strings.ReplaceAll(strings.TrimSpace(s), "\r\n", "\n")
	}

	if normalise(fileContent) != normalise(SlidingWindowScript) {
		t.Error("embedded SlidingWindowScript does not match internal/redis/scripts/sliding_window.lua")
		t.Logf("file len=%d, embedded len=%d", len(fileContent), len(SlidingWindowScript))
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
