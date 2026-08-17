package metrics

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestActiveConnectionsHasASingleWriterPair guards a bug found by driving real
// traffic through the stack: ja4proxy_active_connections read -19.
//
// The gauge is the process-wide accept counter, maintained as a matched
// Inc/Dec pair in cmd/ja4pd/main.go. internal/security/tcp_analyzer.go also
// called Set() on it, passing ONE CLIENT IP's concurrent-connection count from
// Redis. That clobbered the global value, and the accept path's subsequent
// Dec() calls drove it negative.
//
// Nothing caught it: the gauge has no label to validate, no alert referenced
// it, and a negative gauge is not an error — it just renders as a nonsense
// number on a dashboard. It surfaced only because someone looked at it after
// 5184 connections.
//
// Rule: only the accept path may write this gauge, and only via Inc/Dec.
func TestActiveConnectionsHasASingleWriterPair(t *testing.T) {
	root := filepath.Join("..", "..")
	writeRe := regexp.MustCompile(`metrics\.ActiveConnections\.(Set|Add|Sub|Inc|Dec)\(`)

	type site struct{ file, op string }
	var sites []site

	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for _, m := range writeRe.FindAllStringSubmatch(string(b), -1) {
				rel, _ := filepath.Rel(root, path)
				sites = append(sites, site{rel, m[1]})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}

	for _, s := range sites {
		if s.op == "Set" || s.op == "Add" || s.op == "Sub" {
			t.Errorf("%s calls ActiveConnections.%s — this gauge is the "+
				"process-wide accept counter and may only be adjusted by the "+
				"matched Inc/Dec pair in cmd/ja4pd. A Set() here clobbers it "+
				"and later Dec() calls drive it negative (observed: -19).",
				s.file, s.op)
		}
		if !strings.HasPrefix(s.file, "cmd/ja4pd") {
			t.Errorf("%s writes ActiveConnections (.%s); only cmd/ja4pd's "+
				"accept path may.", s.file, s.op)
		}
	}

	var inc, dec int
	for _, s := range sites {
		switch s.op {
		case "Inc":
			inc++
		case "Dec":
			dec++
		}
	}
	if inc != dec {
		t.Errorf("ActiveConnections has %d Inc and %d Dec call sites — they "+
			"must be paired, or the gauge drifts", inc, dec)
	}
	if inc == 0 {
		t.Error("ActiveConnections is never incremented — the gauge is dead")
	}
}
