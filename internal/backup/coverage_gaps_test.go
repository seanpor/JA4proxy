package backup

import (
	"testing"
	"time"
)

// TestNopMetrics verifies all NopMetrics methods are callable without panic.
func TestNopMetrics(t *testing.T) {
	n := NopMetrics{}
	n.SetRunning(true)
	n.SetRunning(false)
	n.IncOperation(true)
	n.IncOperation(false)
	n.SetLastSuccess(time.Now())
	n.ObserveDuration(time.Second)
}

// TestResultDuration verifies Duration returns FinishedAt - StartedAt.
func TestResultDuration(t *testing.T) {
	start := time.Now()
	end := start.Add(5 * time.Second)
	r := &Result{StartedAt: start, FinishedAt: end}
	if d := r.Duration(); d != 5*time.Second {
		t.Errorf("Duration() = %v, want 5s", d)
	}
}

// TestPromMetrics verifies the Prometheus-backed metrics are callable.
// They write to the global registry; we verify no panic.
func TestPromMetrics(t *testing.T) {
	pm := PromMetrics{}
	pm.SetRunning(true)
	pm.SetRunning(false)
	pm.IncOperation(true)
	pm.IncOperation(false)
	pm.SetLastSuccess(time.Now())
	pm.ObserveDuration(time.Second)
}

// TestRestorePromMetrics exercises the restore-side PromMetrics.
func TestRestorePromMetrics(t *testing.T) {
	pm := RestorePromMetrics{}
	pm.SetRunning(true)
	pm.SetRunning(false)
	pm.IncOperation(true)
	pm.IncOperation(false)
	pm.ObserveDuration(time.Second)
	pm.IncSkipped("duplicate")
	pm.IncSkipped("ttl_expired")
}

// TestPrefixOf covers the colon-split helper.
func TestPrefixOf(t *testing.T) {
	cases := []struct{ key, want string }{
		{"ban:1.2.3.4", "ban"},
		{"config:dial", "config"},
		{"nocolon", "nocolon"},
		{"a:b:c", "a"},
	}
	for _, c := range cases {
		got := prefixOf(c.key)
		if got != c.want {
			t.Errorf("prefixOf(%q) = %q, want %q", c.key, got, c.want)
		}
	}
}

// TestListArtifactsNonexistentDir verifies listArtifacts handles a missing dir.
func TestListArtifactsNonexistentDir(t *testing.T) {
	files, err := listArtifacts("/nonexistent/path/that/does/not/exist")
	if err != nil {
		t.Fatalf("expected no error for nonexistent dir, got %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected empty list, got %v", files)
	}
}

// TestGzipRoundtrip covers gzipBytes and gunzipBytes.
func TestGzipRoundtrip(t *testing.T) {
	orig := []byte("hello backup world 1234567890")
	compressed, err := gzipBytes(orig)
	if err != nil {
		t.Fatalf("gzipBytes: %v", err)
	}
	if len(compressed) == 0 {
		t.Fatal("gzipBytes returned empty")
	}
	decompressed, err := gunzipBytes(compressed)
	if err != nil {
		t.Fatalf("gunzipBytes: %v", err)
	}
	if string(decompressed) != string(orig) {
		t.Errorf("roundtrip mismatch: got %q, want %q", decompressed, orig)
	}
}

// TestGunzipBytesInvalidData covers the error path in gunzipBytes.
func TestGunzipBytesInvalidData(t *testing.T) {
	_, err := gunzipBytes([]byte("not gzip data"))
	if err == nil {
		t.Error("expected error for invalid gzip data")
	}
}

// TestWriteArtifactAndListArtifacts exercises writeArtifact + listArtifacts
// together in a temp directory.
func TestWriteArtifactAndListArtifacts(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{
		cfg: Config{Dir: dir, Passphrase: "test"},
		log: silentLog(),
		now: time.Now,
	}
	artifact := []byte("fake encrypted payload")
	path, err := e.writeArtifact(artifact, time.Now())
	if err != nil {
		t.Fatalf("writeArtifact: %v", err)
	}
	if path == "" {
		t.Fatal("writeArtifact returned empty path")
	}

	files, err := listArtifacts(dir)
	if err != nil {
		t.Fatalf("listArtifacts: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 artifact, got %d", len(files))
	}
}

// TestExcluded verifies the key-exclusion logic.
func TestExcluded(t *testing.T) {
	e := &Engine{
		cfg: Config{ExcludePrefixes: []string{"session:", "tmp:"}},
		log: silentLog(),
	}
	if !e.excluded("session:abc123") {
		t.Error("session: key should be excluded")
	}
	if !e.excluded("tmp:work") {
		t.Error("tmp: key should be excluded")
	}
	if e.excluded("ban:1.2.3.4") {
		t.Error("ban: key should not be excluded")
	}
	if e.excluded("config:dial") {
		t.Error("config: key should not be excluded")
	}
}
