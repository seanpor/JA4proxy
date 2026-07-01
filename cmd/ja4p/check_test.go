package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildJa4check builds the unified ja4p binary (cmd/ja4check was folded into
// it as the "check" subcommand — phase-151) and returns its path.
// Skips the test if the build fails (e.g., in CI without GOROOT).
func buildJa4check(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "ja4p")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = filepath.Join(checkFindModuleRoot(t), "cmd", "ja4p")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("skipping: could not build ja4p binary: %v\n%s", err, out)
	}
	return binPath
}

// TestJa4check_NoArgs verifies that running `ja4p check` without arguments
// exits with code 1 and prints usage to stderr.
func TestJa4check_NoArgs(t *testing.T) {
	binPath := buildJa4check(t)

	// Run without args
	runCmd := exec.Command(binPath, "check")
	out, err := runCmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for no arguments")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("exit code = %d; want 1", exitErr.ExitCode())
	}
	if len(out) == 0 {
		t.Error("expected usage message on stderr")
	}
}

// TestJa4check_InvalidFile verifies that `ja4p check` exits with code 1 for a
// nonexistent file.
func TestJa4check_InvalidFile(t *testing.T) {
	binPath := buildJa4check(t)

	runCmd := exec.Command(binPath, "check", "/nonexistent/file.bin")
	_, err := runCmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for missing file")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("exit code = %d; want 1", exitErr.ExitCode())
	}
}

// TestJa4check_InvalidData verifies that `ja4p check` exits with code 1 for
// data that is not a valid TLS ClientHello (check.go os.Exit(1)s on every
// error path — parse failures are not distinguished from I/O failures).
func TestJa4check_InvalidData(t *testing.T) {
	binPath := buildJa4check(t)

	// Write invalid data to a temp file
	tmpFile := filepath.Join(t.TempDir(), "bad.bin")
	if err := os.WriteFile(tmpFile, []byte("not a clienthello"), 0o644); err != nil {
		t.Fatal(err)
	}

	runCmd := exec.Command(binPath, "check", tmpFile)
	_, err := runCmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for invalid TLS data")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("exit code = %d; want 1", exitErr.ExitCode())
	}
}

// findModuleRoot walks up from the test file to find the go.mod directory.
func checkFindModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find module root (go.mod)")
		}
		dir = parent
	}
}
