package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestJa4check_NoArgs verifies that running ja4check without arguments exits
// with code 1 and prints usage to stderr.
func TestJa4check_NoArgs(t *testing.T) {
	// Build the binary
	binPath := filepath.Join(t.TempDir(), "ja4check")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = filepath.Join(findModuleRoot(t), "cmd", "ja4check")
	cmd.Env = append(os.Environ(), "GOROOT=/snap/go/current")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	// Run without args
	runCmd := exec.Command(binPath)
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

// TestJa4check_InvalidFile verifies that ja4check exits with code 1 for a
// nonexistent file.
func TestJa4check_InvalidFile(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "ja4check")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = filepath.Join(findModuleRoot(t), "cmd", "ja4check")
	cmd.Env = append(os.Environ(), "GOROOT=/snap/go/current")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	runCmd := exec.Command(binPath, "/nonexistent/file.bin")
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

// TestJa4check_InvalidData verifies that ja4check exits with code 2 for data
// that is not a valid TLS ClientHello.
func TestJa4check_InvalidData(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "ja4check")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = filepath.Join(findModuleRoot(t), "cmd", "ja4check")
	cmd.Env = append(os.Environ(), "GOROOT=/snap/go/current")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	// Write invalid data to a temp file
	tmpFile := filepath.Join(t.TempDir(), "bad.bin")
	if err := os.WriteFile(tmpFile, []byte("not a clienthello"), 0o644); err != nil {
		t.Fatal(err)
	}

	runCmd := exec.Command(binPath, tmpFile)
	_, err := runCmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for invalid TLS data")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("exit code = %d; want 2", exitErr.ExitCode())
	}
}

// findModuleRoot walks up from the test file to find the go.mod directory.
func findModuleRoot(t *testing.T) string {
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
