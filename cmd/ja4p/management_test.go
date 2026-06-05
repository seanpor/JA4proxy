package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildCLI builds the ja4proxy-cli binary and returns its path.
// Skips the test if the build fails (e.g., in CI without GOROOT).
func buildCLI(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "ja4proxy-cli")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = filepath.Join(managementFindModuleRoot(t), "cmd", "ja4proxy-cli")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("skipping: could not build ja4proxy-cli binary: %v\n%s", err, out)
	}
	return binPath
}

// TestCLI_NoArgs_ShowsHelp verifies that running without arguments shows help.
func TestCLI_NoArgs_ShowsHelp(t *testing.T) {
	bin := buildCLI(t)
	out, err := exec.Command(bin).CombinedOutput()
	// cobra with no required args usually exits 0 and shows help
	if err != nil {
		// Some cobra setups exit 0, some exit 1 — both are fine for --help
		t.Logf("exit error (acceptable): %v", err)
	}
	if !strings.Contains(string(out), "ja4proxy-cli") {
		t.Errorf("output should contain 'ja4proxy-cli': %s", out)
	}
}

// TestCLI_Help verifies --help flag works.
func TestCLI_Help(t *testing.T) {
	bin := buildCLI(t)
	out, err := exec.Command(bin, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("--help should exit 0: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ja4proxy-cli") {
		t.Errorf("output should contain 'ja4proxy-cli': %s", out)
	}
	if !strings.Contains(string(out), "Available Commands") {
		t.Errorf("output should list available commands: %s", out)
	}
}

// TestCLI_SubcommandHelp verifies --help on each major subcommand.
func TestCLI_SubcommandHelp(t *testing.T) {
	bin := buildCLI(t)
	subcommands := []string{
		"ip",
		"allowlist",
		"blocklist",
		"dial",
		"config",
		"health",
		"policy",
		"simulation",
		"compliance",
		"report",
	}
	for _, sub := range subcommands {
		t.Run(sub, func(t *testing.T) {
			out, err := exec.Command(bin, sub, "--help").CombinedOutput()
			if err != nil {
				t.Fatalf("%s --help failed: %v\n%s", sub, err, out)
			}
			if len(out) == 0 {
				t.Errorf("%s --help produced no output", sub)
			}
		})
	}
}

// TestCLI_PolicyValidateHelp verifies policy validate --help works.
func TestCLI_PolicyValidateHelp(t *testing.T) {
	bin := buildCLI(t)
	out, err := exec.Command(bin, "policy", "validate", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("policy validate --help failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--file") {
		t.Errorf("output should mention --file flag: %s", out)
	}
}

// TestCLI_UnknownCommand verifies that an unknown command exits with error.
func TestCLI_UnknownCommand(t *testing.T) {
	bin := buildCLI(t)
	_, err := exec.Command(bin, "nonexistent-command").CombinedOutput()
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
}

// findModuleRoot walks up from the test file to find the go.mod directory.
func managementFindModuleRoot(t *testing.T) string {
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
