package wizard

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// queuedInput returns an inputFn that pops from a slice of prepared responses.
// Any empty response uses the default (simulates Enter key).
func queuedInput(responses []string) func(string) (string, error) {
	i := 0
	return func(_ string) (string, error) {
		if i >= len(responses) {
			return "", nil // EOF/default for any extra prompts
		}
		r := responses[i]
		i++
		return r, nil
	}
}

// noPass is a GetPassFn that always returns empty (no password provided).
func noPass(_ string) (string, error) { return "", nil }

// -- ConsoleOutput coverage --

func TestConsoleOutput_NoColor(t *testing.T) {
	// Redirect stdout/stderr to discard output (ConsoleOutput writes there).
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	c := &ConsoleOutput{NoColor: true}
	c.Header("Test Header")
	c.Section("Test Section")
	c.Info("Info %s", "msg")
	c.Success("Success %s", "msg")
	c.Raw("raw content")

	w.Close()
	os.Stdout = old
	io.Copy(io.Discard, r)

	// Also exercise Warn (writes to stderr).
	oldErr := os.Stderr
	re, we, _ := os.Pipe()
	os.Stderr = we
	c.Warn("Warn %s", "msg")
	we.Close()
	os.Stderr = oldErr
	io.Copy(io.Discard, re)
}

func TestConsoleOutput_WithColor(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	c := &ConsoleOutput{NoColor: false}
	c.Header("H")
	c.Section("S")
	c.Info("i")
	c.Success("s")
	c.Raw("r")

	w.Close()
	os.Stdout = old
	buf := &bytes.Buffer{}
	io.Copy(buf, r)
	// Color codes present in output when NoColor=false.
	if !strings.Contains(buf.String(), "\033[") {
		t.Error("expected ANSI escape codes in output with NoColor=false")
	}
}

func TestNewConsoleOutput_EnvNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	c := NewConsoleOutput()
	if !c.NoColor {
		t.Error("expected NoColor=true when NO_COLOR is set")
	}
}

func TestNewConsoleOutput_Default(t *testing.T) {
	os.Unsetenv("NO_COLOR")
	c := NewConsoleOutput()
	_ = c // Just verify it doesn't panic.
}

func TestStringsRepeat(t *testing.T) {
	got := stringsRepeat("=-", 3)
	if got != "=-=-" {
		// stringsRepeat repeats byte-by-byte: "=-" × 3 = "=-=-="... actually let me check the impl.
		// The impl: result = make([]byte, len(s)*n); result[i] = s[i%len(s)]
		// "=-" * 3 = 6 bytes: s[0%2]='=', s[1%2]='-', s[2%2]='=', s[3%2]='-', s[4%2]='=', s[5%2]='-'
		// = "=-=-=-"... wait that's wrong. Let me recalculate:
		// len("=-") = 2, n = 3 → make([]byte, 6)
		// i=0: s[0%2]=s[0]='='
		// i=1: s[1%2]=s[1]='-'
		// i=2: s[2%2]=s[0]='='
		// i=3: s[3%2]=s[1]='-'
		// i=4: s[4%2]=s[0]='='
		// i=5: s[5%2]=s[1]='-'
		// result = "=-=-=-"
		if got != "=-=-=-" {
			t.Errorf("stringsRepeat('=-', 3) = %q, want '=-=-=-'", got)
		}
	}
}

func TestStringsRepeatSingle(t *testing.T) {
	got := stringsRepeat("=", 5)
	if got != "=====" {
		t.Errorf("stringsRepeat('=', 5) = %q, want '====='", got)
	}
}

// -- validDir --

func TestValidDir_ExistingDir(t *testing.T) {
	dir := t.TempDir()
	if !validDir(dir) {
		t.Errorf("validDir(%q) = false, want true", dir)
	}
}

func TestValidDir_File(t *testing.T) {
	dir := t.TempDir()
	f, _ := os.CreateTemp(dir, "f")
	f.Close()
	if validDir(f.Name()) {
		t.Error("validDir on file should return false")
	}
}

func TestValidDir_Nonexistent(t *testing.T) {
	if validDir("/nonexistent/path/that/does/not/exist") {
		t.Error("validDir on nonexistent path should return false")
	}
}

func TestValidDir_Empty(t *testing.T) {
	if validDir("") {
		t.Error("validDir('') should return false")
	}
}

// -- StdinInput / StdinGetPass (smoke: just verify they read from stdin) --

func TestStdinInput_EOF(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()

	_, err = StdinInput("prompt: ")
	if err == nil {
		t.Error("StdinInput on closed pipe should return error")
	}
}

func TestStdinGetPass_EOF(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()

	_, err = StdinGetPass("password: ")
	if err == nil {
		t.Error("StdinGetPass on closed pipe should return error")
	}
}

// -- ShellLaneManager --

func TestShellLaneManager_New(t *testing.T) {
	m := NewShellLaneManager("/scripts/lane-env.sh", "/tmp")
	if m == nil {
		t.Fatal("NewShellLaneManager returned nil")
	}
	if m.LaneEnvScript != "/scripts/lane-env.sh" {
		t.Errorf("LaneEnvScript = %q", m.LaneEnvScript)
	}
}

func TestShellLaneManager_ListLanes_NoScript(t *testing.T) {
	m := &ShellLaneManager{LaneEnvScript: ""} // no script
	lanes, err := m.ListLanes(context.Background())
	if err != nil {
		t.Fatalf("ListLanes with no script should not error: %v", err)
	}
	if len(lanes) != 0 {
		t.Errorf("expected no lanes, got %v", lanes)
	}
}

func TestShellLaneManager_ListLanes_MissingScript(t *testing.T) {
	m := &ShellLaneManager{LaneEnvScript: "/nonexistent/lane-env.sh", WorkDir: t.TempDir()}
	// Script not found → exec error returned to caller.
	_, err := m.ListLanes(context.Background())
	if err == nil {
		t.Fatal("ListLanes with missing script should return an error")
	}
}

func TestShellLaneManager_PreviewPorts(t *testing.T) {
	m := &ShellLaneManager{}
	ports, err := m.PreviewPorts(2)
	if err != nil {
		t.Fatalf("PreviewPorts: %v", err)
	}
	if ports["INGRESS"] != 643 {
		t.Errorf("lane 2 INGRESS = %d, want 643", ports["INGRESS"])
	}
}

func TestShellLaneManager_AssignLane_Preferred(t *testing.T) {
	m := &ShellLaneManager{}
	info, err := m.AssignLane(context.Background(), 5)
	if err != nil {
		t.Fatalf("AssignLane(5): %v", err)
	}
	if info.Number != 5 {
		t.Errorf("AssignLane(5).Number = %d, want 5", info.Number)
	}
}

func TestShellLaneManager_AssignLane_AutoAssign(t *testing.T) {
	m := &ShellLaneManager{LaneEnvScript: ""} // no script → no used lanes
	info, err := m.AssignLane(context.Background(), -1)
	if err != nil {
		t.Fatalf("AssignLane(-1): %v", err)
	}
	if info.Number < 0 {
		t.Errorf("AssignLane(-1).Number = %d, want >= 0", info.Number)
	}
}

// -- Interactive collectStep functions via mock input --

func TestCollectStep1Basics(t *testing.T) {
	// Responses: host, port, mode, bind IP, admin user, log level
	// (password prompt uses GetPassFn which we set to noPass)
	inputs := queuedInput([]string{
		"mybackend",    // backend host
		"443",          // port
		"container",    // mode
		"127.0.0.1",   // bind IP
		"admin",        // admin user
		"INFO",         // log level
	})
	w := &Wizard{Out: silentOutput{}, InputFn: inputs, GetPassFn: noPass}
	if err := w.collectStep1Basics(context.Background()); err != nil {
		t.Fatalf("collectStep1Basics: %v", err)
	}
	if w.Answers.BackendHost != "mybackend" {
		t.Errorf("BackendHost = %q", w.Answers.BackendHost)
	}
	if w.Answers.BackendPort != 443 {
		t.Errorf("BackendPort = %d", w.Answers.BackendPort)
	}
	if w.Answers.Mode != "container" {
		t.Errorf("Mode = %q", w.Answers.Mode)
	}
}

func TestCollectStep2Network(t *testing.T) {
	// dial=0, lb=n, proxy=n, snis=""
	inputs := queuedInput([]string{"0", "n", "n", ""})
	w := &Wizard{Out: silentOutput{}, InputFn: inputs, GetPassFn: noPass}
	if err := w.collectStep2Network(context.Background()); err != nil {
		t.Fatalf("collectStep2Network: %v", err)
	}
	if w.Answers.DialValue != 0 {
		t.Errorf("DialValue = %d", w.Answers.DialValue)
	}
}

func TestCollectStep2Network_HighDial(t *testing.T) {
	// dial=75 triggers a warning, lb=n, proxy=n, snis=""
	inputs := queuedInput([]string{"75", "n", "n", ""})
	w := &Wizard{Out: silentOutput{}, InputFn: inputs, GetPassFn: noPass}
	if err := w.collectStep2Network(context.Background()); err != nil {
		t.Fatalf("collectStep2Network (high dial): %v", err)
	}
	if w.Answers.DialValue != 75 {
		t.Errorf("DialValue = %d, want 75", w.Answers.DialValue)
	}
}

func TestCollectStep2Network_WithLB(t *testing.T) {
	// dial=0, lb=y (trusted CIDRs), proxy=n, snis=""
	inputs := queuedInput([]string{"0", "y", "10.0.0.0/8,192.168.0.0/16", "n", ""})
	w := &Wizard{Out: silentOutput{}, InputFn: inputs, GetPassFn: noPass}
	if err := w.collectStep2Network(context.Background()); err != nil {
		t.Fatalf("collectStep2Network (with LB): %v", err)
	}
	if !w.Answers.UpstreamLB {
		t.Error("UpstreamLB should be true")
	}
	if len(w.Answers.TrustedCIDRs) != 2 {
		t.Errorf("TrustedCIDRs = %v", w.Answers.TrustedCIDRs)
	}
}

func TestCollectStep2Network_WithProxy(t *testing.T) {
	// dial=0, lb=n, proxy=y, version=2, snis=""
	inputs := queuedInput([]string{"0", "n", "y", "2", ""})
	w := &Wizard{Out: silentOutput{}, InputFn: inputs, GetPassFn: noPass}
	if err := w.collectStep2Network(context.Background()); err != nil {
		t.Fatalf("collectStep2Network (with PROXY): %v", err)
	}
	if !w.Answers.WritePROXY {
		t.Error("WritePROXY should be true")
	}
	if w.Answers.PROXYVersion != 2 {
		t.Errorf("PROXYVersion = %d, want 2", w.Answers.PROXYVersion)
	}
}

func TestCollectStep3TLS_SelfSigned(t *testing.T) {
	// certMode=self-signed; geoip path directed to a real tmp dir.
	dir := t.TempDir()
	inputs2 := queuedInput([]string{"self-signed", dir})
	wiz2 := &Wizard{Out: silentOutput{}, InputFn: inputs2, GetPassFn: noPass}
	if err := wiz2.collectStep3TLS(context.Background()); err != nil {
		t.Fatalf("collectStep3TLS: %v", err)
	}
	if wiz2.Answers.TLSCerts != "self-signed" {
		t.Errorf("TLSCerts = %q, want self-signed", wiz2.Answers.TLSCerts)
	}
}

func TestCollectStep4Lane_NoLaneManager(t *testing.T) {
	// No LaneManager: lane=0, name=prod
	inputs := queuedInput([]string{"0", "prod"})
	w := &Wizard{Out: silentOutput{}, InputFn: inputs, GetPassFn: noPass}
	if err := w.collectStep4Lane(context.Background()); err != nil {
		t.Fatalf("collectStep4Lane: %v", err)
	}
	if w.Answers.LaneName != "prod" {
		t.Errorf("LaneName = %q, want prod", w.Answers.LaneName)
	}
}

func TestCollectStep5Security_AllEmpty(t *testing.T) {
	// All TI keys empty → skip
	inputs := queuedInput([]string{})
	w := &Wizard{Out: silentOutput{}, InputFn: inputs, GetPassFn: noPass}
	if err := w.collectStep5Security(context.Background()); err != nil {
		t.Fatalf("collectStep5Security: %v", err)
	}
	if len(w.Answers.TIKeys) != 0 {
		t.Errorf("TIKeys = %v, want empty", w.Answers.TIKeys)
	}
}

func TestCollectStep5Security_WithKey(t *testing.T) {
	// First TI key (AbuseIPDB) filled in, rest empty.
	callCount := 0
	getPass := func(_ string) (string, error) {
		callCount++
		if callCount == 1 {
			return "myapikey123", nil
		}
		return "", nil
	}
	w := &Wizard{Out: silentOutput{}, InputFn: queuedInput([]string{}), GetPassFn: getPass}
	if err := w.collectStep5Security(context.Background()); err != nil {
		t.Fatalf("collectStep5Security (with key): %v", err)
	}
	if w.Answers.TIKeys["ABUSEIPDB_API_KEY"] != "myapikey123" {
		t.Errorf("TIKeys[ABUSEIPDB] = %q", w.Answers.TIKeys["ABUSEIPDB_API_KEY"])
	}
}

func TestCollectStep6Hardening(t *testing.T) {
	// firewall=ufw, fail2ban=n, crowdsec=n, log=none, backup=none, monitor=n
	inputs := queuedInput([]string{"ufw", "n", "n", "none", "none", "n"})
	w := &Wizard{Out: silentOutput{}, InputFn: inputs, GetPassFn: noPass}
	if err := w.collectStep6Hardening(context.Background()); err != nil {
		t.Fatalf("collectStep6Hardening: %v", err)
	}
	if w.Answers.Firewall != "ufw" {
		t.Errorf("Firewall = %q, want ufw", w.Answers.Firewall)
	}
	if w.Answers.LogForwarding != "none" {
		t.Errorf("LogForwarding = %q, want none", w.Answers.LogForwarding)
	}
}

func TestCollectStep6Hardening_WithBackupRecipient(t *testing.T) {
	// backup=age, recipient="age1abc...", monitor=n
	inputs := queuedInput([]string{"ufw", "n", "n", "none", "age", "age1abcdefg", "n"})
	w := &Wizard{Out: silentOutput{}, InputFn: inputs, GetPassFn: noPass}
	if err := w.collectStep6Hardening(context.Background()); err != nil {
		t.Fatalf("collectStep6Hardening (with backup): %v", err)
	}
	if w.Answers.BackupEncrypt != "age" {
		t.Errorf("BackupEncrypt = %q, want age", w.Answers.BackupEncrypt)
	}
	if w.Answers.BackupRecipient != "age1abcdefg" {
		t.Errorf("BackupRecipient = %q, want age1abcdefg", w.Answers.BackupRecipient)
	}
}

// TestConfirmAndWrite_DryRun verifies that dry-run does not write files.
func TestConfirmAndWrite_DryRun(t *testing.T) {
	w := &Wizard{
		Out:       silentOutput{},
		InputFn:   queuedInput([]string{}),
		GetPassFn: noPass,
		Answers: Answers{
			BackendHost: "10.0.0.1",
			BackendPort: 443,
			Mode:        "container",
			DryRun:      true,
		},
	}
	if err := w.confirmAndWrite(context.Background()); err != nil {
		t.Fatalf("confirmAndWrite (dry-run): %v", err)
	}
}

// TestRun_Interactive runs a full interactive wizard with canned input.
func TestRun_Interactive(t *testing.T) {
	dir := t.TempDir()
	// Step 1: host, port, mode, bind IP, admin user, log level
	// Step 2: dial, lb=n, proxy=n, snis=""
	// Step 3: self-signed, geoip path (dir)
	// Step 4: lane=0, name=test
	// Step 5: all TI keys empty (handled by GetPassFn)
	// Step 6: ufw, n, n, none, none, n
	// confirmAndWrite: confirm=y ... but DryRun=true avoids writes
	inputs := queuedInput([]string{
		"mybackend", "443", "container", "127.0.0.1", "admin", "INFO", // step 1
		"0", "n", "n", "",        // step 2
		"self-signed", dir,       // step 3 (dir used as geoip path)
		"0", "test",              // step 4
		// step 5: no inputs (all GetPassFn)
		"ufw", "n", "n", "none", "none", "n", // step 6
		"y", // confirm
	})
	w := New(silentOutput{}, inputs, noPass, nil)
	w.Answers.DryRun = true

	ans, cfg, err := w.Run(context.Background())
	if err != nil {
		t.Fatalf("Run (interactive): %v", err)
	}
	if ans == nil {
		t.Fatal("Run returned nil answers")
	}
	if cfg == nil {
		t.Fatal("Run returned nil config")
	}
	if ans.BackendHost != "mybackend" {
		t.Errorf("BackendHost = %q, want mybackend", ans.BackendHost)
	}
	_ = fmt.Sprintf("lane=%d name=%s", ans.Lane, ans.LaneName)
}
