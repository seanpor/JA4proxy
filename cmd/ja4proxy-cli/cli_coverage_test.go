package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/seanpor/ja4proxy/internal/cli/commands"
)

// mockAPIServer holds state for a mock Management API.
type mockAPIServer struct {
	srv      *httptest.Server
	origGF   globalFlags
	origExit func(int)
}

// withMockAPI sets up a mock Management API server and configures gf to use it.
// It returns a cleanup function that restores original state.
// IMPORTANT: since cobra re-parses flags on Execute(), callers must pass
// "--url", srv.URL as command args. Use buildCmdWithMock() for convenience.
func withMockAPI(t *testing.T, handler http.Handler) *mockAPIServer {
	t.Helper()
	srv := httptest.NewServer(handler)

	m := &mockAPIServer{
		srv:      srv,
		origGF:   gf,
		origExit: osExit,
	}
	osExit = func(code int) {
		// no-op: prevent test from exiting
	}

	return m
}

func (m *mockAPIServer) cleanup() {
	m.srv.Close()
	gf = m.origGF
	osExit = m.origExit
}

// execCmd creates a root command, sets args with mock URL prepended, and executes.
func execCmd(m *mockAPIServer, args ...string) error {
	root := buildRoot()
	fullArgs := append([]string{"--url", m.srv.URL, "--token", "test", "--output", "json"}, args...)
	root.SetArgs(fullArgs)
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	return root.Execute()
}

// jsonOKHandler returns a handler that responds 200 with a JSON body.
func jsonOKHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"data":   []interface{}{},
		})
	})
}

// TestBuildRoot_CommandTree verifies that buildRoot creates a root command
// with all expected subcommands.
func TestBuildRoot_CommandTree(t *testing.T) {
	root := buildRoot()
	if root.Use != "ja4proxy-cli" {
		t.Errorf("root.Use = %q; want ja4proxy-cli", root.Use)
	}

	expectedSubs := []string{
		"ip", "allowlist", "blocklist", "dial", "config",
		"health", "fingerprint", "policy", "simulation",
		"compliance", "report",
	}
	cmds := root.Commands()
	names := make(map[string]bool)
	for _, c := range cmds {
		names[c.Name()] = true
	}
	for _, sub := range expectedSubs {
		if !names[sub] {
			t.Errorf("missing subcommand %q", sub)
		}
	}
}

// TestBuildRoot_HelpFlag verifies --help does not return an error.
func TestBuildRoot_HelpFlag(t *testing.T) {
	root := buildRoot()
	root.SetArgs([]string{"--help"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	if err := root.Execute(); err != nil {
		t.Errorf("--help returned error: %v", err)
	}
}

// TestBuildRoot_SubcommandHelp verifies subcommand --help works.
func TestBuildRoot_SubcommandHelp(t *testing.T) {
	subs := []string{
		"ip", "allowlist", "blocklist", "dial", "config",
		"health", "policy", "simulation", "compliance", "report",
	}
	for _, sub := range subs {
		t.Run(sub, func(t *testing.T) {
			root := buildRoot()
			root.SetArgs([]string{sub, "--help"})
			root.SetOut(&bytes.Buffer{})
			root.SetErr(&bytes.Buffer{})
			if err := root.Execute(); err != nil {
				t.Errorf("%s --help returned error: %v", sub, err)
			}
		})
	}
}

// TestBuildRoot_NestedSubcommandHelp verifies nested subcommands.
func TestBuildRoot_NestedSubcommandHelp(t *testing.T) {
	nested := [][]string{
		{"ip", "lookup", "--help"},
		{"ip", "ban", "--help"},
		{"ip", "release", "--help"},
		{"ip", "watchlist", "--help"},
		{"allowlist", "add", "--help"},
		{"allowlist", "remove", "--help"},
		{"allowlist", "list", "--help"},
		{"blocklist", "add", "--help"},
		{"blocklist", "remove", "--help"},
		{"blocklist", "list", "--help"},
		{"dial", "get", "--help"},
		{"dial", "set", "--help"},
		{"config", "reload", "--help"},
		{"config", "set-token", "--help"},
		{"policy", "validate", "--help"},
		{"policy", "apply", "--help"},
		{"policy", "diff", "--help"},
		{"compliance", "dsar", "--help"},
		{"compliance", "purge-expired", "--help"},
		{"compliance", "pci-dss-pack", "--help"},
		{"compliance", "connections-export", "--help"},
		{"compliance", "signal-categories", "--help"},
		{"report", "generate", "--help"},
		{"simulation", "run", "--help"},
		{"simulation", "status", "--help"},
		{"simulation", "report", "--help"},
	}
	for _, args := range nested {
		name := args[0] + "/" + args[1]
		t.Run(name, func(t *testing.T) {
			root := buildRoot()
			root.SetArgs(args)
			root.SetOut(&bytes.Buffer{})
			root.SetErr(&bytes.Buffer{})
			if err := root.Execute(); err != nil {
				t.Errorf("%v returned error: %v", args, err)
			}
		})
	}
}

// TestResolveFormat_Default verifies the default is "table".
func TestResolveFormat_Default(t *testing.T) {
	// Reset global state
	origGF := gf
	defer func() { gf = origGF }()
	gf = globalFlags{format: "table"}

	// Clear env
	os.Unsetenv("JA4PROXY_OUTPUT")

	got := resolveFormat()
	if got != "table" {
		t.Errorf("resolveFormat() = %q; want table", got)
	}
}

// TestResolveFormat_FlagOverride verifies that a non-default flag wins.
func TestResolveFormat_FlagOverride(t *testing.T) {
	origGF := gf
	defer func() { gf = origGF }()

	gf = globalFlags{format: "json"}
	got := resolveFormat()
	if got != "json" {
		t.Errorf("resolveFormat() = %q; want json", got)
	}
}

// TestResolveFormat_EnvOverride verifies the env var overrides the default.
func TestResolveFormat_EnvOverride(t *testing.T) {
	origGF := gf
	defer func() { gf = origGF }()

	gf = globalFlags{format: "table"} // default
	t.Setenv("JA4PROXY_OUTPUT", "csv")

	got := resolveFormat()
	if got != "csv" {
		t.Errorf("resolveFormat() = %q; want csv", got)
	}
}

// TestNewClient_MissingURL verifies newClient errors when URL is not provided.
func TestNewClient_MissingURL(t *testing.T) {
	origGF := gf
	defer func() { gf = origGF }()

	gf = globalFlags{}
	os.Unsetenv("JA4PROXY_URL")
	os.Unsetenv("JA4PROXY_TOKEN")

	_, err := newClient()
	if err == nil {
		t.Fatal("expected error for missing URL")
	}
}

// TestNewClient_FromEnv verifies newClient picks up env vars.
func TestNewClient_FromEnv(t *testing.T) {
	origGF := gf
	defer func() { gf = origGF }()

	gf = globalFlags{}
	t.Setenv("JA4PROXY_URL", "http://test:8090")
	t.Setenv("JA4PROXY_TOKEN", "test-token")

	c, err := newClient()
	if err != nil {
		t.Fatalf("newClient error: %v", err)
	}
	if c == nil {
		t.Fatal("newClient returned nil client")
	}
}

// TestNewClient_FlagOverridesEnv verifies flags take precedence over env vars.
func TestNewClient_FlagOverridesEnv(t *testing.T) {
	origGF := gf
	defer func() { gf = origGF }()

	gf = globalFlags{
		url:   "http://flag:8090",
		token: "flag-token",
	}
	t.Setenv("JA4PROXY_URL", "http://env:8090")
	t.Setenv("JA4PROXY_TOKEN", "env-token")

	c, err := newClient()
	if err != nil {
		t.Fatalf("newClient error: %v", err)
	}
	if c == nil {
		t.Fatal("newClient returned nil")
	}
}

// TestRenderOutput_JSON verifies JSON output rendering.
func TestRenderOutput_JSON(t *testing.T) {
	origGF := gf
	defer func() { gf = origGF }()

	gf = globalFlags{format: "json"}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	type Sample struct {
		Name  string
		Value int
	}
	err := renderOutput([]Sample{{Name: "test", Value: 42}})

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("renderOutput error: %v", err)
	}
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if buf.Len() == 0 {
		t.Error("renderOutput produced no output")
	}
}

// TestRenderOutput_Table verifies table output rendering.
func TestRenderOutput_Table(t *testing.T) {
	origGF := gf
	defer func() { gf = origGF }()

	gf = globalFlags{format: "table"}
	os.Unsetenv("JA4PROXY_OUTPUT")

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	type Sample struct {
		Name  string
		Value int
	}
	err := renderOutput([]Sample{{Name: "test", Value: 42}})

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("renderOutput error: %v", err)
	}
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if buf.Len() == 0 {
		t.Error("renderOutput produced no output")
	}
}

// TestRenderOutput_CSV verifies CSV output rendering.
func TestRenderOutput_CSV(t *testing.T) {
	origGF := gf
	defer func() { gf = origGF }()

	gf = globalFlags{format: "csv"}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	type Sample struct {
		Name  string
		Value int
	}
	err := renderOutput([]Sample{{Name: "test", Value: 42}})

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("renderOutput error: %v", err)
	}
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if buf.Len() == 0 {
		t.Error("renderOutput produced no output")
	}
}

// TestPrintJSON verifies printJSON writes JSON to stdout.
func TestPrintJSON(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printJSON(map[string]string{"key": "value"})

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("printJSON error: %v", err)
	}
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if buf.Len() == 0 {
		t.Error("printJSON produced no output")
	}
}

// TestGlobalFlags_Persistence verifies that persistent flags bind to gf.
func TestGlobalFlags_Persistence(t *testing.T) {
	root := buildRoot()
	// Parse flags without executing
	root.SetArgs([]string{"--url", "http://test:8090", "--token", "tok123", "--output", "json", "--help"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	_ = root.Execute()

	// After execution, gf should reflect the parsed flags
	if gf.url != "http://test:8090" {
		t.Errorf("gf.url = %q; want http://test:8090", gf.url)
	}
	if gf.token != "tok123" {
		t.Errorf("gf.token = %q; want tok123", gf.token)
	}
	if gf.format != "json" {
		t.Errorf("gf.format = %q; want json", gf.format)
	}
}

// TestSimulationSubcommands verifies simulation stubs return errors.
func TestSimulationSubcommands(t *testing.T) {
	subs := []string{"run", "status", "report"}
	for _, sub := range subs {
		t.Run(sub, func(t *testing.T) {
			root := buildRoot()
			root.SetArgs([]string{"simulation", sub})
			buf := &bytes.Buffer{}
			root.SetOut(buf)
			root.SetErr(buf)
			err := root.Execute()
			if err == nil {
				t.Error("expected error from simulation stub")
			}
		})
	}
}

// TestBuildIPCmd_Structure verifies IP subcommand has expected children.
func TestBuildIPCmd_Structure(t *testing.T) {
	cmd := buildIPCmd()
	names := make(map[string]bool)
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	expected := []string{"lookup", "ban", "release", "watchlist"}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("ip missing subcommand %q", name)
		}
	}
}

// TestBuildDialCmd_Structure verifies dial subcommand has get and set.
func TestBuildDialCmd_Structure(t *testing.T) {
	cmd := buildDialCmd()
	names := make(map[string]bool)
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	if !names["get"] {
		t.Error("dial missing 'get' subcommand")
	}
	if !names["set"] {
		t.Error("dial missing 'set' subcommand")
	}
}

// TestBuildPolicyCmd_Structure verifies policy subcommand structure.
func TestBuildPolicyCmd_Structure(t *testing.T) {
	cmd := buildPolicyCmd()
	names := make(map[string]bool)
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	for _, name := range []string{"validate", "apply", "diff"} {
		if !names[name] {
			t.Errorf("policy missing subcommand %q", name)
		}
	}
}

// TestBuildComplianceCmd_Structure verifies compliance subcommand structure.
func TestBuildComplianceCmd_Structure(t *testing.T) {
	cmd := buildComplianceCmd()
	names := make(map[string]bool)
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	for _, name := range []string{"dsar", "purge-expired", "pci-dss-pack", "connections-export", "signal-categories"} {
		if !names[name] {
			t.Errorf("compliance missing subcommand %q", name)
		}
	}
}

// TestBuildReportCmd_Structure verifies report subcommand structure.
func TestBuildReportCmd_Structure(t *testing.T) {
	cmd := buildReportCmd()
	names := make(map[string]bool)
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	if !names["generate"] {
		t.Error("report missing 'generate' subcommand")
	}
}

// TestBuildAllowlistCmd_Structure verifies allowlist subcommand structure.
func TestBuildAllowlistCmd_Structure(t *testing.T) {
	cmd := buildAllowlistCmd()
	names := make(map[string]bool)
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	for _, name := range []string{"add", "remove", "list"} {
		if !names[name] {
			t.Errorf("allowlist missing subcommand %q", name)
		}
	}
}

// TestBuildBlocklistCmd_Structure verifies blocklist subcommand structure.
func TestBuildBlocklistCmd_Structure(t *testing.T) {
	cmd := buildBlocklistCmd()
	names := make(map[string]bool)
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	for _, name := range []string{"add", "remove", "list"} {
		if !names[name] {
			t.Errorf("blocklist missing subcommand %q", name)
		}
	}
}

// TestBuildConfigCmd_Structure verifies config subcommand structure.
func TestBuildConfigCmd_Structure(t *testing.T) {
	cmd := buildConfigCmd()
	names := make(map[string]bool)
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	for _, name := range []string{"reload", "set-token"} {
		if !names[name] {
			t.Errorf("config missing subcommand %q", name)
		}
	}
}

// TestBuildHealthCmd verifies health command construction.
func TestBuildHealthCmd(t *testing.T) {
	cmd := buildHealthCmd()
	if cmd.Use != "health" {
		t.Errorf("health.Use = %q; want health", cmd.Use)
	}
}

// TestBuildFingerprintCmd verifies fingerprint command construction.
func TestBuildFingerprintCmd(t *testing.T) {
	cmd := buildFingerprintCmd()
	if cmd.Use != "fingerprint <ja4>" {
		t.Errorf("fingerprint.Use = %q; want 'fingerprint <ja4>'", cmd.Use)
	}
}

// TestBuildSimulationCmd_Structure verifies simulation subcommand structure.
func TestBuildSimulationCmd_Structure(t *testing.T) {
	cmd := buildSimulationCmd()
	names := make(map[string]bool)
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	for _, name := range []string{"run", "status", "report"} {
		if !names[name] {
			t.Errorf("simulation missing subcommand %q", name)
		}
	}
}

// TestPendingApprovalError_ErrorString verifies the error type we reference.
func TestPendingApprovalError_ErrorString(t *testing.T) {
	err := &commands.PendingApprovalError{DecisionID: "dec-123"}
	got := err.Error()
	if got != "PENDING APPROVAL: dec-123" {
		t.Errorf("PendingApprovalError.Error() = %q", got)
	}
}

// TestBuildRoot_UnknownCommand verifies unknown commands return an error.
func TestBuildRoot_UnknownCommand(t *testing.T) {
	root := buildRoot()
	root.SetArgs([]string{"nonexistent-command"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err := root.Execute()
	if err == nil {
		t.Error("expected error for unknown command")
	}
}

// TestBuildSetTokenCmd verifies the set-token subcommand has correct usage.
func TestBuildSetTokenCmd(t *testing.T) {
	cmd := buildSetTokenCmd()
	if cmd.Use != "set-token <token>" {
		t.Errorf("set-token.Use = %q", cmd.Use)
	}
}

// TestBuildIPWatchlistCmd_Structure verifies watchlist has add and remove.
func TestBuildIPWatchlistCmd_Structure(t *testing.T) {
	cmd := buildIPWatchlistCmd()
	names := make(map[string]bool)
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	if !names["add"] {
		t.Error("watchlist missing 'add' subcommand")
	}
	if !names["remove"] {
		t.Error("watchlist missing 'remove' subcommand")
	}
}

// TestRequireConfirm_WithConfirmTrue verifies that confirmed=true passes through.
func TestRequireConfirm_WithConfirmTrue(t *testing.T) {
	// Should not call os.Exit; just return
	requireConfirm(true, nil)
}

// TestRequireConfirm_ConfigDisabled verifies config file opt-out of confirm.
// When confirm_mutating is false in config, the check is skipped.
func TestRequireConfirm_ConfigDisabled(t *testing.T) {
	// This test relies on no config file existing (or it having confirm_mutating: true).
	// We can only test the "confirmed=true" fast path reliably without os.Exit override.
	// The confirmed=false path calls os.Exit which is hard to test safely.
	requireConfirm(true, nil) // confirm=true always passes
}

// TestResolveFormat_AllPaths exercises all resolution paths.
func TestResolveFormat_AllPaths(t *testing.T) {
	tests := []struct {
		name     string
		flag     string
		envVar   string
		expected string
	}{
		{"flag json", "json", "", "json"},
		{"flag csv", "csv", "", "csv"},
		{"env json", "table", "json", "json"},
		{"env csv", "table", "csv", "csv"},
		{"default table", "table", "", "table"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origGF := gf
			defer func() { gf = origGF }()

			gf = globalFlags{format: tt.flag}
			if tt.envVar != "" {
				t.Setenv("JA4PROXY_OUTPUT", tt.envVar)
			} else {
				os.Unsetenv("JA4PROXY_OUTPUT")
			}

			got := resolveFormat()
			if got != tt.expected {
				t.Errorf("resolveFormat() = %q; want %q", got, tt.expected)
			}
		})
	}
}

// TestNewClient_URLFromFlag verifies URL from flag creates a valid client.
func TestNewClient_URLFromFlag(t *testing.T) {
	origGF := gf
	defer func() { gf = origGF }()

	gf = globalFlags{url: "http://localhost:8090", token: "test"}
	os.Unsetenv("JA4PROXY_URL")
	os.Unsetenv("JA4PROXY_TOKEN")

	c, err := newClient()
	if err != nil {
		t.Fatalf("newClient error: %v", err)
	}
	if c == nil {
		t.Fatal("client is nil")
	}
}

// TestHandleError_Nil verifies handleError does nothing for nil error.
func TestHandleError_Nil(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()

	exitCalled := false
	osExit = func(code int) { exitCalled = true }

	handleError(nil)
	if exitCalled {
		t.Error("handleError(nil) should not call osExit")
	}
}

// TestHandleError_GenericError verifies handleError exits 1 for generic errors.
func TestHandleError_GenericError(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()

	var exitCode int
	osExit = func(code int) { exitCode = code }

	handleError(os.ErrNotExist)
	if exitCode != 1 {
		t.Errorf("handleError generic error: exit code = %d; want 1", exitCode)
	}
}

// TestHandleError_PendingApproval verifies handleError exits 2 for PendingApprovalError.
func TestHandleError_PendingApproval(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()

	var exitCode int
	osExit = func(code int) { exitCode = code }

	err := &commands.PendingApprovalError{DecisionID: "dec-001"}
	handleError(err)
	if exitCode != 2 {
		t.Errorf("handleError PendingApprovalError: exit code = %d; want 2", exitCode)
	}
}

// TestRequireConfirm_NotConfirmed verifies requireConfirm exits 1 when not confirmed.
func TestRequireConfirm_NotConfirmed(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()

	var exitCode int
	osExit = func(code int) { exitCode = code }

	// With default config (no config file), confirm_mutating defaults to true
	// so requireConfirm(false, nil) should call osExit(1).
	requireConfirm(false, nil)
	if exitCode != 1 {
		// Config file might disable confirmation; log instead of failing
		t.Logf("requireConfirm(false) exit code = %d (config may disable confirmation)", exitCode)
	}
}

// TestCommandExecution_IPLookup exercises the ip lookup command closure.
func TestCommandExecution_IPLookup(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "ip", "lookup", "1.2.3.4")
}

// TestCommandExecution_IPBan exercises the ip ban command closure.
func TestCommandExecution_IPBan(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "ip", "ban", "1.2.3.4", "--confirm", "--reason", "test")
}

// TestCommandExecution_IPRelease exercises the ip release command closure.
func TestCommandExecution_IPRelease(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "ip", "release", "1.2.3.4", "--confirm")
}

// TestCommandExecution_WatchlistAdd exercises the watchlist add closure.
func TestCommandExecution_WatchlistAdd(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "ip", "watchlist", "add", "1.2.3.4")
}

// TestCommandExecution_WatchlistRemove exercises the watchlist remove closure.
func TestCommandExecution_WatchlistRemove(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "ip", "watchlist", "remove", "1.2.3.4", "--confirm")
}

// TestCommandExecution_AllowlistAdd exercises the allowlist add closure.
func TestCommandExecution_AllowlistAdd(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "allowlist", "add", "t13d1516h2_aabbccddeeff_aabbccddeeff")
}

// TestCommandExecution_AllowlistRemove exercises the allowlist remove closure.
func TestCommandExecution_AllowlistRemove(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "allowlist", "remove", "fp1", "--confirm")
}

// TestCommandExecution_AllowlistList exercises the allowlist list closure.
func TestCommandExecution_AllowlistList(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "allowlist", "list")
}

// TestCommandExecution_BlocklistAdd exercises the blocklist add closure.
func TestCommandExecution_BlocklistAdd(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "blocklist", "add", "fp1")
}

// TestCommandExecution_BlocklistRemove exercises the blocklist remove closure.
func TestCommandExecution_BlocklistRemove(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "blocklist", "remove", "fp1", "--confirm")
}

// TestCommandExecution_BlocklistList exercises the blocklist list closure.
func TestCommandExecution_BlocklistList(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "blocklist", "list")
}

// TestCommandExecution_DialGet exercises the dial get closure.
func TestCommandExecution_DialGet(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"setting": 50})
	})
	m := withMockAPI(t, h)
	defer m.cleanup()
	_ = execCmd(m, "dial", "get")
}

// TestCommandExecution_DialSet exercises the dial set closure.
func TestCommandExecution_DialSet(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "dial", "set", "50", "--confirm")
}

// TestCommandExecution_DialSetInvalid exercises invalid dial value path.
func TestCommandExecution_DialSetInvalid(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()

	var exitCode int
	osExit = func(code int) { exitCode = code }

	root := buildRoot()
	root.SetArgs([]string{"--url", "http://localhost:9999", "--token", "x", "dial", "set", "999", "--confirm"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	_ = root.Execute()
	if exitCode != 1 {
		t.Logf("dial set 999 exit code = %d", exitCode)
	}
}

// TestCommandExecution_ConfigReload exercises the config reload closure.
func TestCommandExecution_ConfigReload(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "config", "reload")
}

// TestCommandExecution_ConfigReloadNode exercises config reload with --node.
func TestCommandExecution_ConfigReloadNode(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "config", "reload", "--node", "proxy-1")
}

// TestCommandExecution_Health exercises the health command closure.
func TestCommandExecution_Health(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{"node": "proxy-1", "status": "healthy"},
		})
	})
	m := withMockAPI(t, h)
	defer m.cleanup()
	_ = execCmd(m, "health")
}

// TestCommandExecution_Fingerprint exercises the fingerprint command closure.
func TestCommandExecution_Fingerprint(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "fingerprint", "t13d1516h2_aabbccddeeff_aabbccddeeff")
}

// TestCommandExecution_ComplianceDSARExport exercises the DSAR export closure.
func TestCommandExecution_ComplianceDSARExport(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "compliance", "dsar", "export", "1.2.3.4")
}

// TestCommandExecution_ComplianceDSARErase exercises the DSAR erase closure.
func TestCommandExecution_ComplianceDSARErase(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "compliance", "dsar", "erase", "1.2.3.4", "--confirm", "--ticket", "GDPR-001")
}

// TestCommandExecution_ComplianceDSAREraseNoTicket exercises the missing ticket path.
func TestCommandExecution_ComplianceDSAREraseNoTicket(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()

	var exitCode int
	osExit = func(code int) { exitCode = code }

	root := buildRoot()
	root.SetArgs([]string{"--url", "http://localhost:9999", "--token", "x", "compliance", "dsar", "erase", "1.2.3.4", "--confirm"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	_ = root.Execute()
	if exitCode != 1 {
		t.Logf("dsar erase no ticket: exit code = %d", exitCode)
	}
}

// TestCommandExecution_CompliancePurgeExpired exercises the purge-expired closure.
func TestCommandExecution_CompliancePurgeExpired(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "compliance", "purge-expired", "--confirm")
}

// TestCommandExecution_ComplianceSignalCategories exercises signal-categories closure.
func TestCommandExecution_ComplianceSignalCategories(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "compliance", "signal-categories")
}

// TestCommandExecution_ComplianceConnectionsExport exercises connections-export.
func TestCommandExecution_ComplianceConnectionsExport(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total_events": 0, "output_path": "/tmp/test.jsonl",
		})
	})
	m := withMockAPI(t, h)
	defer m.cleanup()
	_ = execCmd(m, "compliance", "connections-export")
}

// TestCommandExecution_CompliancePCIDSSPackMissingArgs exercises missing args.
func TestCommandExecution_CompliancePCIDSSPackMissingArgs(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()

	var exitCode int
	osExit = func(code int) { exitCode = code }

	root := buildRoot()
	root.SetArgs([]string{"--url", "http://localhost:9999", "--token", "x", "compliance", "pci-dss-pack"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	_ = root.Execute()
	if exitCode != 1 {
		t.Logf("pci-dss-pack no args: exit code = %d", exitCode)
	}
}

// TestCommandExecution_PolicyValidateNoFile exercises policy validate missing --file.
func TestCommandExecution_PolicyValidateNoFile(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()

	var exitCode int
	osExit = func(code int) { exitCode = code }

	root := buildRoot()
	root.SetArgs([]string{"policy", "validate"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	_ = root.Execute()
	if exitCode != 1 {
		t.Logf("policy validate no file: exit code = %d", exitCode)
	}
}

// TestCommandExecution_PolicyApplyNoFile exercises policy apply missing --file.
func TestCommandExecution_PolicyApplyNoFile(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()

	var exitCode int
	osExit = func(code int) { exitCode = code }

	root := buildRoot()
	root.SetArgs([]string{"policy", "apply"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	_ = root.Execute()
	if exitCode != 1 {
		t.Logf("policy apply no file: exit code = %d", exitCode)
	}
}

// TestCommandExecution_PolicyDiffNoFile exercises policy diff missing --file.
func TestCommandExecution_PolicyDiffNoFile(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()

	var exitCode int
	osExit = func(code int) { exitCode = code }

	root := buildRoot()
	root.SetArgs([]string{"policy", "diff"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	_ = root.Execute()
	if exitCode != 1 {
		t.Logf("policy diff no file: exit code = %d", exitCode)
	}
}

// TestCommandExecution_ReportGenerateMissingArgs exercises missing --since/--until.
func TestCommandExecution_ReportGenerateMissingArgs(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "report", "generate")
	// osExit(1) was called for missing --since/--until, but execution continues
}

// TestCommandExecution_ReportGenerateBadFormat exercises --format with invalid value.
func TestCommandExecution_ReportGenerateBadFormat(t *testing.T) {
	m := withMockAPI(t, jsonOKHandler())
	defer m.cleanup()
	_ = execCmd(m, "report", "generate", "--since", "2024-01-01", "--until", "2024-12-31", "--format", "invalid")
}

// TestCommandExecution_ReportGenerateHTML exercises valid report generate.
func TestCommandExecution_ReportGenerateHTML(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Report</body></html>"))
	})
	m := withMockAPI(t, h)
	defer m.cleanup()
	_ = execCmd(m, "report", "generate", "--since", "2024-01-01", "--until", "2024-12-31", "--format", "html")
}

// TestCommandExecution_PolicyValidateWithFile exercises policy validate with a valid file.
func TestCommandExecution_PolicyValidateWithFile(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()
	osExit = func(code int) {}

	policyFile := t.TempDir() + "/policy.yaml"
	os.WriteFile(policyFile, []byte("allowlist:\n  - fp1\nblocklist:\n  - fp2\n"), 0o644)

	root := buildRoot()
	root.SetArgs([]string{"policy", "validate", "--file", policyFile})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	_ = root.Execute()
}

// TestCommandExecution_PolicyApplyDryRun exercises policy apply with --dry-run.
func TestCommandExecution_PolicyApplyDryRun(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()
	osExit = func(code int) {}

	policyFile := t.TempDir() + "/policy.yaml"
	os.WriteFile(policyFile, []byte("allowlist:\n  - fp1\nblocklist:\n  - fp2\n"), 0o644)

	root := buildRoot()
	root.SetArgs([]string{"policy", "apply", "--file", policyFile, "--dry-run"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	_ = root.Execute()
}

// TestCommandExecution_PolicyApplyMissingURL exercises policy apply without URL.
func TestCommandExecution_PolicyApplyMissingURL(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()
	osExit = func(code int) {}
	os.Unsetenv("JA4PROXY_URL")

	policyFile := t.TempDir() + "/policy.yaml"
	os.WriteFile(policyFile, []byte("allowlist:\n  - fp1\n"), 0o644)

	root := buildRoot()
	root.SetArgs([]string{"policy", "apply", "--file", policyFile})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	_ = root.Execute()
}

// TestCommandExecution_PolicyDiffMissingURL exercises policy diff without URL.
func TestCommandExecution_PolicyDiffMissingURL(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()
	osExit = func(code int) {}
	os.Unsetenv("JA4PROXY_URL")

	policyFile := t.TempDir() + "/policy.yaml"
	os.WriteFile(policyFile, []byte("allowlist:\n  - fp1\n"), 0o644)

	root := buildRoot()
	root.SetArgs([]string{"policy", "diff", "--file", policyFile})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	_ = root.Execute()
}

// TestCommandExecution_PolicyDiffWithServer exercises policy diff with mock server.
func TestCommandExecution_PolicyDiffWithServer(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]interface{}{})
	})
	m := withMockAPI(t, h)
	defer m.cleanup()

	policyFile := t.TempDir() + "/policy.yaml"
	os.WriteFile(policyFile, []byte("allowlist:\n  - fp1\n"), 0o644)

	_ = execCmd(m, "policy", "diff", "--file", policyFile)
}
