package wizard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── validators ───────────────────────────────────────────────────────────────

func TestValidPort(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"443", true},
		{"1", true},
		{"65535", true},
		{"0", false},
		{"65536", false},
		{"-1", false},
		{"abc", false},
		{"", false},
	}
	for _, tc := range tests {
		got := validPort(tc.input)
		if got != tc.want {
			t.Errorf("validPort(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestValidBindIP(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"127.0.0.1", true},
		{"0.0.0.0", true},
		{"192.168.1.1", true},
		{"::1", true},
		{"", false},
		{"not-an-ip", false},
		{"300.300.300.300", false},
	}
	for _, tc := range tests {
		got := validBindIP(tc.input)
		if got != tc.want {
			t.Errorf("validBindIP(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestValidCertPath(t *testing.T) {
	// Create temp file to validate against
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(tmpFile, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		input string
		want  bool
	}{
		{tmpFile, true},
		{"/nonexistent/path", false},
		{tmpDir, false}, // directory, not file
		{"", false},
	}
	for _, tc := range tests {
		got := validCertPath(tc.input)
		if got != tc.want {
			t.Errorf("validCertPath(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestAtoi(t *testing.T) {
	tests := []struct {
		input string
		def   int
		want  int
	}{
		{"42", -1, 42},
		{"0", -1, 0},
		{"abc", 99, 99},
		{"", 5, 5},
		{"  7  ", -1, 7},
	}
	for _, tc := range tests {
		got := atoi(tc.input, tc.def)
		if got != tc.want {
			t.Errorf("atoi(%q, %d) = %d, want %d", tc.input, tc.def, got, tc.want)
		}
	}
}

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{"", nil},
		{"  a , b ", []string{"a", "b"}},
		{"single", []string{"single"}},
	}
	for _, tc := range tests {
		got := splitCSV(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("splitCSV(%q) = %v, want %v", tc.input, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitCSV(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

// ── secrets ──────────────────────────────────────────────────────────────────

func TestGenPassword(t *testing.T) {
	pw := genPassword(24)
	if len(pw) != 24 {
		t.Errorf("genPassword(24) length = %d, want 24", len(pw))
	}
	for _, c := range pw {
		if !strings.ContainsRune(letters, c) {
			t.Errorf("genPassword() produced invalid char %c", c)
		}
	}
	pw2 := genPassword(24)
	if pw == pw2 {
		t.Error("genPassword() produced identical passwords twice")
	}
}

func TestGenHexKey(t *testing.T) {
	key := genHexKey(32)
	if len(key) != 32 {
		t.Errorf("genHexKey(32) length = %d, want 32", len(key))
	}
	key2 := genHexKey(32)
	if key == key2 {
		t.Error("genHexKey() produced identical keys twice")
	}
}

// ── env builder ──────────────────────────────────────────────────────────────

func TestBuildEnv(t *testing.T) {
	a := &Answers{
		BackendHost:     "10.0.0.1",
		BackendPort:     443,
		Mode:            "container",
		BindIP:          "127.0.0.1",
		AdminUser:       "admin",
		LogLevel:        "INFO",
		DialValue:       0,
		Lane:            0,
		LaneName:        "prod",
		MonitoringStack: true,
		Firewall:        "ufw",
		Fail2Ban:        true,
		TLSCerts:        "self-signed",
	}
	env := buildEnv(a)
	checks := map[string]string{
		"BACKEND_HOST":      "10.0.0.1",
		"BACKEND_PORT":      "443",
		"AGENT_BIND_IP":     "127.0.0.1",
		"LOG_LEVEL":         "INFO",
		"MONITORING_STACK":  "true",
		"FIREWALL_BACKEND":  "ufw",
		"FAIL2BAN_ENABLED":  "true",
		"HOST_PORT_INGRESS": "443",
		"HOST_PORT_DIRECT":  "8081",
	}
	for k, want := range checks {
		if got := env[k]; got != want {
			t.Errorf("buildEnv[%s] = %q, want %q", k, got, want)
		}
	}
	if pw, ok := env["REDIS_PASSWORD"]; !ok || pw == "" {
		t.Error("buildEnv missing REDIS_PASSWORD or it's empty")
	}
	if pw, ok := env["MANAGEMENT_ADMIN_PASSWORD"]; !ok || pw == "" {
		t.Error("buildEnv missing MANAGEMENT_ADMIN_PASSWORD or it's empty")
	}
}

func TestBuildEnvLaneOffset(t *testing.T) {
	a := &Answers{BackendHost: "b", BackendPort: 443, Lane: 3, LaneName: "staging"}
	env := buildEnv(a)
	if got := env["HOST_PORT_INGRESS"]; got != "743" {
		t.Errorf("lane 3 ingress port = %s, want 743", got)
	}
	if got := env["HOST_PORT_DIRECT"]; got != "8381" {
		t.Errorf("lane 3 direct port = %s, want 8381", got)
	}
}

func TestBuildEnvWithTIKeys(t *testing.T) {
	a := &Answers{
		BackendHost: "b",
		BackendPort: 443,
		TIKeys:      map[string]string{"ABUSEIPDB_API_KEY": "abc123"},
	}
	env := buildEnv(a)
	if got := env["ABUSEIPDB_API_KEY"]; got != "abc123" {
		t.Errorf("TI key = %q, want abc123", got)
	}
}

func TestBuildEnvWritePROXY(t *testing.T) {
	a := &Answers{BackendHost: "b", BackendPort: 443, WritePROXY: true, PROXYVersion: 2}
	env := buildEnv(a)
	if got := env["WRITE_PROXY_PROTOCOL"]; got != "true" {
		t.Error("WRITE_PROXY_PROTOCOL not set to true")
	}
	if got := env["WRITE_PROXY_PROTOCOL_VERSION"]; got != "2" {
		t.Errorf("WRITE_PROXY_PROTOCOL_VERSION = %s, want 2", got)
	}
}

func TestBuildEnvDial(t *testing.T) {
	a := &Answers{BackendHost: "b", BackendPort: 443, DialValue: 75}
	env := buildEnv(a)
	if got := env["JA4PROXY_DIAL"]; got != "75" {
		t.Errorf("JA4PROXY_DIAL = %s, want 75", got)
	}
}

func TestRenderEnv(t *testing.T) {
	env := map[string]string{"KEY_A": "val1", "KEY_B": "val2"}
	rendered := renderEnv(env)
	if !strings.HasPrefix(rendered, "# Generated by") {
		t.Error("renderEnv missing header")
	}
	if !strings.Contains(rendered, "KEY_A=val1") {
		t.Error("renderEnv missing KEY_A")
	}
	if !strings.HasSuffix(strings.TrimSpace(rendered), "KEY_B=val2") {
		t.Error("renderEnv missing KEY_B at end")
	}
}

// TestRenderEnvRedacted is the regression for code-scanning alert 95
// (go/clear-text-logging): the dry-run .env preview must never expose secret
// values. Every secret key — generated secrets, the admin password, and dynamic
// threat-intel API keys — must render as the placeholder, while non-secret keys
// pass through unchanged.
func TestRenderEnvRedacted(t *testing.T) {
	a := &Answers{
		BackendHost:   "10.0.0.1",
		BackendPort:   443,
		AdminUser:     "admin",
		AdminPassword: "sup3r-s3cret-admin-pw",
		LogLevel:      "INFO",
		TIKeys:        map[string]string{"ABUSEIPDB_API_KEY": "ti-key-shh-do-not-log"},
	}

	full := buildEnv(a)             // disk path — must still carry real secrets
	preview := renderEnvRedacted(a) // stdout path — must be masked

	// Non-secret values still visible in the preview.
	if !strings.Contains(preview, "BACKEND_HOST=10.0.0.1") {
		t.Error("redacted preview dropped a non-secret key (BACKEND_HOST)")
	}
	if !strings.Contains(preview, "MANAGEMENT_ADMIN_USER=admin") {
		t.Error("redacted preview dropped MANAGEMENT_ADMIN_USER")
	}

	// Every generated secret key plus the admin password must be masked, and its
	// real value (present in the on-disk env) must be absent from the preview.
	for _, k := range secretEnvKeys {
		if !strings.Contains(preview, k+"=***REDACTED***") {
			t.Errorf("secret %s not redacted in preview", k)
		}
		if v := full[k]; v != "" && strings.Contains(preview, v) {
			t.Errorf("secret value for %s leaked into preview", k)
		}
	}

	// Dynamic threat-intel API keys are masked and their value never appears.
	if !strings.Contains(preview, "ABUSEIPDB_API_KEY=***REDACTED***") {
		t.Error("TI API key not redacted in preview")
	}
	if strings.Contains(preview, "ti-key-shh-do-not-log") {
		t.Error("TI API key value leaked into preview")
	}
	if strings.Contains(preview, "sup3r-s3cret-admin-pw") {
		t.Error("admin password leaked into preview")
	}
}

// ── lanes ────────────────────────────────────────────────────────────────────

func TestComputeLanePorts(t *testing.T) {
	ports := computeLanePorts(0)
	if ports["INGRESS"] != 443 {
		t.Errorf("lane 0 ingress = %d, want 443", ports["INGRESS"])
	}
	ports2 := computeLanePorts(2)
	if ports2["INGRESS"] != 643 {
		t.Errorf("lane 2 ingress = %d, want 643", ports2["INGRESS"])
	}
}

func TestParseEnvFile(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, ".env")
	content := "# comment\nREDIS_PASSWORD=secret123\nBACKEND_HOST=10.0.0.1\n\nEMPTY_LINE=\n"
	if err := os.WriteFile(envPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	env, err := parseEnvFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if env["REDIS_PASSWORD"] != "secret123" {
		t.Errorf("REDIS_PASSWORD = %q, want secret123", env["REDIS_PASSWORD"])
	}
	if env["BACKEND_HOST"] != "10.0.0.1" {
		t.Errorf("BACKEND_HOST = %q, want 10.0.0.1", env["BACKEND_HOST"])
	}
}

func TestParseEnvFileNotFound(t *testing.T) {
	_, err := parseEnvFile("/nonexistent/.env")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestDetectLanesFromFS(t *testing.T) {
	tmpDir := t.TempDir()
	envContent := "JA4_LANE=5\nJA4_LANE_NAME=staging\nCOMPOSE_PROJECT_NAME=ja4proxy-staging\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	lanes, err := detectLanesFromFS(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(lanes) != 1 {
		t.Fatalf("got %d lanes, want 1", len(lanes))
	}
	if lanes[0].Number != 5 {
		t.Errorf("lane number = %d, want 5", lanes[0].Number)
	}
	if lanes[0].Name != "staging" {
		t.Errorf("lane name = %s, want staging", lanes[0].Name)
	}
}

func TestDetectLanesFromFSNoEnv(t *testing.T) {
	tmpDir := t.TempDir()
	lanes, err := detectLanesFromFS(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(lanes) != 0 {
		t.Errorf("got %d lanes, want 0", len(lanes))
	}
}

func TestMergeEnvPreserveSecrets(t *testing.T) {
	tmpDir := t.TempDir()
	existingContent := "REDIS_PASSWORD=existing-secret\nBACKEND_HOST=10.0.0.1\nHOST_PORT_INGRESS=9999\n"
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte(existingContent), 0600); err != nil {
		t.Fatal(err)
	}

	newEnv := map[string]string{
		"REDIS_PASSWORD":    "new-secret",
		"BACKEND_HOST":      "10.0.0.2",
		"HOST_PORT_INGRESS": "443",
	}
	merged, err := mergeEnvPreserveSecrets(envPath, newEnv)
	if err != nil {
		t.Fatal(err)
	}

	// Secret should be preserved from existing
	if merged["REDIS_PASSWORD"] != "existing-secret" {
		t.Errorf("REDIS_PASSWORD = %q, want existing-secret", merged["REDIS_PASSWORD"])
	}
	// Non-secret should be replaced
	if merged["BACKEND_HOST"] != "10.0.0.2" {
		t.Errorf("BACKEND_HOST = %q, want 10.0.0.2", merged["BACKEND_HOST"])
	}
	if merged["HOST_PORT_INGRESS"] != "443" {
		t.Errorf("HOST_PORT_INGRESS = %q, want 443", merged["HOST_PORT_INGRESS"])
	}
}

func TestMergeEnvPreserveSecretsNoExisting(t *testing.T) {
	merged, err := mergeEnvPreserveSecrets("/nonexistent/.env", map[string]string{"KEY": "val"})
	if err != nil {
		t.Fatal(err)
	}
	if merged["KEY"] != "val" {
		t.Errorf("KEY = %q, want val", merged["KEY"])
	}
}

// ── systemd ──────────────────────────────────────────────────────────────────

func TestBuildSystemdContainer(t *testing.T) {
	a := &Answers{Mode: "container"}
	unit := buildSystemdUnit(a)
	if !strings.Contains(unit, "docker compose") {
		t.Error("container mode systemd missing docker compose")
	}
	if !strings.Contains(unit, "RemainAfterExit") {
		t.Error("container mode systemd missing RemainAfterExit")
	}
}

func TestBuildSystemdNative(t *testing.T) {
	a := &Answers{Mode: "native"}
	unit := buildSystemdUnit(a)
	if !strings.Contains(unit, "ja4pd --config") {
		t.Error("native mode systemd missing ja4pd binary")
	}
	if !strings.Contains(unit, "Type=simple") {
		t.Error("native mode systemd missing Type=simple")
	}
}

// ── templates ────────────────────────────────────────────────────────────────

func TestRenderProxyYML(t *testing.T) {
	data := TemplateData{
		BackendHost: "10.0.0.1",
		BackendPort: 443,
		BindIP:      "127.0.0.1",
		LogLevel:    "INFO",
		DialValue:   0,
		Mode:        "container",
	}
	output, err := RenderProxyYML(data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "10.0.0.1") {
		t.Error("proxy.yml missing backend host")
	}
	if !strings.Contains(output, "monitor") {
		t.Error("proxy.yml missing monitor mode for dial=0")
	}
}

func TestRenderProxyYMLWithWritePROXY(t *testing.T) {
	data := TemplateData{
		BackendHost:  "10.0.0.1",
		BackendPort:  443,
		WritePROXY:   true,
		PROXYVersion: 2,
	}
	output, err := RenderProxyYML(data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "write_proxy_protocol: true") {
		t.Error("proxy.yml missing write_proxy_protocol")
	}
	if !strings.Contains(output, "2") {
		t.Error("proxy.yml missing version 2")
	}
}

func TestRenderHAProxyCfg(t *testing.T) {
	data := TemplateData{}
	output, err := RenderHAProxyCfg(data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "frontend ja4proxy_ingress") {
		t.Error("haproxy.cfg missing frontend")
	}
}

func TestRenderSystemdService(t *testing.T) {
	data := TemplateData{Lane: 3, LaneName: "staging"}
	output, err := RenderSystemdService(data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "staging") {
		t.Error("systemd template missing lane name")
	}
}

// ── prompts (mock I/O) ───────────────────────────────────────────────────────

func TestAskWithDefault(t *testing.T) {
	input := func(prompt string) (string, error) {
		return "", nil // empty = use default
	}
	result, err := ask("test prompt", "default", func(s string) bool { return true }, input)
	if err != nil {
		t.Fatal(err)
	}
	if result != "default" {
		t.Errorf("ask returned %q, want default", result)
	}
}

func TestAskCustomValue(t *testing.T) {
	input := func(prompt string) (string, error) {
		return "custom", nil
	}
	result, err := ask("test", "", func(s string) bool { return s == "custom" }, input)
	if err != nil {
		t.Fatal(err)
	}
	if result != "custom" {
		t.Errorf("ask returned %q, want custom", result)
	}
}

func TestAskValidationRetry(t *testing.T) {
	attempts := 0
	input := func(prompt string) (string, error) {
		attempts++
		if attempts == 1 {
			return "invalid", nil
		}
		return "valid", nil
	}
	result, err := ask("test", "", func(s string) bool { return s == "valid" }, input)
	if err != nil {
		t.Fatal(err)
	}
	if result != "valid" {
		t.Errorf("ask returned %q, want valid", result)
	}
	if attempts != 2 {
		t.Errorf("ask took %d attempts, want 2", attempts)
	}
}

func TestAskYesNoDefaultYes(t *testing.T) {
	input := func(prompt string) (string, error) { return "", nil }
	result, err := askYesNo("test", true, input)
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Error("askYesNo default yes returned false")
	}
}

func TestAskYesNoDefaultNo(t *testing.T) {
	input := func(prompt string) (string, error) { return "", nil }
	result, err := askYesNo("test", false, input)
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Error("askYesNo default no returned true")
	}
}

func TestAskYesNoCustomYes(t *testing.T) {
	input := func(prompt string) (string, error) { return "y", nil }
	result, err := askYesNo("test", false, input)
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Error("askYesNo(y) should return true")
	}
}

func TestAskYesNoCustomNo(t *testing.T) {
	input := func(prompt string) (string, error) { return "n", nil }
	result, err := askYesNo("test", true, input)
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Error("askYesNo(n) should return false")
	}
}

// ── generateConfigs ──────────────────────────────────────────────────────────

func TestGenerateConfigs(t *testing.T) {
	out := &testOutput{}
	a := &Answers{
		BackendHost:     "10.0.0.50",
		BackendPort:     8443,
		Mode:            "container",
		BindIP:          "127.0.0.1",
		AdminUser:       "admin",
		LogLevel:        "INFO",
		DialValue:       0,
		Lane:            2,
		LaneName:        "staging",
		MonitoringStack: true,
		Firewall:        "ufw",
		TLSCerts:        "self-signed",
	}
	wiz := New(out, nil, nil, nil)
	wiz.Answers = *a

	cfg, err := wiz.generateConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("cfg is nil")
	}
	if cfg.Env == "" {
		t.Error("env content is empty")
	}
	if !strings.Contains(cfg.Env, "10.0.0.50") {
		t.Error("env missing backend host")
	}
	if !strings.Contains(cfg.Env, "staging") {
		t.Error("env missing lane name")
	}
	if cfg.ProxyYML == "" {
		t.Error("proxy.yml content is empty")
	}
	if cfg.HAProxy == "" {
		t.Error("haproxy.cfg should be generated for container mode")
	}
	if cfg.Systemd == "" {
		t.Error("systemd content is empty")
	}
}

func TestGenerateConfigsNativeMode(t *testing.T) {
	out := &testOutput{}
	a := &Answers{
		BackendHost: "10.0.0.1",
		BackendPort: 443,
		Mode:        "native",
		BindIP:      "127.0.0.1",
		AdminUser:   "admin",
		LogLevel:    "INFO",
		DialValue:   50,
		Lane:        0,
		TLSCerts:    "self-signed",
	}
	wiz := New(out, nil, nil, nil)
	wiz.Answers = *a

	cfg, err := wiz.generateConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProxyYML == "" {
		t.Error("proxy.yml content is empty")
	}
	if cfg.HAProxy != "" {
		t.Error("haproxy.cfg should be empty for native mode")
	}
	if !strings.Contains(cfg.ProxyYML, "dial") {
		t.Error("proxy.yml missing dial config")
	}
}

func TestGenerateConfigsWithTIKeys(t *testing.T) {
	out := &testOutput{}
	a := &Answers{
		BackendHost: "b",
		BackendPort: 443,
		TIKeys:      map[string]string{"ABUSEIPDB_API_KEY": "abc123"},
	}
	wiz := New(out, nil, nil, nil)
	wiz.Answers = *a

	cfg, err := wiz.generateConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg.Env, "ABUSEIPDB_API_KEY=abc123") {
		t.Error("env missing TI key")
	}
}

func TestGenerateConfigsDryRun(t *testing.T) {
	// generateConfigs should work identically regardless of DryRun flag
	out := &testOutput{}
	a := &Answers{
		BackendHost: "b",
		BackendPort: 443,
		DryRun:      true,
	}
	wiz := New(out, nil, nil, nil)
	wiz.Answers = *a

	cfg, err := wiz.generateConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Env == "" {
		t.Error("dry-run should still generate env content")
	}
}

func TestTemplateDataBuild(t *testing.T) {
	out := &testOutput{}
	a := &Answers{
		BackendHost:  "10.0.0.1",
		BackendPort:  443,
		Lane:         3,
		LaneName:     "prod",
		WritePROXY:   true,
		PROXYVersion: 2,
	}
	wiz := New(out, nil, nil, nil)
	wiz.Answers = *a

	data := wiz.buildTemplateData()
	if data.BackendHost != "10.0.0.1" {
		t.Errorf("BackendHost = %q, want 10.0.0.1", data.BackendHost)
	}
	if data.WritePROXY != true {
		t.Error("WritePROXY should be true")
	}
	if data.PROXYVersion != 2 {
		t.Errorf("PROXYVersion = %d, want 2", data.PROXYVersion)
	}
	if data.ProjectName != "ja4proxy-prod" {
		t.Errorf("ProjectName = %q, want ja4proxy-prod", data.ProjectName)
	}
	if data.Ports["INGRESS"] != 743 {
		t.Errorf("INGRESS port = %d, want 743", data.Ports["INGRESS"])
	}
}

func TestProjectName(t *testing.T) {
	tests := []struct {
		name     string
		lane     int
		laneName string
		want     string
	}{
		{"named lane", 0, "prod", "ja4proxy-prod"},
		{"numbered lane", 3, "default", "ja4proxy-lane3"},
		{"default name", 5, "", "ja4proxy-lane5"},
	}
	for _, tc := range tests {
		a := &Answers{Lane: tc.lane, LaneName: tc.laneName}
		got := projectName(a)
		if got != tc.want {
			t.Errorf("projectName(%d, %q) = %q, want %q", tc.lane, tc.laneName, got, tc.want)
		}
	}
}

// ── test helper ──────────────────────────────────────────────────────────────

type testOutput struct {
	lines []string
}

func (o *testOutput) Header(text string)  { o.lines = append(o.lines, "header:"+text) }
func (o *testOutput) Section(text string) { o.lines = append(o.lines, "section:"+text) }
func (o *testOutput) Info(f string, a ...interface{}) {
	o.lines = append(o.lines, "info:"+fmt.Sprintf(f, a...))
}
func (o *testOutput) Warn(f string, a ...interface{}) {
	o.lines = append(o.lines, "warn:"+fmt.Sprintf(f, a...))
}
func (o *testOutput) Success(f string, a ...interface{}) {
	o.lines = append(o.lines, "success:"+fmt.Sprintf(f, a...))
}
func (o *testOutput) Raw(text string) {
	o.lines = append(o.lines, "raw:"+text)
}
