package wizard

import (
	"context"
	"os"
	"strings"
	"testing"
)

// -- collectStep3TLS coverage --

// TestCollectStep3TLS_UserSupplied covers the "user-supplied" cert branch
// that requires cert/key paths.
func TestCollectStep3TLS_UserSupplied(t *testing.T) {
	certFile := t.TempDir() + "/cert.pem"
	keyFile := t.TempDir() + "/key.pem"
	os.WriteFile(certFile, []byte("dummy"), 0600)
	os.WriteFile(keyFile, []byte("dummy"), 0600)

	geoDir := t.TempDir()
	inputs := queuedInput([]string{"user-supplied", certFile, keyFile, geoDir})
	w := &Wizard{Out: silentOutput{}, InputFn: inputs, GetPassFn: noPass}
	if err := w.collectStep3TLS(context.Background()); err != nil {
		t.Fatalf("collectStep3TLS user-supplied: %v", err)
	}
	if w.Answers.TLSCerts != "user-supplied" {
		t.Errorf("TLSCerts = %q; want user-supplied", w.Answers.TLSCerts)
	}
	if w.Answers.TLSCertPath != certFile {
		t.Errorf("TLSCertPath = %q; want %q", w.Answers.TLSCertPath, certFile)
	}
}

// -- collectStep4Lane coverage --

// TestCollectStep4Lane_WithLanes_ChooseExisting covers the hasLanes=true →
// laneChoice="existing" branch.
func TestCollectStep4Lane_WithLanes_ChooseExisting(t *testing.T) {
	lm := &stubLaneManager{lanes: []LaneInfo{
		{Number: 1, Name: "prod", Path: "/srv/lane1"},
	}}
	// choose existing, then lane number "1", then name "prod"
	inputs := queuedInput([]string{"existing", "1", "prod"})
	w := &Wizard{Out: silentOutput{}, InputFn: inputs, GetPassFn: noPass, LaneManager: lm}
	if err := w.collectStep4Lane(context.Background()); err != nil {
		t.Fatalf("collectStep4Lane existing: %v", err)
	}
	if w.Answers.Lane != 1 {
		t.Errorf("Lane = %d; want 1", w.Answers.Lane)
	}
}

// TestCollectStep4Lane_WithLanes_ChooseNew covers the hasLanes=true → "new" branch.
func TestCollectStep4Lane_WithLanes_ChooseNew(t *testing.T) {
	lm := &stubLaneManager{lanes: []LaneInfo{
		{Number: 1, Name: "prod", Path: "/srv/lane1"},
	}}
	// choose new, then the lane-creation prompts (lane=0, name=staging)
	inputs := queuedInput([]string{"new", "staging"})
	w := &Wizard{Out: silentOutput{}, InputFn: inputs, GetPassFn: noPass, LaneManager: lm}
	if err := w.collectStep4Lane(context.Background()); err != nil {
		t.Fatalf("collectStep4Lane new: %v", err)
	}
	if w.Answers.LaneName != "staging" {
		t.Errorf("LaneName = %q; want staging", w.Answers.LaneName)
	}
}

// stubLaneManager satisfies the LaneManager interface for tests.
type stubLaneManager struct {
	lanes []LaneInfo
	err   error
}

func (s *stubLaneManager) ListLanes(_ context.Context) ([]LaneInfo, error) {
	return s.lanes, s.err
}
func (s *stubLaneManager) PreviewPorts(_ int) (map[string]int, error) {
	return map[string]int{"INGRESS": 443}, nil
}
func (s *stubLaneManager) AssignLane(_ context.Context, _ int) (LaneInfo, error) {
	if len(s.lanes) > 0 {
		return s.lanes[0], nil
	}
	return LaneInfo{Number: 1}, nil
}

// -- confirmAndWrite coverage --

// TestConfirmAndWrite_NonInteractive verifies that NonInteractive=true skips
// the confirmation prompt and writes files.
func TestConfirmAndWrite_NonInteractive(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(orig)

	w := &Wizard{
		Out:            silentOutput{},
		InputFn:        queuedInput([]string{}),
		GetPassFn:      noPass,
		NonInteractive: true,
		Answers: Answers{
			BackendHost: "10.0.0.1",
			BackendPort: 443,
			Mode:        "container",
			LaneName:    "test",
		},
	}
	if err := w.confirmAndWrite(context.Background()); err != nil {
		// Might fail writing /etc/systemd/system — that's OK.
		if !strings.Contains(err.Error(), "systemd") && !strings.Contains(err.Error(), "permission") {
			t.Fatalf("confirmAndWrite non-interactive: %v", err)
		}
	}
	// At minimum, .env and config/proxy.yml should be written.
	if _, err := os.Stat(dir + "/.env"); err != nil {
		t.Error("expected .env to be written")
	}
}

// TestConfirmAndWrite_InteractiveAbort covers the "user says no" branch.
func TestConfirmAndWrite_InteractiveAbort(t *testing.T) {
	w := &Wizard{
		Out:       silentOutput{},
		InputFn:   queuedInput([]string{"n"}),
		GetPassFn: noPass,
		Answers: Answers{
			BackendHost: "10.0.0.1",
			BackendPort: 443,
			Mode:        "container",
		},
	}
	if err := w.confirmAndWrite(context.Background()); err != nil {
		t.Fatalf("confirmAndWrite abort: %v", err)
	}
	// No files should be written (no panic = success).
}

// -- buildPublicEnv coverage --

// TestBuildPublicEnv_AllOptionalFields covers the optional branches in
// buildPublicEnv that are not triggered by the default empty Answers.
func TestBuildPublicEnv_AllOptionalFields(t *testing.T) {
	a := &Answers{
		BackendHost:     "backend.internal",
		BackendPort:     443,
		BindIP:          "0.0.0.0",
		AdminUser:       "admin",
		LogLevel:        "info",
		LaneName:        "prod",
		Lane:            1,
		MonitoringStack: true,
		Firewall:        "ufw",
		Fail2Ban:        true,
		CrowdSec:        true,
		LogForwarding:   "syslog",
		DialValue:       50,
		AllowedSNIs:     []string{"api.example.com"},
		UpstreamLB:      true,
		TrustedCIDRs:    []string{"10.0.0.0/8"},
		WritePROXY:      true,
		PROXYVersion:    2,
		TLSCerts:        "user-supplied",
		TLSCertPath:     "/etc/certs/cert.pem",
		TLSKeyPath:      "/etc/certs/key.pem",
	}

	env := buildPublicEnv(a)

	checks := map[string]string{
		"MONITORING_STACK":          "true",
		"FIREWALL_BACKEND":          "ufw",
		"FAIL2BAN_ENABLED":          "true",
		"CROWDSEC_ENABLED":          "true",
		"LOG_FORWARDING":            "syslog",
		"JA4PROXY_DIAL":             "50",
		"UPSTREAM_LB":               "true",
		"UPSTREAM_TRUSTED_CIDRS":    "10.0.0.0/8",
		"WRITE_PROXY_PROTOCOL":      "true",
		"WRITE_PROXY_PROTOCOL_VERSION": "2",
		"TLS_CERT_PATH":             "/etc/certs/cert.pem",
		"TLS_KEY_PATH":              "/etc/certs/key.pem",
	}
	for k, want := range checks {
		if got := env[k]; got != want {
			t.Errorf("env[%q] = %q; want %q", k, got, want)
		}
	}
	if snis := env["ALLOWED_SNIS"]; snis != "api.example.com" {
		t.Errorf("ALLOWED_SNIS = %q; want api.example.com", snis)
	}
}

// TestLaneOffset_Negative verifies laneOffset clamps negative Lane to 0.
func TestLaneOffset_Negative(t *testing.T) {
	a := &Answers{Lane: -5}
	offset := laneOffset(a)
	if offset != 0 {
		t.Errorf("laneOffset(-5) = %d; want 0", offset)
	}
	if a.Lane != 0 {
		t.Errorf("Lane after clamp = %d; want 0", a.Lane)
	}
}

// TestMergeSecrets_AllPresent verifies mergeSecrets skips generation when all
// secrets are already set.
func TestMergeSecrets_AllPresent(t *testing.T) {
	// Pre-populate every secret key so mergeSecrets has nothing to generate.
	env := make(map[string]string)
	for _, k := range secretEnvKeys {
		env[k] = "preset-" + k
	}

	result := mergeSecrets(env)
	for _, k := range secretEnvKeys {
		if result[k] != "preset-"+k {
			t.Errorf("mergeSecrets overwrote existing key %q: got %q", k, result[k])
		}
	}
}

// -- detectGeoIPAt coverage --

// TestDetectGeoIPAt_ValidDir verifies .mmdb files are found in a directory.
func TestDetectGeoIPAt_ValidDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/GeoLite2-ASN.mmdb", []byte("dummy"), 0644)
	os.WriteFile(dir+"/GeoLite2-Country.mmdb", []byte("dummy"), 0644)
	os.WriteFile(dir+"/other.txt", []byte("not mmdb"), 0644)

	found := detectGeoIPAt(dir)
	if len(found) != 2 {
		t.Errorf("detectGeoIPAt found %d files; want 2: %v", len(found), found)
	}
}

// TestDetectGeoIPAt_NonexistentDir verifies nil is returned for missing dirs.
func TestDetectGeoIPAt_NonexistentDir(t *testing.T) {
	found := detectGeoIPAt("/nonexistent/geoip/dir")
	if found != nil {
		t.Errorf("detectGeoIPAt nonexistent: expected nil, got %v", found)
	}
}

// -- templateFuncs coverage --

// TestTemplateFuncs_Add verifies the "add" function in templateFuncs.
func TestTemplateFuncs_Add(t *testing.T) {
	fns := templateFuncs()
	addFn, ok := fns["add"].(func(int, int) int)
	if !ok {
		t.Fatal("templateFuncs[\"add\"] is not func(int,int)int")
	}
	if got := addFn(3, 7); got != 10 {
		t.Errorf("add(3,7) = %d; want 10", got)
	}
}

// -- render functions coverage --

// TestRenderHAProxyCfg_Renders verifies RenderHAProxyCfg produces non-empty output.
func TestRenderHAProxyCfg_Renders(t *testing.T) {
	data := TemplateData{
		BackendHost: "backend.internal",
		BackendPort: 443,
		BindIP:      "0.0.0.0",
		Mode:        "container",
		LaneName:    "prod",
		Lane:        0,
		Ports: map[string]int{
			"INGRESS": 443, "DIRECT": 8081,
		},
	}
	out, err := RenderHAProxyCfg(data)
	if err != nil {
		t.Fatalf("RenderHAProxyCfg: %v", err)
	}
	if len(out) == 0 {
		t.Error("RenderHAProxyCfg returned empty string")
	}
}

// TestRenderSystemdService_Renders verifies RenderSystemdService produces non-empty output.
func TestRenderSystemdService_Renders(t *testing.T) {
	data := TemplateData{
		BackendHost: "backend.internal",
		LaneName:    "prod",
		Lane:        0,
		Mode:        "baremetal",
	}
	out, err := RenderSystemdService(data)
	if err != nil {
		t.Fatalf("RenderSystemdService: %v", err)
	}
	if len(out) == 0 {
		t.Error("RenderSystemdService returned empty string")
	}
}

// TestRun_NonInteractive verifies Run in non-interactive mode uses pre-filled answers.
func TestRun_NonInteractive(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(orig)

	w := &Wizard{
		Out:            silentOutput{},
		InputFn:        queuedInput([]string{"y"}), // "y" for write confirmation
		GetPassFn:      noPass,
		NonInteractive: true,
		Answers: Answers{
			BackendHost: "10.0.0.1",
			BackendPort: 443,
			Mode:        "container",
			LaneName:    "",  // triggers default → "default"
			Lane:        -1,  // triggers clamp → 0
			DryRun:      true,
		},
	}

	answers, cfg, err := w.Run(context.Background())
	if err != nil {
		t.Fatalf("Run non-interactive: %v", err)
	}
	if answers == nil || cfg == nil {
		t.Fatalf("Run returned nil answers=%v cfg=%v", answers, cfg)
	}
	if answers.LaneName != "default" {
		t.Errorf("LaneName = %q; want default", answers.LaneName)
	}
}
