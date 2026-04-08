package commands_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
	"github.com/anomalyco/ja4proxy/internal/cli/commands"
)

// ── DSAR export ───────────────────────────────────────────────────────────────

// TestRunDSARExport_CallsCorrectEndpoint verifies the right path and method are used.
func TestRunDSARExport_CallsCorrectEndpoint(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"1.2.3.4","events":[],"beaconing_keys":[],"return_visitor":null,"active_ban":null}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	result, err := commands.RunDSARExport(context.Background(), c, "1.2.3.4")
	if err != nil {
		t.Fatalf("RunDSARExport error: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q; want GET", gotMethod)
	}
	if gotPath != "/api/v1/compliance/dsar/1.2.3.4" {
		t.Errorf("path = %q; want /api/v1/compliance/dsar/1.2.3.4", gotPath)
	}
	if result.IP != "1.2.3.4" {
		t.Errorf("result.IP = %q; want 1.2.3.4", result.IP)
	}
}

// TestRunDSARExport_Returns404AsError verifies that a 404 response surfaces as an error.
func TestRunDSARExport_Returns404AsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunDSARExport(context.Background(), c, "9.9.9.9")
	if err == nil {
		t.Fatal("expected error for 404; got nil")
	}
}

// ── PCI-DSS pack ─────────────────────────────────────────────────────────────

// TestRunPCIDSSPack_WritesZipToPath verifies that the ZIP content is written to
// the specified output file and the returned path matches.
func TestRunPCIDSSPack_WritesZipToPath(t *testing.T) {
	fakeZip := []byte("PK\x03\x04fake zip content")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q; want POST", r.Method)
		}
		if r.URL.Path != "/api/v1/compliance/pci-dss-pack" {
			t.Errorf("path = %q; want /api/v1/compliance/pci-dss-pack", r.URL.Path)
		}
		// Verify request body contains since/until
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["since"] == "" || body["until"] == "" {
			t.Errorf("body missing since/until: %v", body)
		}
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(fakeZip)
	}))
	defer srv.Close()

	outPath := filepath.Join(t.TempDir(), "pack.zip")
	c := client.New(srv.URL, "token")
	gotPath, err := commands.RunPCIDSSPack(
		context.Background(), c,
		"2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z",
		outPath,
	)
	if err != nil {
		t.Fatalf("RunPCIDSSPack error: %v", err)
	}
	if gotPath != outPath {
		t.Errorf("returned path = %q; want %q", gotPath, outPath)
	}
	data, _ := os.ReadFile(outPath)
	if !bytes.Equal(data, fakeZip) {
		t.Errorf("written content %q != expected %q", data, fakeZip)
	}
}

// TestRunPCIDSSPack_GeneratesFilenameIfEmpty verifies that when outPath is empty
// a filename is generated and the file is created.
func TestRunPCIDSSPack_GeneratesFilenameIfEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write([]byte("PK\x03\x04fake"))
	}))
	defer srv.Close()

	// Change to temp dir so the auto-generated file is created there.
	orig, _ := os.Getwd()
	tmp := t.TempDir()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(orig) }()

	c := client.New(srv.URL, "token")
	gotPath, err := commands.RunPCIDSSPack(
		context.Background(), c,
		"2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z",
		"",
	)
	if err != nil {
		t.Fatalf("RunPCIDSSPack error: %v", err)
	}
	if gotPath == "" {
		t.Fatal("returned path is empty")
	}
	if !strings.HasSuffix(gotPath, ".zip") {
		t.Errorf("generated path %q missing .zip suffix", gotPath)
	}
	if _, err := os.Stat(gotPath); os.IsNotExist(err) {
		t.Errorf("file %q was not created", gotPath)
	}
}

// ── Report generate ───────────────────────────────────────────────────────────

// TestRunReportGenerate_HTMLWritesToWriter verifies that report content is
// written to the provided io.Writer.
func TestRunReportGenerate_HTMLWritesToWriter(t *testing.T) {
	const fakeHTML = "<html><body>Report content</body></html>"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q; want POST", r.Method)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["format"] != "html" {
			t.Errorf("body.format = %q; want html", body["format"])
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fakeHTML))
	}))
	defer srv.Close()

	var buf bytes.Buffer
	c := client.New(srv.URL, "token")
	err := commands.RunReportGenerate(
		context.Background(), c,
		"2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z",
		commands.ReportFormatHTML,
		&buf,
	)
	if err != nil {
		t.Fatalf("RunReportGenerate error: %v", err)
	}
	if buf.String() != fakeHTML {
		t.Errorf("output = %q; want %q", buf.String(), fakeHTML)
	}
}

// ── Purge expired ─────────────────────────────────────────────────────────────

// TestRunPurgeExpired_CallsCorrectEndpoint verifies POST /api/v1/compliance/purge-expired
// is called and the response fields are parsed.
func TestRunPurgeExpired_CallsCorrectEndpoint(t *testing.T) {
	var gotMethod, gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"stream_events_purged": 150,
			"beaconing_keys_purged": 20,
			"rv_hashes_purged": 5,
			"monthly_aggs_purged": 0,
			"errors": [],
			"completed_at": "2026-04-07T10:00:00Z"
		}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	result, err := commands.RunPurgeExpired(context.Background(), c)
	if err != nil {
		t.Fatalf("RunPurgeExpired error: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q; want POST", gotMethod)
	}
	if gotPath != "/api/v1/compliance/purge-expired" {
		t.Errorf("path = %q; want /api/v1/compliance/purge-expired", gotPath)
	}
	if result.StreamEventsPurged != 150 {
		t.Errorf("StreamEventsPurged = %d; want 150", result.StreamEventsPurged)
	}
}

// TestRunPurgeExpired_ReturnsErrorOnFailure verifies a 500 response surfaces as an error.
func TestRunPurgeExpired_ReturnsErrorOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"redis unavailable"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunPurgeExpired(context.Background(), c)
	if err == nil {
		t.Fatal("expected error for 500; got nil")
	}
}

// ── Signal categories ─────────────────────────────────────────────────────────

// TestRunSignalCategories_ParsesResponse verifies the response is decoded correctly.
func TestRunSignalCategories_ParsesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q; want GET", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"categories":{"tor_exit":{"category":"tor_exit_node","weight":95}}}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	result, err := commands.RunSignalCategories(context.Background(), c)
	if err != nil {
		t.Fatalf("RunSignalCategories error: %v", err)
	}
	entry, ok := result.Categories["tor_exit"]
	if !ok {
		t.Fatal("tor_exit missing from categories")
	}
	if entry.Category != "tor_exit_node" {
		t.Errorf("category = %q; want tor_exit_node", entry.Category)
	}
	if entry.Weight != 95 {
		t.Errorf("weight = %d; want 95", entry.Weight)
	}
}

// ── Connections export ────────────────────────────────────────────────────────

// TestRunConnectionsExport_WritesJSONL verifies that events are written as JSONL
// and the total count matches.
func TestRunConnectionsExport_WritesJSONL(t *testing.T) {
	const numEvents = 5
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		events := make([]map[string]string, numEvents)
		for i := range events {
			events[i] = map[string]string{
				"ip": fmt.Sprintf("10.0.0.%d", i), "ja4": "t13abc",
				"risk_score": "50", "action_taken": "blocked",
				"timestamp": "2026-01-01T00:00:00Z",
			}
		}
		resp := map[string]interface{}{
			"connections":     events,
			"count":           numEvents,
			"has_more":        false,
			"next_page_token": nil,
			"total_in_window": numEvents,
			"truncated":       false,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	outPath := filepath.Join(t.TempDir(), "export.jsonl")
	c := client.New(srv.URL, "token")
	result, err := commands.RunConnectionsExport(
		context.Background(), c,
		"2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z",
		outPath,
	)
	if err != nil {
		t.Fatalf("RunConnectionsExport error: %v", err)
	}
	if result.TotalEvents != numEvents {
		t.Errorf("TotalEvents = %d; want %d", result.TotalEvents, numEvents)
	}

	data, _ := os.ReadFile(outPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != numEvents {
		t.Errorf("JSONL lines = %d; want %d", len(lines), numEvents)
	}
	// Each line must be valid JSON with an "ip" field.
	for i, line := range lines {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d is not valid JSON: %v — %s", i, err, line)
		}
		if _, ok := m["ip"]; !ok {
			t.Errorf("line %d missing 'ip' field", i)
		}
	}
}
