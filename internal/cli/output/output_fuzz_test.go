package output_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/seanpor/ja4proxy/internal/cli/output"
)

type fuzzPayload struct {
	Title       string                 `json:"title"`
	Description string                 `json:"desc"`
	Code        int                    `json:"code"`
	Enabled     bool                   `json:"enabled"`
	Metadata    map[string]interface{} `json:"meta,omitempty"`
}

// FuzzOutputFormatter fuzzes table and JSON rendering across arbitrary UTF-8 strings,
// special characters, and nested map payloads.
func FuzzOutputFormatter(f *testing.F) {
	f.Add("normal_title", "simple description", 200, true)
	f.Add("\x00\x01\x1b[31mRed\x1b[0m", "ANSI \t\r\n escapes", -1, false)
	f.Add("emoji 🛡️🚀🔒", "Unicode 漢語 / 한국어 / Русский", 99999, true)
	f.Add(strings.Repeat("long_", 100), strings.Repeat("A", 1000), 0, false)

	f.Fuzz(func(t *testing.T, title, desc string, code int, enabled bool) {
		item := fuzzPayload{
			Title:       title,
			Description: desc,
			Code:        code,
			Enabled:     enabled,
		}
		items := []fuzzPayload{item}

		// Table rendering must never panic
		_, err := output.RenderTable(items)
		if err != nil {
			t.Logf("RenderTable returned error: %v", err)
		}

		// CSV rendering must never panic
		_, err = output.RenderCSV(items)
		if err != nil {
			t.Logf("RenderCSV returned error: %v", err)
		}

		// JSON rendering must never panic and must produce valid JSON
		jsonOut, err := output.RenderJSON(items)
		if err != nil {
			t.Fatalf("RenderJSON failed: %v", err)
		}
		if !json.Valid([]byte(jsonOut)) {
			t.Fatalf("RenderJSON did not produce valid JSON for payload: %s", jsonOut)
		}
	})
}

// BenchmarkRenderTable measures throughput of table rendering.
func BenchmarkRenderTable(b *testing.B) {
	records := make([]fuzzPayload, 20)
	for i := 0; i < 20; i++ {
		records[i] = fuzzPayload{
			Title:       "Sample Rule",
			Description: "Passive TAP Rule description with metadata",
			Code:        i,
			Enabled:     i%2 == 0,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = output.RenderTable(records)
	}
}

// BenchmarkRenderJSON measures throughput of JSON formatting.
func BenchmarkRenderJSON(b *testing.B) {
	records := make([]fuzzPayload, 20)
	for i := 0; i < 20; i++ {
		records[i] = fuzzPayload{
			Title:       "Sample Rule",
			Description: "Passive TAP Rule description with metadata",
			Code:        i,
			Enabled:     i%2 == 0,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = output.RenderJSON(records)
	}
}
