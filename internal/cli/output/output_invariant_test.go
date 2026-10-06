package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/seanpor/ja4proxy/internal/cli/output"
	"pgregory.net/rapid"
)

type sampleRecord struct {
	ID    int
	Name  string
	State string
}

// INV-CLI-001: RenderJSON Valid JSON Invariant
// json.Valid([]byte(RenderJSON(data))) == true
func TestInvariant_CLI_RenderJSONValidJSON(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		count := rapid.IntRange(1, 10).Draw(t, "count")
		records := make([]sampleRecord, count)
		for i := 0; i < count; i++ {
			records[i] = sampleRecord{
				ID:    rapid.IntRange(1, 1000).Draw(t, "id"),
				Name:  rapid.StringMatching("[a-zA-Z0-9_-]{1,10}").Draw(t, "name"),
				State: rapid.SampledFrom([]string{"active", "banned", "expired"}).Draw(t, "state"),
			}
		}

		out, err := output.RenderJSON(records)
		if err != nil {
			t.Fatalf("RenderJSON failed: %v", err)
		}

		if !json.Valid([]byte(out)) {
			t.Fatalf("RenderJSON output is not valid JSON: %s", out)
		}
	})
}

// INV-CLI-002: RenderCSV Header Match Invariant
// First line of CSV output matches struct field names
func TestInvariant_CLI_RenderCSVHeaderMatch(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		count := rapid.IntRange(1, 5).Draw(t, "count")
		records := make([]sampleRecord, count)
		for i := 0; i < count; i++ {
			records[i] = sampleRecord{
				ID:    rapid.IntRange(1, 100).Draw(t, "id"),
				Name:  "rec",
				State: "active",
			}
		}

		out, err := output.RenderCSV(records)
		if err != nil {
			t.Fatalf("RenderCSV failed: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) < 1 {
			t.Fatalf("RenderCSV returned empty string")
		}

		header := lines[0]
		expectedHeader := "ID,Name,State"
		if header != expectedHeader {
			t.Fatalf("RenderCSV header mismatch: got %q, want %q", header, expectedHeader)
		}
	})
}

// INV-CLI-003: Non-Slice Error Invariant
// Passing non-slice input returns error without panic
func TestInvariant_CLI_NonSliceError(t *testing.T) {
	invalidInputs := []interface{}{
		"not a slice",
		123,
		struct{ Field string }{"test"},
		nil,
	}

	for _, input := range invalidInputs {
		_, errTable := output.RenderTable(input)
		if errTable == nil {
			t.Fatalf("RenderTable expected error for non-slice input %v, got nil", input)
		}

		_, errCSV := output.RenderCSV(input)
		if errCSV == nil {
			t.Fatalf("RenderCSV expected error for non-slice input %v, got nil", input)
		}
	}
}

// INV-CLI-004: WriteTo Trailing Newline Invariant
// WriteTo output ends with exactly one newline '\n'
func TestInvariant_CLI_WriteToAppendsNewline(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		text := rapid.StringMatching("[a-zA-Z0-9_\n\t ]{0,50}").Draw(t, "text")

		var buf bytes.Buffer
		err := output.WriteTo(&buf, text)
		if err != nil {
			t.Fatalf("WriteTo failed: %v", err)
		}

		out := buf.String()
		if !strings.HasSuffix(out, "\n") {
			t.Fatalf("WriteTo output missing trailing newline: %q", out)
		}
		if strings.HasSuffix(out, "\n\n") {
			t.Fatalf("WriteTo output has multiple trailing newlines: %q", out)
		}
	})
}
