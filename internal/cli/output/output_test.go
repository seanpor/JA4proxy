package output_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/anomalyco/ja4proxy/internal/cli/output"
)

// row is a simple test struct for verifying output rendering.
type row struct {
	Name  string
	Value int
}

// TestTableOutput verifies that RenderTable returns a string containing the
// field values of each row.
func TestTableOutput(t *testing.T) {
	data := []row{{Name: "foo", Value: 42}}
	result, err := output.RenderTable(data)
	if err != nil {
		t.Fatalf("RenderTable returned error: %v", err)
	}

	if !strings.Contains(result, "foo") {
		t.Errorf("table output %q does not contain 'foo'", result)
	}
	if !strings.Contains(result, "42") {
		t.Errorf("table output %q does not contain '42'", result)
	}
}

// TestTableOutput_MultipleRows verifies rendering multiple rows.
func TestTableOutput_MultipleRows(t *testing.T) {
	data := []row{
		{Name: "alpha", Value: 1},
		{Name: "beta", Value: 2},
		{Name: "gamma", Value: 3},
	}
	result, err := output.RenderTable(data)
	if err != nil {
		t.Fatalf("RenderTable returned error: %v", err)
	}

	for _, want := range []string{"alpha", "beta", "gamma"} {
		if !strings.Contains(result, want) {
			t.Errorf("table output does not contain %q", want)
		}
	}
}

// TestJSONOutput verifies that RenderJSON returns valid JSON containing the
// field values.
func TestJSONOutput(t *testing.T) {
	data := []row{{Name: "foo", Value: 42}}
	result, err := output.RenderJSON(data)
	if err != nil {
		t.Fatalf("RenderJSON returned error: %v", err)
	}

	// Must be valid JSON.
	var parsed interface{}
	if jsonErr := json.Unmarshal([]byte(result), &parsed); jsonErr != nil {
		t.Fatalf("RenderJSON output is not valid JSON: %v\noutput: %q", jsonErr, result)
	}

	if !strings.Contains(result, "foo") {
		t.Errorf("JSON output %q does not contain 'foo'", result)
	}
	if !strings.Contains(result, "42") {
		t.Errorf("JSON output %q does not contain '42'", result)
	}
}

// TestJSONOutput_Array verifies that the JSON output for a slice is a JSON array.
func TestJSONOutput_Array(t *testing.T) {
	data := []row{{Name: "a", Value: 1}, {Name: "b", Value: 2}}
	result, err := output.RenderJSON(data)
	if err != nil {
		t.Fatalf("RenderJSON returned error: %v", err)
	}

	var arr []interface{}
	if jsonErr := json.Unmarshal([]byte(result), &arr); jsonErr != nil {
		t.Fatalf("expected JSON array, got: %v\noutput: %q", jsonErr, result)
	}
	if len(arr) != 2 {
		t.Errorf("expected 2 elements, got %d", len(arr))
	}
}

// TestCSVOutput verifies that RenderCSV returns a CSV with a header row and a
// data row containing the field values.
func TestCSVOutput(t *testing.T) {
	data := []row{{Name: "foo", Value: 42}}
	result, err := output.RenderCSV(data)
	if err != nil {
		t.Fatalf("RenderCSV returned error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(result), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines (header + data), got %d:\n%s", len(lines), result)
	}

	// Header row should contain field names.
	header := strings.ToLower(lines[0])
	if !strings.Contains(header, "name") && !strings.Contains(header, "Name") {
		t.Errorf("CSV header %q does not contain 'Name'", lines[0])
	}

	// Data row should contain the value.
	dataRow := lines[1]
	if !strings.Contains(dataRow, "foo") {
		t.Errorf("CSV data row %q does not contain 'foo'", dataRow)
	}
	if !strings.Contains(dataRow, "42") {
		t.Errorf("CSV data row %q does not contain '42'", dataRow)
	}
}

// TestCSVOutput_MultipleRows verifies that multiple rows are rendered correctly.
func TestCSVOutput_MultipleRows(t *testing.T) {
	data := []row{
		{Name: "first", Value: 100},
		{Name: "second", Value: 200},
	}
	result, err := output.RenderCSV(data)
	if err != nil {
		t.Fatalf("RenderCSV returned error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(result), "\n")
	// 1 header + 2 data rows
	if len(lines) < 3 {
		t.Errorf("expected at least 3 lines, got %d:\n%s", len(lines), result)
	}
}

// TestRenderEmpty verifies that all formatters handle empty input gracefully.
func TestRenderEmpty(t *testing.T) {
	var empty []row

	_, err := output.RenderTable(empty)
	if err != nil {
		t.Errorf("RenderTable(empty) returned error: %v", err)
	}

	jsonResult, err := output.RenderJSON(empty)
	if err != nil {
		t.Errorf("RenderJSON(empty) returned error: %v", err)
	}
	// Empty slice should render as an empty JSON array.
	var arr []interface{}
	if jsonErr := json.Unmarshal([]byte(jsonResult), &arr); jsonErr != nil {
		t.Errorf("RenderJSON(empty) is not valid JSON: %v, output: %q", jsonErr, jsonResult)
	}

	_, err = output.RenderCSV(empty)
	if err != nil {
		t.Errorf("RenderCSV(empty) returned error: %v", err)
	}
}
