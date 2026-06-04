package output_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/seanpor/ja4proxy/internal/cli/output"
)

// TestWriteTo_WritesStringWithTrailingNewline verifies WriteTo outputs the string
// with exactly one trailing newline.
func TestWriteTo_WritesStringWithTrailingNewline(t *testing.T) {
	var buf bytes.Buffer
	err := output.WriteTo(&buf, "hello world")
	if err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}
	if buf.String() != "hello world\n" {
		t.Errorf("got %q; want %q", buf.String(), "hello world\n")
	}
}

// TestWriteTo_TrimsExtraNewlines verifies WriteTo strips trailing newlines from
// input before adding exactly one.
func TestWriteTo_TrimsExtraNewlines(t *testing.T) {
	var buf bytes.Buffer
	err := output.WriteTo(&buf, "hello\n\n\n")
	if err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}
	if buf.String() != "hello\n" {
		t.Errorf("got %q; want %q", buf.String(), "hello\n")
	}
}

// TestWriteTo_EmptyString verifies WriteTo handles empty input.
func TestWriteTo_EmptyString(t *testing.T) {
	var buf bytes.Buffer
	err := output.WriteTo(&buf, "")
	if err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}
	if buf.String() != "\n" {
		t.Errorf("got %q; want %q", buf.String(), "\n")
	}
}

// TestRenderCSV_SpecialCharacters verifies CSV handles fields with commas and quotes.
type csvRow struct {
	Name  string
	Value string
}

func TestRenderCSV_SpecialCharacters(t *testing.T) {
	data := []csvRow{
		{Name: "has,comma", Value: `has"quote`},
	}
	result, err := output.RenderCSV(data)
	if err != nil {
		t.Fatalf("RenderCSV error: %v", err)
	}
	// CSV should escape commas and quotes properly
	if !strings.Contains(result, `"has,comma"`) {
		t.Errorf("CSV should quote field with comma: %s", result)
	}
}

// TestRenderTable_NonSliceInput verifies RenderTable returns error for non-slice input.
func TestRenderTable_NonSliceInput(t *testing.T) {
	_, err := output.RenderTable("not a slice")
	if err == nil {
		t.Fatal("expected error for non-slice input")
	}
}

// TestRenderTable_NilInput verifies RenderTable returns error for nil.
func TestRenderTable_NilInput(t *testing.T) {
	_, err := output.RenderTable(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

// TestRenderCSV_NonSliceInput verifies RenderCSV returns error for non-slice input.
func TestRenderCSV_NonSliceInput(t *testing.T) {
	_, err := output.RenderCSV(42)
	if err == nil {
		t.Fatal("expected error for non-slice input")
	}
}

// TestRenderTable_PointerSlice verifies RenderTable works with a slice of pointers.
func TestRenderTable_PointerSlice(t *testing.T) {
	data := []*row{{Name: "ptr", Value: 99}}
	result, err := output.RenderTable(data)
	if err != nil {
		t.Fatalf("RenderTable error: %v", err)
	}
	if !strings.Contains(result, "ptr") {
		t.Errorf("output should contain 'ptr': %s", result)
	}
	if !strings.Contains(result, "99") {
		t.Errorf("output should contain '99': %s", result)
	}
}

// TestRenderCSV_PointerSlice verifies RenderCSV works with a slice of pointers.
func TestRenderCSV_PointerSlice(t *testing.T) {
	data := []*row{{Name: "ptr", Value: 99}}
	result, err := output.RenderCSV(data)
	if err != nil {
		t.Fatalf("RenderCSV error: %v", err)
	}
	if !strings.Contains(result, "ptr") {
		t.Errorf("output should contain 'ptr': %s", result)
	}
}

// TestRenderJSON_SingleStruct verifies RenderJSON handles a single struct (not slice).
func TestRenderJSON_SingleStruct(t *testing.T) {
	data := row{Name: "single", Value: 7}
	result, err := output.RenderJSON(data)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}
	if !strings.Contains(result, "single") {
		t.Errorf("output should contain 'single': %s", result)
	}
}

// TestWriteTo_ErrorWriter verifies WriteTo returns error on write failure.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) {
	return 0, bytes.ErrTooLarge
}

func TestWriteTo_ErrorWriter(t *testing.T) {
	err := output.WriteTo(failWriter{}, "hello")
	if err == nil {
		t.Fatal("expected error on failing writer")
	}
}
