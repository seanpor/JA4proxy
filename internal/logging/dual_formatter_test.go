package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// errFormatter is a logrus.Formatter that always returns an error.
type errFormatter struct{ msg string }

func (e *errFormatter) Format(*logrus.Entry) ([]byte, error) {
	return nil, errors.New(e.msg)
}

// makeDualEntry creates a logrus.Entry with a fixed time and message.
func makeDualEntry(msg string) *logrus.Entry {
	logger := logrus.New()
	logger.SetOutput(bytes.NewBuffer(nil))
	entry := logrus.NewEntry(logger)
	entry.Time = time.Date(2026, 4, 11, 10, 0, 0, 0, time.UTC)
	entry.Level = logrus.InfoLevel
	entry.Message = msg
	return entry
}

// makeDualFormatter builds a DualFormatter using the standard legacy + ECS formatters.
func makeDualFormatter() *DualFormatter {
	return &DualFormatter{
		Legacy: &logrus.JSONFormatter{
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
			},
		},
		ECS: NewECSLogrusFormatter("ecs"),
	}
}

func TestDualFormatter_EmitsTwoLines(t *testing.T) {
	df := makeDualFormatter()
	entry := makeDualEntry("two lines test")

	out, err := df.Format(entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d:\n%s", len(lines), string(out))
	}

	var obj1, obj2 map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &obj1); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v\nline: %s", err, lines[0])
	}
	if err := json.Unmarshal([]byte(lines[1]), &obj2); err != nil {
		t.Fatalf("line 2 is not valid JSON: %v\nline: %s", err, lines[1])
	}
}

func TestDualFormatter_FirstLineIsLegacy(t *testing.T) {
	df := makeDualFormatter()
	entry := makeDualEntry("legacy line check")

	out, err := df.Format(entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &obj); err != nil {
		t.Fatalf("line 1 not valid JSON: %v", err)
	}

	if _, ok := obj["timestamp"]; !ok {
		t.Error("first line (legacy) should have 'timestamp' key")
	}
	if _, ok := obj["@timestamp"]; ok {
		t.Error("first line (legacy) must NOT have '@timestamp' key")
	}
}

func TestDualFormatter_SecondLineIsECS(t *testing.T) {
	df := makeDualFormatter()
	entry := makeDualEntry("ecs line check")

	out, err := df.Format(entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(lines[1]), &obj); err != nil {
		t.Fatalf("line 2 not valid JSON: %v", err)
	}

	if _, ok := obj["@timestamp"]; !ok {
		t.Error("second line (ECS) should have '@timestamp' key")
	}
	if _, ok := obj["timestamp"]; ok {
		t.Error("second line (ECS) must NOT have 'timestamp' key")
	}
}

func TestDualFormatter_BothLinesHaveSameMessage(t *testing.T) {
	df := makeDualFormatter()
	entry := makeDualEntry("hello world")

	out, err := df.Format(entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	var legacy, ecs map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &legacy); err != nil {
		t.Fatalf("line 1 not valid JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &ecs); err != nil {
		t.Fatalf("line 2 not valid JSON: %v", err)
	}

	// Legacy uses "message" key (from FieldMap); ECS also uses "message".
	legacyMsg, _ := legacy["message"].(string)
	ecsMsg, _ := ecs["message"].(string)
	if legacyMsg != "hello world" {
		t.Errorf("legacy message = %q, want %q", legacyMsg, "hello world")
	}
	if ecsMsg != "hello world" {
		t.Errorf("ecs message = %q, want %q", ecsMsg, "hello world")
	}
}

func TestDualFormatter_LegacyFormatterError(t *testing.T) {
	df := &DualFormatter{
		Legacy: &errFormatter{msg: "legacy error"},
		ECS:    NewECSLogrusFormatter("ecs"),
	}
	entry := makeDualEntry("test")

	_, err := df.Format(entry)
	if err == nil {
		t.Fatal("expected error from legacy formatter, got nil")
	}
	if !strings.Contains(err.Error(), "legacy error") {
		t.Errorf("error = %v, want to contain 'legacy error'", err)
	}
}

func TestDualFormatter_ECSFormatterError(t *testing.T) {
	df := &DualFormatter{
		Legacy: &logrus.JSONFormatter{},
		ECS:    &errFormatter{msg: "ecs error"},
	}
	entry := makeDualEntry("test")

	_, err := df.Format(entry)
	if err == nil {
		t.Fatal("expected error from ECS formatter, got nil")
	}
	if !strings.Contains(err.Error(), "ecs error") {
		t.Errorf("error = %v, want to contain 'ecs error'", err)
	}
}
