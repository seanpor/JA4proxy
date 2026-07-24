package main

import (
	"io"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/tap"
)

// TestRunRejectsInvalidEventBuffer verifies --event-buffer < 1 fails fast
// (R-004) instead of reaching tap.NewSensor's make(chan, n), which panics on
// a negative size. The check fires before pcap-file/interface are opened, so
// a nonexistent pcap path is enough to isolate this validation path.
func TestRunRejectsInvalidEventBuffer(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	for _, buf := range []int{0, -1, -1024} {
		err := run("nonexistent.pcap", "", 0, nil, true, "", tap.EnforcerConfig{}, "", buf, log)
		if err == nil {
			t.Errorf("event-buffer=%d: expected an error, got nil", buf)
			continue
		}
		if !strings.Contains(err.Error(), "event-buffer") {
			t.Errorf("event-buffer=%d: expected an --event-buffer validation error, got: %v", buf, err)
		}
	}
}
