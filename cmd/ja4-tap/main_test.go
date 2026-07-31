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
		cfg := runConfig{pcapFile: "nonexistent.pcap", quiet: true, enfCfg: tap.EnforcerConfig{}, eventBuffer: buf}
		err := run(cfg, log)
		if err == nil {
			t.Errorf("event-buffer=%d: expected an error, got nil", buf)
			continue
		}
		if !strings.Contains(err.Error(), "event-buffer") {
			t.Errorf("event-buffer=%d: expected an --event-buffer validation error, got: %v", buf, err)
		}
	}
}

// TestRunRejectsInvalidFrameSize guards F-027: a negative --frame-size would
// underflow into a huge uint32 inside the afpacket library (int -> uint32
// cast), and an absurdly large one risks an oversized allocation. 0 (library
// default) must still be accepted.
func TestRunRejectsInvalidFrameSize(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	for _, fs := range []int{-1, -65536, 1, 2047, 1<<20 + 1} {
		cfg := runConfig{pcapFile: "nonexistent.pcap", quiet: true, enfCfg: tap.EnforcerConfig{}, eventBuffer: 16, frameSize: fs}
		err := run(cfg, log)
		if err == nil {
			t.Errorf("frame-size=%d: expected an error, got nil", fs)
			continue
		}
		if !strings.Contains(err.Error(), "frame-size") {
			t.Errorf("frame-size=%d: expected a --frame-size validation error, got: %v", fs, err)
		}
	}
}

// TestRunAcceptsValidFrameSize proves 0 (library default) and sane in-range
// values pass validation and reach the actual open-pcap step (which then
// fails for an unrelated reason — a nonexistent path — proving the frame-size
// check itself did not reject them).
func TestRunAcceptsValidFrameSize(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	for _, fs := range []int{0, 2048, 65536, 1 << 20} {
		cfg := runConfig{pcapFile: "nonexistent.pcap", quiet: true, enfCfg: tap.EnforcerConfig{}, eventBuffer: 16, frameSize: fs}
		err := run(cfg, log)
		if err == nil || strings.Contains(err.Error(), "frame-size") {
			t.Errorf("frame-size=%d: expected to pass validation and fail on the pcap open instead, got: %v", fs, err)
		}
	}
}
