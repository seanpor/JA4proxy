package metrics

import (
	"testing"
)

func TestParseChronycTracking(t *testing.T) {
	out := `Reference ID    : CB00710A (1.2.3.4)
Stratum         : 3
Ref time (UTC)  : Wed Apr 08 20:53:05 2026
System time     : 0.000001234 seconds slow of NTP time
Last offset     : -0.000000567 seconds
RMS offset      : 0.000002345 seconds
Frequency       : 1.234 ppm slow
Residual freq   : -0.001 ppm
Skew            : 0.012 ppm
Root delay      : 0.012345678 seconds
Root dispersion : 0.000123456 seconds
Update interval : 64.0 seconds
Leap status     : Normal`

	drift, err := parseChronycTracking(out)
	if err != nil {
		t.Fatalf("parseChronycTracking: %v", err)
	}
	expected := -0.000001234
	if drift != expected {
		t.Errorf("got %f, want %f", drift, expected)
	}

	out2 := `System time     : 0.000004321 seconds fast of NTP time`
	drift2, err := parseChronycTracking(out2)
	if err != nil {
		t.Fatalf("parseChronycTracking (fast): %v", err)
	}
	expected2 := 0.000004321
	if drift2 != expected2 {
		t.Errorf("got %f, want %f", drift2, expected2)
	}
}

func TestParseNtpstat(t *testing.T) {
	out := `synchronised to NTP server (1.2.3.4) at stratum 2
   time correct to within 12 ms
   polling server every 64 s`

	drift, err := parseNtpstat(out)
	if err != nil {
		t.Fatalf("parseNtpstat: %v", err)
	}
	expected := 0.012
	if drift != expected {
		t.Errorf("got %f, want %f", drift, expected)
	}

	out2 := `unsynchronised
  time server re-starting
   polling server every 8 s`
	_, err = parseNtpstat(out2)
	if err == nil {
		t.Error("parseNtpstat: expected error for unsynchronised")
	}
}
