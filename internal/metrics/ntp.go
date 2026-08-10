package metrics

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var ntpWarnOnce sync.Once

// StartNTPMonitor starts a background goroutine to periodically check NTP drift.
func StartNTPMonitor(ctx context.Context, intervalSeconds int, log *logrus.Logger) {
	if intervalSeconds <= 0 {
		intervalSeconds = 60
	}
	ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)
	defer ticker.Stop()

	log.WithField("interval", intervalSeconds).Info("metrics: NTP drift monitor started")

	// Initial check — log which binary is available (or neither)
	drift, err := getNTPDrift()
	if err != nil {
		SyncClockMonitorAvailable.Set(0)
		ntpWarnOnce.Do(func() {
			log.WithError(err).Warn("metrics: NTP drift monitoring unavailable — neither chronyc nor ntpstat found")
		})
	} else {
		SyncClockMonitorAvailable.Set(1)
		SyncClockDriftSeconds.Set(drift)
		log.WithField("drift", drift).Debug("metrics: NTP drift monitor initialised")
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkNTP(log)
		}
	}
}

func checkNTP(log *logrus.Logger) {
	drift, err := getNTPDrift()
	if err != nil {
		// Re-set on every failure, not just the first: the monitor can go
		// unavailable mid-run (chronyd stopped, binary removed by an image
		// update), and the log warning is once-only by design.
		SyncClockMonitorAvailable.Set(0)
		ntpWarnOnce.Do(func() {
			log.WithError(err).Warn("metrics: NTP drift monitoring unavailable — neither chronyc nor ntpstat found")
		})
		return
	}
	SyncClockMonitorAvailable.Set(1)
	SyncClockDriftSeconds.Set(drift)
}

// getNTPDrift executes 'chronyc tracking' and parses the system time offset.
// Returns drift in seconds.
func getNTPDrift() (float64, error) {
	// Try chronyc first
	out, err := exec.Command("/usr/bin/chronyc", "tracking").Output()
	if err == nil {
		return parseChronycTracking(string(out))
	}

	// Fallback to ntpstat if chronyc is not available
	out, err = exec.Command("/usr/bin/ntpstat").Output()
	if err == nil {
		return parseNtpstat(string(out))
	}

	return 0, fmt.Errorf("neither chronyc nor ntpstat available")
}

// parseChronycTracking extracts "System time" offset from chronyc tracking output.
// Example line: "System time     : 0.000001234 seconds slow of NTP time"
func parseChronycTracking(out string) (float64, error) {
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "System time") {
			parts := strings.Fields(line)
			// parts should be ["System", "time", ":", "0.000001234", "seconds", ...]
			if len(parts) >= 4 {
				drift, err := strconv.ParseFloat(parts[3], 64)
				if err != nil {
					return 0, err
				}
				if strings.Contains(line, "slow") {
					return -drift, nil
				}
				return drift, nil
			}
		}
	}
	return 0, fmt.Errorf("system time not found in chronyc output")
}

// parseNtpstat extracts drift from ntpstat output.
// Example: "synchronised to NTP server (1.2.3.4) at stratum 2
//
//	time correct to within 12 ms"
func parseNtpstat(out string) (float64, error) {
	if strings.Contains(out, "unsynchronised") {
		return 0, fmt.Errorf("ntpstat: unsynchronised")
	}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "time correct to within") {
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				val, err := strconv.ParseFloat(parts[4], 64)
				if err != nil {
					return 0, err
				}
				unit := parts[5]
				if unit == "ms" {
					return val / 1000.0, nil
				}
				return val, nil
			}
		}
	}
	return 0, fmt.Errorf("drift not found in ntpstat output")
}
