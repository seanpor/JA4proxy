package tap

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// minRunBeforeReset is the minimum uptime before a crash is considered
	// a clean restart (not a rapid-crash loop).
	minRunBeforeReset = 10 * time.Second

	// maxRapidRestarts is the number of restarts within the window before
	// the watchdog gives up (prevents infinite crash loops).
	maxRapidRestarts = 5

	// rapidWindow is the window for counting rapid crashes.
	rapidWindow = 60 * time.Second
)

// Watchdog wraps a sensor run loop with automatic restart and rapid-crash
// detection. If the sensor panics or returns a non-nil error, the watchdog
// restarts it — unless it has crashed too many times within rapidWindow, in
// which case it gives up and returns the last error.
type Watchdog struct {
	log *logrus.Logger
}

// NewWatchdog creates a watchdog that logs restarts.
func NewWatchdog(log *logrus.Logger) *Watchdog {
	return &Watchdog{log: log}
}

// Run starts the sensor loop with automatic restart. The srcFactory and
// sensorFactory callbacks are called on each restart to create fresh
// instances (the previous source/sensor may be in a bad state).
// Run blocks until ctx is cancelled or the watchdog gives up.
func (w *Watchdog) Run(
	ctx context.Context,
	srcFactory func() (PacketSource, func(), error),
	sensorFactory func() *Sensor,
	drain func(*Sensor),
) error {
	var restarts []time.Time

	for {
		src, closeSrc, err := srcFactory()
		if err != nil {
			return err
		}

		sensor := sensorFactory()
		done := make(chan error, 1)
		go func() { defer Recover(done, sensor); done <- sensor.Run(ctx, src) }()

		// Drain events from this sensor instance.
		drain(sensor)

		runErr := <-done
		closeSrc()

		if runErr == nil || ctx.Err() != nil {
			return runErr
		}

		// Crash — decide whether to restart.
		now := time.Now()
		restarts = append(restarts, now)

		// Prune old restarts outside the window.
		cutoff := now.Add(-rapidWindow)
		n := 0
		for _, t := range restarts {
			if t.After(cutoff) {
				restarts[n] = t
				n++
			}
		}
		restarts = restarts[:n]

		if len(restarts) >= maxRapidRestarts {
			w.log.WithError(runErr).WithField("restarts", len(restarts)).
				Error("watchdog: rapid-crash loop detected; giving up")
			return runErr
		}

		w.log.WithError(runErr).WithField("restart", len(restarts)).
			Warn("watchdog: sensor crashed; restarting")
	}
}
