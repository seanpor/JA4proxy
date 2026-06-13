package backup

import (
	"time"

	"github.com/seanpor/ja4proxy/internal/metrics"
)

// PromMetrics implements Metrics against the package-level Prometheus series in
// internal/metrics (the ones backup.rules.yml alerts on).
type PromMetrics struct{}

// SetRunning sets the ja4proxy_backup_currently_running gauge.
func (PromMetrics) SetRunning(running bool) {
	if running {
		metrics.BackupCurrentlyRunning.Set(1)
	} else {
		metrics.BackupCurrentlyRunning.Set(0)
	}
}

// IncOperation increments ja4proxy_backup_operations_total{status=...}.
func (PromMetrics) IncOperation(success bool) {
	status := "failure"
	if success {
		status = "success"
	}
	metrics.BackupOperationsTotal.WithLabelValues(status).Inc()
}

// SetLastSuccess sets ja4proxy_backup_last_success_seconds to t (unix seconds).
func (PromMetrics) SetLastSuccess(t time.Time) {
	metrics.BackupLastSuccessSeconds.Set(float64(t.Unix()))
}

// ObserveDuration records a backup duration in the histogram.
func (PromMetrics) ObserveDuration(d time.Duration) {
	metrics.BackupDurationSeconds.Observe(d.Seconds())
}
