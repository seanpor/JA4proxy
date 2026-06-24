package security

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/seanpor/ja4proxy/internal/metrics"
	"github.com/sirupsen/logrus"
)

// BeaconingConfig configures the beaconing detector.
type BeaconingConfig struct {
	Enabled         bool
	ScoreCap        int     // default 35
	MinObservations int     // default 5
	ShortWindowSec  float64 // default 3600
	LongWindowSec   float64 // default 86400
}

// BeaconingDetector detects beaconing behavior via inter-arrival time analysis.
// Port of src/security/beaconing_detector.py.
type BeaconingDetector struct {
	cfg   *BeaconingConfig
	redis RedisReader
	log   *logrus.Logger
}

// NewBeaconingDetector creates a BeaconingDetector with the given configuration.
func NewBeaconingDetector(cfg *BeaconingConfig, redis RedisReader, log *logrus.Logger) *BeaconingDetector {
	if log == nil {
		log = logrus.New()
	}
	if cfg == nil {
		cfg = &BeaconingConfig{}
	}
	return &BeaconingDetector{cfg: cfg, redis: redis, log: log}
}

// GetSignal returns a risk signal if beaconing behavior is detected.
// Returns nil if not enough data, disabled, or browser traffic.
func (d *BeaconingDetector) GetSignal(ctx context.Context, conn *ConnectionContext) *RiskSignal {
	if !d.cfg.Enabled {
		return nil
	}
	// Never fire for browser traffic
	if conn.ALPN == "h2" || conn.ALPN == "h1" {
		return nil
	}
	if conn.JA4 == "" {
		return nil
	}

	shortWindow := d.cfg.ShortWindowSec
	minObs := d.cfg.MinObservations
	scoreCap := d.cfg.ScoreCap

	if d.redis == nil {
		return nil
	}

	key := fmt.Sprintf("beacon:%s:%s", conn.ClientIP, conn.JA4)

	// Fetch all timestamps in the sorted set
	timestamps := d.redis.ZRangeScores(ctx, key, 0, -1)
	if len(timestamps) < minObs {
		return nil
	}

	// Filter to short window
	now := float64(time.Now().UnixNano()) / 1e9
	cutoff := now - shortWindow
	var windowTS []float64
	for _, ts := range timestamps {
		if ts >= cutoff {
			windowTS = append(windowTS, ts)
		}
	}

	if len(windowTS) < minObs {
		return nil
	}

	cv := computeCV(windowTS)

	var beaconingScore float64
	switch {
	case cv < 0.15:
		beaconingScore = 0.9
	case cv < 0.40:
		beaconingScore = 0.5
	case cv < 0.70:
		beaconingScore = 0.2
	default:
		return nil // high variance = not beaconing
	}

	score := int(math.Round(beaconingScore * float64(scoreCap)))
	if score <= 0 {
		return nil
	}

	// phase-309 WP-6 — record this (IP, JA4) on the beacon:suspects leaderboard
	// and refresh the BeaconingSuspects gauge so the BeaconingDetected alert
	// can fire and the Management UI has a leaderboard to render.
	d.recordSuspect(ctx, conn, cv, shortWindow, now)

	return &RiskSignal{
		Name:   "beaconing",
		Score:  score,
		Reason: fmt.Sprintf("beaconing detected (CV=%.3f, n=%d)", cv, len(windowTS)),
		Weight: 1.0,
	}
}

// recordSuspect upserts the (IP, JA4) pair onto the beacon:suspects ZSET
// (score = last-seen unix time), trims entries older than the short window so
// the leaderboard reflects only currently-active suspects, and publishes the
// resulting cardinality to the BeaconingSuspects gauge. Best-effort: a nil
// Redis is a no-op (the gauge simply stays at its last value, fail open).
func (d *BeaconingDetector) recordSuspect(ctx context.Context, conn *ConnectionContext, cv, shortWindow, now float64) {
	if d.redis == nil {
		return
	}
	member := fmt.Sprintf("%s:%s", conn.ClientIP, conn.JA4)
	d.redis.ZAdd(ctx, beaconSuspectsKey, now, member)
	d.redis.ZRemRangeByScore(ctx, beaconSuspectsKey, 0, now-shortWindow)
	metrics.BeaconingSuspects.Set(float64(d.redis.ZCard(ctx, beaconSuspectsKey)))
}

// beaconSuspectsKey is the cross-instance ZSET leaderboard of active beaconing
// suspects. Members are "{ip}:{ja4}"; scores are last-seen unix seconds.
const beaconSuspectsKey = "beacon:suspects"

// MaybeRecord records this connection in the beaconing sorted set.
// Skips block/ban actions and browser ALPN.
func (d *BeaconingDetector) MaybeRecord(ctx context.Context, conn *ConnectionContext, action string) {
	if !d.cfg.Enabled {
		return
	}
	if action == "block" || action == "ban" {
		return
	}
	if conn.ALPN == "h2" || conn.ALPN == "h1" {
		return
	}
	if conn.JA4 == "" {
		return
	}
	if d.redis == nil {
		return
	}

	longWindow := d.cfg.LongWindowSec
	if longWindow == 0 {
		longWindow = 86400
	}

	key := fmt.Sprintf("beacon:%s:%s", conn.ClientIP, conn.JA4)
	now := float64(time.Now().UnixNano()) / 1e9

	d.redis.ZAdd(ctx, key, now, fmt.Sprintf("%f", now))
	// Trim old entries outside the long window
	d.redis.ZRemRangeByScore(ctx, key, 0, now-longWindow)
}

// computeCV computes the coefficient of variation of inter-arrival times.
// Returns 1.0 if fewer than 2 timestamps (high variance = not beaconing).
func computeCV(timestamps []float64) float64 {
	if len(timestamps) < 2 {
		return 1.0
	}
	iats := make([]float64, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		iats[i-1] = timestamps[i] - timestamps[i-1]
	}
	mean := 0.0
	for _, v := range iats {
		mean += v
	}
	mean /= float64(len(iats))
	if mean <= 0 {
		return 1.0
	}
	variance := 0.0
	for _, v := range iats {
		delta := v - mean
		variance += delta * delta
	}
	variance /= float64(len(iats))
	return math.Sqrt(variance) / mean
}
