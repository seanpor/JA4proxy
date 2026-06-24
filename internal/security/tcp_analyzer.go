package security

import (
	"context"
	"strconv"
	"time"

	"github.com/seanpor/ja4proxy/internal/metrics"
	"github.com/sirupsen/logrus"
)

// TCPAnalyzerConfig configures the TCP/connection behavior analyzer.
type TCPAnalyzerConfig struct {
	Enabled                       bool
	SessionResumptionEnabled      bool
	MinConnectionsForSessionCheck int // default 10
	ShortLifespanEnabled          bool
	ShortLifespanThresholdMS      int // default 500
	ConcurrencyEnabled            bool
	ConcurrencyModerate           int // default 20
	ConcurrencyHigh               int // default 50
	ConcurrencySevere             int // default 100
	ReturnVisitorEnabled          bool
	ReturnVisitorMinDays          int     // default 7
	ReturnVisitorMinAllowRate     float64 // default 0.90
}

// TCPAnalyzer checks TCP-level connection behavior signals.
// Port of src/security/tcp_analyzer.py.
type TCPAnalyzer struct {
	cfg   *TCPAnalyzerConfig
	redis RedisReader
	log   *logrus.Logger
}

// NewTCPAnalyzer creates a TCPAnalyzer with the given configuration.
func NewTCPAnalyzer(cfg *TCPAnalyzerConfig, redis RedisReader, log *logrus.Logger) *TCPAnalyzer {
	if log == nil {
		log = logrus.New()
	}
	if cfg == nil {
		cfg = &TCPAnalyzerConfig{}
	}
	return &TCPAnalyzer{cfg: cfg, redis: redis, log: log}
}

// Analyze returns risk signals for TCP/connection-level behavior.
// Never returns an error; fails open.
func (a *TCPAnalyzer) Analyze(ctx context.Context, conn *ConnectionContext) []RiskSignal {
	if !a.cfg.Enabled {
		return nil
	}
	var signals []RiskSignal

	// Session resumption check
	if a.cfg.SessionResumptionEnabled {
		sessionKey := "session:" + conn.ClientIP
		sessionData := a.redis.HGetAll(ctx, sessionKey)
		if sessionData != nil {
			total, _ := strconv.Atoi(sessionData["total"])
			resumed, _ := strconv.Atoi(sessionData["resumed"])
			min := a.cfg.MinConnectionsForSessionCheck
			if total >= min && total > 0 {
				ratio := float64(resumed) / float64(total)
				if ratio < 0.05 {
					metrics.TCPSignalTotal.WithLabelValues("no_session_resumption").Inc()
					signals = append(signals, RiskSignal{
						Name:   "no_session_resumption",
						Score:  15,
						Reason: "very low session resumption rate",
						Weight: 1.0,
					})
				}
			}
		}
	}

	// Short connection lifespan
	if a.cfg.ShortLifespanEnabled && conn.ConnectionLifespanMS > 0 {
		threshold := a.cfg.ShortLifespanThresholdMS
		if conn.ConnectionLifespanMS < threshold {
			metrics.TCPSignalTotal.WithLabelValues("short_connection_lifespan").Inc()
			signals = append(signals, RiskSignal{
				Name:   "short_connection_lifespan",
				Score:  20,
				Reason: "connection closed unusually quickly",
				Weight: 1.0,
			})
		}
	}

	// Concurrency check
	if a.cfg.ConcurrencyEnabled {
		concurrentKey := "concurrent:" + conn.ClientIP
		concurrentStr := a.redis.GetString(ctx, concurrentKey)
		concurrent, _ := strconv.Atoi(concurrentStr)
		metrics.ActiveConnections.Set(float64(concurrent))

		severe := a.cfg.ConcurrencySevere
		high := a.cfg.ConcurrencyHigh
		moderate := a.cfg.ConcurrencyModerate

		if concurrent >= severe {
			metrics.TCPSignalTotal.WithLabelValues("severe_concurrency").Inc()
			signals = append(signals, RiskSignal{
				Name:   "severe_concurrency",
				Score:  40,
				Reason: "very high concurrent connection count",
				Weight: 1.0,
			})
		} else if concurrent >= high {
			metrics.TCPSignalTotal.WithLabelValues("high_concurrency").Inc()
			signals = append(signals, RiskSignal{
				Name:   "high_concurrency",
				Score:  25,
				Reason: "high concurrent connection count",
				Weight: 1.0,
			})
		} else if concurrent >= moderate {
			metrics.TCPSignalTotal.WithLabelValues("moderate_concurrency").Inc()
			signals = append(signals, RiskSignal{
				Name:   "moderate_concurrency",
				Score:  10,
				Reason: "moderate concurrent connection count",
				Weight: 1.0,
			})
		}
	}

	// Return visitor trust
	if a.cfg.ReturnVisitorEnabled {
		rvKey := "return_visitor:" + conn.ClientIP
		rvData := a.redis.HGetAll(ctx, rvKey)
		if rvData != nil {
			total, _ := strconv.Atoi(rvData["total"])
			allowed, _ := strconv.Atoi(rvData["allowed"])
			firstSeenStr := rvData["first_seen"]
			if total > 0 && firstSeenStr != "" {
				firstSeen, err := strconv.ParseInt(firstSeenStr, 10, 64)
				minDays := a.cfg.ReturnVisitorMinDays
				minRate := a.cfg.ReturnVisitorMinAllowRate
				ageDays := time.Since(time.Unix(firstSeen, 0)).Hours() / 24
				allowRate := float64(allowed) / float64(total)
				if err == nil && ageDays >= float64(minDays) && allowRate >= minRate {
					metrics.TCPSignalTotal.WithLabelValues("return_visitor_trust").Inc()
					signals = append(signals, RiskSignal{
						Name:   "return_visitor_trust",
						Score:  -20,
						Reason: "established return visitor with high allow rate",
						Weight: 1.0,
					})
				}
			}
		}
	}

	return signals
}
