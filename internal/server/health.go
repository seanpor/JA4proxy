package server

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/seanpor/ja4proxy/internal/health"
)

func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	redisStatus := "ok"
	if s.Redis != nil {
		if err := s.Redis.Ping(ctx); err != nil {
			redisStatus = "error"
		}
	}
	status := "ok"
	if redisStatus != "ok" {
		status = "degraded"
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": status, "redis": redisStatus}); err != nil {
		if s.Log != nil {
			s.Log.WithError(err).Warn("health: failed to encode response")
		}
	}
}

func (s *Server) HandleHealthDeep(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	s.Mu.Lock()
	if s.HealthState == nil {
		s.HealthState = health.New(health.Config{FailThreshold: 3})
	}
	hs := s.HealthState
	s.Mu.Unlock()

	redisOK := true
	redisLatencyMs := 0.0
	t0 := time.Now()
	if s.Redis != nil {
		if err := s.Redis.Ping(ctx); err != nil {
			redisOK = false
			hs.RecordFailure("redis")
		} else {
			redisLatencyMs = float64(time.Since(t0).Microseconds()) / 1000.0
			hs.RecordSuccess("redis")
		}
	} else {
		redisOK = false
		hs.RecordFailure("redis")
	}
	redisUnhealthy := hs.IsUnhealthy("redis")

	dial := 0
	if s.Redis != nil {
		dial = s.Redis.GetDial(ctx)
	}

	activeBans := 0
	if redisOK && s.Redis != nil {
		activeBans = s.Redis.CountKeys(ctx, "ban:*")
	}

	connTotal := 0.0
	blocksTotal := 0.0
	{
		mfs, gatherErr := prometheus.DefaultGatherer.Gather()
		if gatherErr == nil {
			for _, mf := range mfs {
				if mf.GetName() == "ja4proxy_connections_total" {
					for _, m := range mf.GetMetric() {
						val := m.GetCounter().GetValue()
						connTotal += val
						for _, lp := range m.GetLabel() {
							if lp.GetName() == "action" {
								a := lp.GetValue()
								if a == "block" || a == "ban" || a == "tarpit" || a == "rate_limit" {
									blocksTotal += val
								}
							}
						}
					}
				}
			}
		}
	}

	certTSVal := -1.0
	{
		mfs, gatherErr := prometheus.DefaultGatherer.Gather()
		if gatherErr == nil {
			for _, mf := range mfs {
				if mf.GetName() == "ja4proxy_tls_cert_expiry_timestamp_seconds" {
					for _, m := range mf.GetMetric() {
						certTSVal = m.GetGauge().GetValue()
					}
				}
			}
		}
	}
	var certDaysRemaining float64
	if certTSVal > 0 {
		certDaysRemaining = (certTSVal - float64(time.Now().Unix())) / 86400.0
		if certDaysRemaining < 0 {
			certDaysRemaining = 0
		}
	}

	blockRatePct := 0.0
	if connTotal > 0 {
		blockRatePct = blocksTotal / connTotal * 100.0
	}

	tarpitMax := 0
	if s.Cfg != nil {
		tarpitMax = s.Cfg.Tarpit.MaxActiveConnections
	}
	s.TarpitMu.Lock()
	tarpitActive := s.TarpitConcurrent
	s.TarpitMu.Unlock()
	tarpitStatus := "ok"
	if tarpitMax > 0 && tarpitActive >= tarpitMax {
		tarpitStatus = "degraded"
	}

	geoIPPresent := s.GeoIP != nil
	geoIPStatus := "ok"

	status := "ok"
	if redisUnhealthy {
		status = "error"
	} else if !redisOK {
		status = "degraded"
	} else if redisLatencyMs > 50 {
		status = "degraded"
	} else if tarpitStatus == "degraded" {
		status = "degraded"
	}

	if redisUnhealthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"status":             status,
		"redis_connected":    redisOK,
		"redis_latency_ms":   math.Round(redisLatencyMs*100) / 100,
		"dial":               dial,
		"active_connections": atomic.LoadInt64(&s.ActiveConns),
		"connections_total":  int(connTotal),
		"block_rate_pct":     math.Round(blockRatePct*100) / 100,
		"active_bans":        activeBans,
		"tarpit": map[string]any{
			"active": tarpitActive,
			"max":    tarpitMax,
			"status": tarpitStatus,
		},
		"geoip": map[string]any{
			"present": geoIPPresent,
			"status":  geoIPStatus,
		},
	}
	if certTSVal > 0 {
		resp["cert_days_remaining"] = math.Round(certDaysRemaining*10) / 10
	} else {
		resp["cert_days_remaining"] = nil
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		if s.Log != nil {
			s.Log.WithError(err).Warn("health/deep: failed to encode response")
		}
	}
}

func (s *Server) HandleMetricsSummary(w http.ResponseWriter, r *http.Request) {
	s.HandleHealthDeep(w, r)
}
