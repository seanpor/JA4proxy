package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	"github.com/seanpor/ja4proxy/internal/metrics"
	"github.com/seanpor/ja4proxy/internal/security"
)

type EventPhase string

const (
	EventPhaseProvisional EventPhase = "provisional"
	EventPhaseFinal       EventPhase = "final"
)

func SignStreamEvent(secret string, event []byte) string {
	if secret == "" {
		return ""
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(event)
	return hex.EncodeToString(m.Sum(nil))
}

func DeriveNodeID(hostname string) string {
	out := make([]rune, 0, 32)
	for _, r := range hostname {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
		if len(out) == 32 {
			break
		}
	}
	if len(out) == 0 {
		return "ja4proxy"
	}
	return string(out)
}

func (s *Server) NextConnectionID() string {
	n := atomic.AddUint64(&s.ConnSeq, 1)
	return s.NodeID + "-" + FormatUint36(n)
}

func (s *Server) EmitConnectionEvent(
	connCtx *security.ConnectionContext,
	result *security.PipelineResult,
	backendHost string,
	phase EventPhase,
) {
	if s.Dispatcher == nil || connCtx == nil || result == nil {
		return
	}
	ecsFields := map[string]interface{}{
		"@timestamp":                  time.Now().UTC().Format(time.RFC3339Nano),
		"event.action":                result.Action,
		"event.risk_score":            result.Score,
		"source.ip":                   connCtx.ClientIP,
		"source.port":                 connCtx.ClientPort,
		"destination.ip":              backendHost,
		"destination.port":            443,
		"network.transport":           "tcp",
		"network.protocol":            "tls",
		"service.name":                "ja4proxy",
		"ja4proxy.node_id":           s.NodeID,
		"ja4proxy.fingerprint.ja4":   connCtx.JA4,
		"ja4proxy.sni":               connCtx.SNI,
		"ja4proxy.dial_setting":      result.Dial,
		"ja4proxy.alpn":              connCtx.ALPN,
		"ja4proxy.tls_version":       connCtx.TLSVersion,
		"client.geo.country_iso":     connCtx.Country,
		"client.as.number":            connCtx.ASN,
		"client.as.organization.name": connCtx.ASNOrg,
		"ja4proxy.fingerprint.ja4x":   connCtx.JA4X,
		"ja4proxy.fingerprint.ja4t":   connCtx.TCPJA4T,
		"ja4proxy.bypass_reason":      result.BypassReason,
		"ja4proxy.signals":           security.BuildSignalPayload(result.Signals),
		"ja4proxy.counterfactuals":   security.BuildCounterfactualPayload(result.Counterfactuals),
	}
	ecsFields["ja4proxy.connection_id"] = connCtx.ConnectionID
	ecsFields["ja4proxy.event_phase"] = string(phase)

	if ecsJSON, err := json.Marshal(ecsFields); err == nil {
		s.EnqueueStreamEvent(ecsJSON)
	}
}

func (s *Server) EnqueueStreamEvent(event []byte) {
	if s == nil || s.StreamEventQueue == nil {
		return
	}
	select {
	case s.StreamEventQueue <- event:
		metrics.StreamEventQueueDepth.Set(float64(len(s.StreamEventQueue)))
	default:
		metrics.StreamEventDropsTotal.Inc()
	}
}

func (s *Server) StartStreamEventWorkers(ctx context.Context) {
	if s.StreamEventQueue == nil {
		return
	}
	workers := s.Cfg.Webhooks.StreamWorkers
	if workers <= 0 {
		workers = 4
	}
	timeout := time.Duration(s.Cfg.Webhooks.StreamWriteTimeoutSeconds * float64(time.Second))
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	streamKey := s.Cfg.Webhooks.StreamKey
	if streamKey == "" {
		streamKey = "events:connection"
	}
	for i := 0; i < workers; i++ {
		go s.StreamEventWorker(ctx, streamKey, timeout)
	}
}

func (s *Server) StreamEventWorker(ctx context.Context, streamKey string, timeout time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-s.StreamEventQueue:
			if !ok {
				return
			}
			metrics.StreamEventQueueDepth.Set(float64(len(s.StreamEventQueue)))
			writeCtx, cancel := context.WithTimeout(ctx, timeout)
			values := map[string]interface{}{"event": string(event)}
			if mac := SignStreamEvent(s.StreamHMACSecret, event); mac != "" {
				values["hmac"] = mac
			}
			err := s.Redis.XAddErr(writeCtx, streamKey, values)
			cancel()
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					metrics.StreamEventWriteErrorsTotal.WithLabelValues("timeout").Inc()
				} else {
					metrics.StreamEventWriteErrorsTotal.WithLabelValues("error").Inc()
				}
			}
		}
	}
}

func (s *Server) StartIntegrityWorker(ctx context.Context) {
	if s.Log != nil {
		s.Log.Info("proxy: starting integrity worker (drift detection)")
	}
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.Redis != nil {
				dial := s.Redis.GetDial(ctx)
				metrics.DialCurrent.Set(float64(dial))
			}
		}
	}
}

func FormatUint36(n uint64) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var buf [64]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%36]
		n /= 36
	}
	return string(buf[i:])
}
