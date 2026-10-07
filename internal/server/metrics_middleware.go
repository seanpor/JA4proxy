package server

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/config"
)

func MetricsAuthMiddleware(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.MetricsRequestIsLocal(r.RemoteAddr) {
			next.ServeHTTP(w, r)
			return
		}
		if token == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		const prefix = "Bearer "
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, prefix) ||
			subtle.ConstantTimeCompare([]byte(h[len(prefix):]), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ja4proxy-metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type MetricsRateLimiter struct {
	rps        float64
	burst      float64
	mu         sync.Mutex
	bucket     map[string]*ipBucket
	maxEntries int
}

type ipBucket struct {
	tokens   float64
	lastSeen time.Time
}

func NewMetricsRateLimiter(rps float64, burst int) *MetricsRateLimiter {
	b := float64(burst)
	if b <= 0 {
		b = rps * 2
	}
	return &MetricsRateLimiter{
		rps:        rps,
		burst:      b,
		bucket:     make(map[string]*ipBucket),
		maxEntries: 4096,
	}
}

func (l *MetricsRateLimiter) Allow(remoteAddr string, now time.Time) bool {
	if l == nil || l.rps <= 0 {
		return true
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.bucket[host]
	if !ok {
		if len(l.bucket) >= l.maxEntries {
			var oldestKey string
			var oldestTime time.Time
			for k, v := range l.bucket {
				if oldestKey == "" || v.lastSeen.Before(oldestTime) {
					oldestKey = k
					oldestTime = v.lastSeen
				}
			}
			delete(l.bucket, oldestKey)
		}
		b = &ipBucket{tokens: l.burst, lastSeen: now}
		l.bucket[host] = b
	} else {
		elapsed := now.Sub(b.lastSeen).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * l.rps
			if b.tokens > l.burst {
				b.tokens = l.burst
			}
		}
		b.lastSeen = now
	}
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

func (l *MetricsRateLimiter) allow(remoteAddr string, now time.Time) bool {
	return l.Allow(remoteAddr, now)
}

func MetricsRateLimitMiddleware(next http.Handler, limiter *MetricsRateLimiter, log *logrus.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.MetricsRequestIsLocal(r.RemoteAddr) {
			next.ServeHTTP(w, r)
			return
		}
		now := time.Now()
		if limiter != nil && !limiter.Allow(r.RemoteAddr, now) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			if log != nil {
				log.WithFields(logrus.Fields{
					"remote_addr": r.RemoteAddr,
					"path":        r.URL.Path,
				}).Warn("metrics endpoint rate limit exceeded")
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}
