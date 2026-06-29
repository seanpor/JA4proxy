package logging

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

// SensitiveFieldRedactor is a logrus hook that rewrites sensitive values in
// log fields before they are serialised by the formatter.
//
// Motivation — JA4PROXY-2026-0048. Go-proxy log entries embedded absolute
// filesystem paths (TLS cert locations, GeoIP DB paths), verbatim Redis keys
// (ban:203.0.113.5), and backend IP:port pairs. A curated SIEM pipeline made
// those visible to anyone with log read access — a wider blast radius than
// the data actually needs.
//
// The redactor keeps operationally useful shape (category prefixes, port
// numbers, file basenames) but strips the concrete value. In production
// (ENVIRONMENT=prod[uction]) the hook installs automatically; otherwise it
// is a no-op so dev/test logs stay fully informative.
type SensitiveFieldRedactor struct {
	// Enabled gates the hook. When false Fire returns immediately.
	Enabled bool
}

// NewSensitiveFieldRedactor returns a redactor whose Enabled flag reflects
// the current ENVIRONMENT — "production" and "prod" enable it, anything
// else (including unset) leaves it off.
func NewSensitiveFieldRedactor() *SensitiveFieldRedactor {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("ENVIRONMENT")))
	return &SensitiveFieldRedactor{Enabled: env == "production" || env == "prod"}
}

// Levels implements logrus.Hook — we want every level to be redacted.
func (r *SensitiveFieldRedactor) Levels() []logrus.Level {
	return logrus.AllLevels
}

// pathFields are logrus field names whose values are filesystem paths.
// They are rewritten to just the basename so operators can still correlate
// "which cert failed" without exposing directory layout.
var pathFields = map[string]struct{}{
	"path":        {},
	"cert_path":   {},
	"key_path":    {},
	"ca_path":     {},
	"db_path":     {},
	"config_path": {},
	"feed_path":   {},
	"file":        {},
	"filename":    {},
}

// addrFields are field names whose values are host:port pairs. The host
// portion is replaced with a literal "<redacted>"; the port is preserved
// so operators can still see which listener or upstream is affected.
var addrFields = map[string]struct{}{
	"addr":     {},
	"backend":  {},
	"bind":     {},
	"peer":     {},
	"remote":   {},
	"target":   {},
	"upstream": {},
}

// opaqueFields are field names whose entire value is sensitive and has no
// useful residual shape — drop the value altogether.
var opaqueFields = map[string]struct{}{
	"prefix":     {}, // CIDR from netbox — can expose trusted network topology
	"val":        {}, // generic "offending value" context on parse errors
	"pubsub_raw": {}, // JA4PROXY-2026-0074: pubsub message payload may contain HMAC signatures
	"sig":        {}, // JA4PROXY-2026-0075: tampered HMAC signature on dial mismatch log
}

// Fire implements logrus.Hook. It mutates entry.Data in place.
func (r *SensitiveFieldRedactor) Fire(entry *logrus.Entry) error {
	if !r.Enabled || entry == nil {
		return nil
	}
	for k, v := range entry.Data {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if _, hit := pathFields[k]; hit {
			entry.Data[k] = redactPath(s)
			continue
		}
		if _, hit := addrFields[k]; hit {
			entry.Data[k] = redactAddr(s)
			continue
		}
		if _, hit := opaqueFields[k]; hit {
			entry.Data[k] = "<redacted>"
			continue
		}
		if k == "key" {
			entry.Data[k] = redactRedisKey(s)
		}
	}
	return nil
}

// redactPath keeps only the basename — "/etc/ja4proxy/tls/server.crt" →
// "server.crt". Empty input stays empty.
func redactPath(p string) string {
	if p == "" {
		return p
	}
	return filepath.Base(p)
}

// redactAddr preserves the ":port" suffix and replaces the host portion.
// Handles both IPv4 ("10.0.0.5:443") and bracketed IPv6 ("[::1]:443").
// Unparsable inputs become the plain "<redacted>" sentinel.
func redactAddr(addr string) string {
	if addr == "" {
		return addr
	}
	// Bracketed IPv6: "[::1]:443"
	if strings.HasPrefix(addr, "[") {
		if close := strings.Index(addr, "]"); close > 0 && close+1 < len(addr) && addr[close+1] == ':' {
			port := addr[close+2:]
			for _, c := range port {
				if c < '0' || c > '9' {
					return "<redacted>"
				}
			}
			return "<redacted>:" + port
		}
		return "<redacted>"
	}
	// IPv4 or bare host: "10.0.0.5:443" or "hostname:443"
	if idx := strings.LastIndex(addr, ":"); idx > 0 && idx < len(addr)-1 {
		port := addr[idx+1:]
		for _, c := range port {
			if c < '0' || c > '9' {
				return "<redacted>"
			}
		}
		return "<redacted>:" + port
	}
	return "<redacted>"
}

// redactRedisKey keeps the category prefix up to the first ':' so that
// "redis: GET failed" entries still tell an operator which subsystem
// (ban, ja4, beacon, analytics) is involved. "ban:203.0.113.5" becomes
// "ban:<redacted>". Keys without a ':' are redacted wholesale.
func redactRedisKey(key string) string {
	if key == "" {
		return key
	}
	idx := strings.Index(key, ":")
	if idx <= 0 {
		return "<redacted>"
	}
	return key[:idx+1] + "<redacted>"
}
