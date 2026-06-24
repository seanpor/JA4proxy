package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

// Regression test for JA4PROXY-2026-0048 — Verbose Error Logging Exposes Internals.
//
// The Go proxy used to log verbatim filesystem paths, Redis keys, and backend
// IP:port values. In production environments where logs reach a SIEM, every
// operator with log-read access could reconstruct the internal layout of the
// deployment (where certs live, what the ban-key namespace looks like, which
// upstream a given proxy instance fronts). SensitiveFieldRedactor installs
// on the root logger when ENVIRONMENT=production and keeps operationally
// useful *shape* (file basename, ":port" suffix, Redis category prefix)
// while dropping the concrete value.

func logWithRedactor(t *testing.T, enabled bool, fields logrus.Fields, msg string) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	log := logrus.New()
	log.SetOutput(&buf)
	log.SetLevel(logrus.DebugLevel)
	log.SetFormatter(&logrus.JSONFormatter{})
	log.AddHook(&SensitiveFieldRedactor{Enabled: enabled})
	log.WithFields(fields).Warn(msg)
	line := strings.TrimSpace(buf.String())
	out := make(map[string]any)
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatalf("unmarshal log line: %v; line=%q", err, line)
	}
	return out
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func TestRegression_JA4PROXY_2026_0048_disabled_in_dev(t *testing.T) {
	// ENVIRONMENT is not production — redactor disabled, full values retained.
	fields := logrus.Fields{
		"path":    "/etc/ja4proxy/tls/server.crt",
		"key":     "ban:203.0.113.5",
		"backend": "10.0.0.5:443",
		"prefix":  "10.0.0.0/24",
	}
	out := logWithRedactor(t, false, fields, "dev: untouched")
	if got := out["path"]; got != "/etc/ja4proxy/tls/server.crt" {
		t.Fatalf("dev mode must not rewrite path; got %v", got)
	}
	if got := out["key"]; got != "ban:203.0.113.5" {
		t.Fatalf("dev mode must not rewrite Redis key; got %v", got)
	}
	if got := out["backend"]; got != "10.0.0.5:443" {
		t.Fatalf("dev mode must not rewrite backend; got %v", got)
	}
	if got := out["prefix"]; got != "10.0.0.0/24" {
		t.Fatalf("dev mode must not rewrite CIDR prefix; got %v", got)
	}
}

func TestRegression_JA4PROXY_2026_0048_redacts_paths_in_production(t *testing.T) {
	cases := []struct {
		field string
		in    string
		want  string
	}{
		{"path", "/etc/ja4proxy/tls/server.crt", "server.crt"},
		{"cert_path", "/var/lib/ja4proxy/certs/proxy.pem", "proxy.pem"},
		{"db_path", "/opt/maxmind/GeoLite2-ASN.mmdb", "GeoLite2-ASN.mmdb"},
		{"config_path", "/etc/ja4proxy/config/proxy.yml", "proxy.yml"},
		{"feed_path", "/var/cache/ja4proxy/feeds/drop.txt", "drop.txt"},
	}
	for _, tc := range cases {
		out := logWithRedactor(t, true, logrus.Fields{tc.field: tc.in}, "prod: path test")
		if got := out[tc.field]; got != tc.want {
			t.Errorf("field=%s: expected basename %q, got %v", tc.field, tc.want, got)
		}
		// Must not leak the directory portion anywhere in the line.
		if strings.Contains(mustJSON(out), "/etc/") || strings.Contains(mustJSON(out), "/var/") || strings.Contains(mustJSON(out), "/opt/") {
			t.Errorf("field=%s: directory component leaked: %s", tc.field, mustJSON(out))
		}
	}
}

func TestRegression_JA4PROXY_2026_0048_redacts_redis_keys_in_production(t *testing.T) {
	// Category prefix is preserved so operators can tell which subsystem is
	// affected; the actual key value is redacted.
	cases := []struct {
		in   string
		want string
	}{
		{"ban:203.0.113.5", "ban:<redacted>"},
		{"ja4:whitelist", "ja4:<redacted>"},
		{"beacon:suspects", "beacon:<redacted>"},
		{"config:dial", "config:<redacted>"},
		{"analytics:stream:events", "analytics:<redacted>"},
	}
	for _, tc := range cases {
		out := logWithRedactor(t, true, logrus.Fields{"key": tc.in}, "prod: redis key")
		if got := out["key"]; got != tc.want {
			t.Errorf("key=%q: want %q, got %v", tc.in, tc.want, got)
		}
	}
}

func TestRegression_JA4PROXY_2026_0048_redis_key_without_prefix(t *testing.T) {
	// Bare keys (no ':') have no shape worth preserving — drop the whole value.
	out := logWithRedactor(t, true, logrus.Fields{"key": "opaque-singleton"}, "prod: opaque")
	if got := out["key"]; got != "<redacted>" {
		t.Fatalf("bare key should be wholly redacted; got %v", got)
	}
}

func TestRegression_JA4PROXY_2026_0048_redacts_addresses_in_production(t *testing.T) {
	cases := []struct {
		field string
		in    string
		want  string
	}{
		{"backend", "10.0.0.5:443", "<redacted>:443"},
		{"addr", "192.168.1.100:8080", "<redacted>:8080"},
		{"upstream", "10.2.3.4:9000", "<redacted>:9000"},
	}
	for _, tc := range cases {
		out := logWithRedactor(t, true, logrus.Fields{tc.field: tc.in}, "prod: addr")
		if got := out[tc.field]; got != tc.want {
			t.Errorf("field=%s: want %q, got %v", tc.field, tc.want, got)
		}
		// Hard assertion — the IP octets must not appear anywhere.
		for _, leak := range []string{"10.0.0.5", "192.168.1.100", "10.2.3.4"} {
			if strings.Contains(mustJSON(out), leak) {
				t.Errorf("field=%s: IP %q leaked in output %s", tc.field, leak, mustJSON(out))
			}
		}
	}
}

func TestRegression_JA4PROXY_2026_0048_redacts_opaque_fields_in_production(t *testing.T) {
	cases := []struct {
		field string
		in    string
	}{
		{"prefix", "10.0.0.0/24"},
		{"val", "not-a-number-oops"},
		{"pubsub_raw", "dial:42:hmacABCDEF"},
		{"sig", "aabbccddeeff00112233445566778899aabbccdd"},
	}
	for _, tc := range cases {
		out := logWithRedactor(t, true, logrus.Fields{tc.field: tc.in}, "prod: opaque field")
		if got := out[tc.field]; got != "<redacted>" {
			t.Errorf("field=%s: want <redacted>, got %v", tc.field, got)
		}
		if strings.Contains(mustJSON(out), tc.in) {
			t.Errorf("field=%s: original value leaked: %s", tc.field, mustJSON(out))
		}
	}
}

func TestRegression_JA4PROXY_2026_0048_preserves_unrelated_fields(t *testing.T) {
	// Redacting sensitive fields must not disturb normal telemetry fields —
	// client_ip, ja4, score etc. must be passed through verbatim so the
	// security event log remains useful.
	fields := logrus.Fields{
		"path":      "/etc/secret/tls.pem",
		"client_ip": "8.8.8.8",
		"ja4":       "t13d1516h2_aabbccddeeff_aabbccddeeff",
		"score":     42,
		"action":    "block",
	}
	out := logWithRedactor(t, true, fields, "prod: mixed")
	if got := out["path"]; got != "tls.pem" {
		t.Errorf("path should be redacted to basename; got %v", got)
	}
	if got := out["client_ip"]; got != "8.8.8.8" {
		t.Errorf("client_ip must pass through; got %v", got)
	}
	if got := out["ja4"]; got != "t13d1516h2_aabbccddeeff_aabbccddeeff" {
		t.Errorf("ja4 must pass through; got %v", got)
	}
	if got := out["action"]; got != "block" {
		t.Errorf("action must pass through; got %v", got)
	}
}

func TestNewSensitiveFieldRedactor_respects_ENVIRONMENT(t *testing.T) {
	cases := []struct {
		env     string
		enabled bool
	}{
		{"production", true},
		{"PRODUCTION", true},
		{"prod", true},
		{"Prod", true},
		{"", false},
		{"dev", false},
		{"staging", false},
		{"test", false},
	}
	for _, tc := range cases {
		t.Setenv("ENVIRONMENT", tc.env)
		r := NewSensitiveFieldRedactor()
		if r.Enabled != tc.enabled {
			t.Errorf("ENVIRONMENT=%q: expected Enabled=%v, got %v", tc.env, tc.enabled, r.Enabled)
		}
	}
}

// TestRegression_JA4PROXY_2026_0039_RedactorDoesNotPatternMatchDigits guards the
// "Sensitive Data Filter Matches Timestamps (False Positive)" finding. The deleted
// Python proxy ran a Luhn/credit-card regex (\d{13,19}) over log values and
// false-matched epoch timestamps. The Go redactor redacts strictly by field *name*
// (path/addr/opaque/key) and performs no value/digit pattern matching, so long
// digit strings and timestamps pass through untouched — the false positive is
// architecturally impossible.
func TestRegression_JA4PROXY_2026_0039_RedactorDoesNotPatternMatchDigits(t *testing.T) {
	r := NewSensitiveFieldRedactor()
	r.Enabled = true // force production behaviour regardless of test ENVIRONMENT
	want := map[string]string{
		"ts_ms":    "1700000000000",    // 13-digit epoch ms — tripped the Python Luhn regex
		"counter":  "4111111111111111", // 16 digits (test-card shape)
		"duration": "9223372036854775", // long digit run
	}
	fields := logrus.Fields{}
	for k, v := range want {
		fields[k] = v
	}
	entry := &logrus.Entry{Data: fields}
	if err := r.Fire(entry); err != nil {
		t.Fatalf("Fire returned error: %v", err)
	}
	for k, expected := range want {
		if got := entry.Data[k]; got != expected {
			t.Errorf("field %q = %v; want unchanged %q (Go redactor must not digit/Luhn-match)", k, got, expected)
		}
	}
}

// Compile-time proof that we implement logrus.Hook.
var _ logrus.Hook = (*SensitiveFieldRedactor)(nil)
