// Package logging provides ECS 8.x-compliant log formatting for JA4proxy.
// These tests verify that ECSFormatter produces output conforming to the
// Elastic Common Schema field names expected by SIEM platforms.
package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// formatEntry creates a logrus.Entry with the given fields, runs it through
// ECSFormatter, and returns the parsed JSON map.
func formatEntry(t *testing.T, fields logrus.Fields, msg string) map[string]interface{} {
	t.Helper()
	f := &ECSFormatter{}
	entry := &logrus.Entry{
		Logger:  logrus.New(),
		Data:    fields,
		Time:    time.Now(),
		Level:   logrus.InfoLevel,
		Message: msg,
	}
	b, err := f.Format(entry)
	if err != nil {
		t.Fatalf("ECSFormatter.Format returned error: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("ECSFormatter output is not valid JSON: %v\nraw: %s", err, b)
	}
	return out
}

// formatLegacyEntry runs ECSFormatter in legacy mode and returns parsed JSON.
func formatLegacyEntry(t *testing.T, fields logrus.Fields, msg string) map[string]interface{} {
	t.Helper()
	f := &ECSFormatter{Format: "legacy"}
	entry := &logrus.Entry{
		Logger:  logrus.New(),
		Data:    fields,
		Time:    time.Now(),
		Level:   logrus.InfoLevel,
		Message: msg,
	}
	b, err := f.Format(entry)
	if err != nil {
		t.Fatalf("ECSFormatter(legacy).Format returned error: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("ECSFormatter(legacy) output is not valid JSON: %v\nraw: %s", err, b)
	}
	return out
}

// ── @timestamp ────────────────────────────────────────────────────────────────

func TestECSFormatter_AtTimestamp(t *testing.T) {
	out := formatEntry(t, logrus.Fields{}, "test event")
	ts, ok := out["@timestamp"]
	if !ok {
		t.Fatal("ECS output missing '@timestamp' field")
	}
	tsStr, ok := ts.(string)
	if !ok {
		t.Fatalf("'@timestamp' should be a string, got %T", ts)
	}
	// ECS requires RFC3339 — must be parseable
	if _, err := time.Parse(time.RFC3339Nano, tsStr); err != nil {
		if _, err2 := time.Parse(time.RFC3339, tsStr); err2 != nil {
			t.Errorf("'@timestamp' %q is not RFC3339: %v", tsStr, err)
		}
	}
}

func TestECSFormatter_NoLegacyTimestamp(t *testing.T) {
	out := formatEntry(t, logrus.Fields{}, "test event")
	if _, ok := out["timestamp"]; ok {
		t.Error("ECS output should NOT have 'timestamp' — only '@timestamp'")
	}
}

// ── source.ip ─────────────────────────────────────────────────────────────────

func TestECSFormatter_SourceIP(t *testing.T) {
	out := formatEntry(t, logrus.Fields{"client_ip": "203.0.113.42"}, "connection")
	if out["source.ip"] != "203.0.113.42" {
		t.Errorf("source.ip = %v, want %q", out["source.ip"], "203.0.113.42")
	}
}

func TestECSFormatter_SourceIP_IPv6(t *testing.T) {
	out := formatEntry(t, logrus.Fields{"client_ip": "2001:db8::1"}, "connection")
	if out["source.ip"] != "2001:db8::1" {
		t.Errorf("source.ip = %v, want %q", out["source.ip"], "2001:db8::1")
	}
}

func TestECSFormatter_SourceIP_AbsentWhenNoClientIP(t *testing.T) {
	out := formatEntry(t, logrus.Fields{}, "connection")
	if _, ok := out["source.ip"]; ok {
		t.Error("source.ip should not be present when client_ip log field is absent")
	}
}

// ── destination.port ─────────────────────────────────────────────────────────

func TestECSFormatter_DestinationPort(t *testing.T) {
	out := formatEntry(t, logrus.Fields{}, "connection")
	port, ok := out["destination.port"]
	if !ok {
		t.Fatal("ECS output missing 'destination.port' field")
	}
	// JSON numbers unmarshal to float64 in Go
	portNum, ok := port.(float64)
	if !ok {
		t.Fatalf("destination.port should be a number, got %T: %v", port, port)
	}
	if int(portNum) != 443 {
		t.Errorf("destination.port = %d, want 443", int(portNum))
	}
}

// ── event.action ─────────────────────────────────────────────────────────────

func TestECSFormatter_EventAction_Allow(t *testing.T) {
	out := formatEntry(t, logrus.Fields{"action": "allow"}, "connection")
	if out["event.action"] != "allow" {
		t.Errorf("event.action = %v, want 'allow'", out["event.action"])
	}
}

func TestECSFormatter_EventAction_Block(t *testing.T) {
	out := formatEntry(t, logrus.Fields{"action": "block"}, "connection")
	if out["event.action"] != "block" {
		t.Errorf("event.action = %v, want 'block'", out["event.action"])
	}
}

func TestECSFormatter_EventAction_Ban(t *testing.T) {
	out := formatEntry(t, logrus.Fields{"action": "ban"}, "connection")
	if out["event.action"] != "ban" {
		t.Errorf("event.action = %v, want 'ban'", out["event.action"])
	}
}

func TestECSFormatter_EventAction_AllActions(t *testing.T) {
	actions := []string{"allow", "block", "ban", "tarpit", "flagged", "rate_limited"}
	for _, action := range actions {
		out := formatEntry(t, logrus.Fields{"action": action}, "connection")
		if out["event.action"] != action {
			t.Errorf("action=%q: event.action = %v, want %q", action, out["event.action"], action)
		}
	}
}

// ── event.outcome ─────────────────────────────────────────────────────────────

func TestECSFormatter_EventOutcome_Allow(t *testing.T) {
	out := formatEntry(t, logrus.Fields{"action": "allow"}, "connection")
	if out["event.outcome"] != "success" {
		t.Errorf("event.outcome for allow = %v, want 'success'", out["event.outcome"])
	}
}

func TestECSFormatter_EventOutcome_Block(t *testing.T) {
	out := formatEntry(t, logrus.Fields{"action": "block"}, "connection")
	if out["event.outcome"] != "failure" {
		t.Errorf("event.outcome for block = %v, want 'failure'", out["event.outcome"])
	}
}

func TestECSFormatter_EventOutcome_Ban(t *testing.T) {
	out := formatEntry(t, logrus.Fields{"action": "ban"}, "connection")
	if out["event.outcome"] != "failure" {
		t.Errorf("event.outcome for ban = %v, want 'failure'", out["event.outcome"])
	}
}

func TestECSFormatter_EventOutcome_Tarpit(t *testing.T) {
	out := formatEntry(t, logrus.Fields{"action": "tarpit"}, "connection")
	if out["event.outcome"] != "failure" {
		t.Errorf("event.outcome for tarpit = %v, want 'failure'", out["event.outcome"])
	}
}

// ── event.kind, event.category ───────────────────────────────────────────────

func TestECSFormatter_EventKind(t *testing.T) {
	out := formatEntry(t, logrus.Fields{}, "connection")
	if out["event.kind"] != "event" {
		t.Errorf("event.kind = %v, want 'event'", out["event.kind"])
	}
}

func TestECSFormatter_EventCategory(t *testing.T) {
	out := formatEntry(t, logrus.Fields{}, "connection")
	raw, ok := out["event.category"]
	if !ok {
		t.Fatal("ECS output missing 'event.category' field")
	}
	// Must be a JSON array of strings
	categories, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("event.category should be an array, got %T: %v", raw, raw)
	}
	categoryStrings := make([]string, 0, len(categories))
	for _, c := range categories {
		s, ok := c.(string)
		if !ok {
			t.Fatalf("event.category element should be string, got %T", c)
		}
		categoryStrings = append(categoryStrings, s)
	}
	hasNetwork := false
	hasIDS := false
	for _, c := range categoryStrings {
		if c == "network" {
			hasNetwork = true
		}
		if c == "intrusion_detection" {
			hasIDS = true
		}
	}
	if !hasNetwork {
		t.Errorf("event.category %v missing 'network'", categoryStrings)
	}
	if !hasIDS {
		t.Errorf("event.category %v missing 'intrusion_detection'", categoryStrings)
	}
}

// ── network fields ────────────────────────────────────────────────────────────

func TestECSFormatter_NetworkTransport(t *testing.T) {
	out := formatEntry(t, logrus.Fields{}, "connection")
	if out["network.transport"] != "tcp" {
		t.Errorf("network.transport = %v, want 'tcp'", out["network.transport"])
	}
}

func TestECSFormatter_NetworkProtocol(t *testing.T) {
	out := formatEntry(t, logrus.Fields{}, "connection")
	if out["network.protocol"] != "tls" {
		t.Errorf("network.protocol = %v, want 'tls'", out["network.protocol"])
	}
}

// ── service.name ──────────────────────────────────────────────────────────────

func TestECSFormatter_ServiceName(t *testing.T) {
	out := formatEntry(t, logrus.Fields{}, "connection")
	if out["service.name"] != "ja4proxy" {
		t.Errorf("service.name = %v, want 'ja4proxy'", out["service.name"])
	}
}

// ── ja4proxy namespace fields ─────────────────────────────────────────────────

func TestECSFormatter_JA4Fingerprint(t *testing.T) {
	ja4 := "t13d1516h2_aabbccddeeff_aabbccddeeff"
	out := formatEntry(t, logrus.Fields{"ja4": ja4}, "connection")
	if out["ja4proxy.fingerprint.ja4"] != ja4 {
		t.Errorf("ja4proxy.fingerprint.ja4 = %v, want %q", out["ja4proxy.fingerprint.ja4"], ja4)
	}
}

func TestECSFormatter_JA4X_Fingerprint(t *testing.T) {
	ja4x := "aabbccddee11_ffeeddccbb22_112233445566"
	out := formatEntry(t, logrus.Fields{"ja4x": ja4x}, "connection")
	if out["ja4proxy.fingerprint.ja4x"] != ja4x {
		t.Errorf("ja4proxy.fingerprint.ja4x = %v, want %q", out["ja4proxy.fingerprint.ja4x"], ja4x)
	}
}

func TestECSFormatter_JA4T_Fingerprint(t *testing.T) {
	ja4t := "1460_2_1_1_1460_M1460"
	out := formatEntry(t, logrus.Fields{"ja4t": ja4t}, "connection")
	if out["ja4proxy.fingerprint.ja4t"] != ja4t {
		t.Errorf("ja4proxy.fingerprint.ja4t = %v, want %q", out["ja4proxy.fingerprint.ja4t"], ja4t)
	}
}

func TestECSFormatter_JA4Fields_AbsentWhenNotLogged(t *testing.T) {
	out := formatEntry(t, logrus.Fields{}, "connection")
	for _, field := range []string{"ja4proxy.fingerprint.ja4", "ja4proxy.fingerprint.ja4x", "ja4proxy.fingerprint.ja4t"} {
		if _, ok := out[field]; ok {
			t.Errorf("%q should not be present when the corresponding log field is absent", field)
		}
	}
}

func TestECSFormatter_Score(t *testing.T) {
	out := formatEntry(t, logrus.Fields{"score": 72}, "connection")
	score, ok := out["ja4proxy.score"]
	if !ok {
		t.Fatal("ECS output missing 'ja4proxy.score' field")
	}
	if int(score.(float64)) != 72 {
		t.Errorf("ja4proxy.score = %v, want 72", score)
	}
}

func TestECSFormatter_SNI(t *testing.T) {
	out := formatEntry(t, logrus.Fields{"sni": "example.com"}, "connection")
	if out["ja4proxy.sni"] != "example.com" {
		t.Errorf("ja4proxy.sni = %v, want 'example.com'", out["ja4proxy.sni"])
	}
}

func TestECSFormatter_ALPN(t *testing.T) {
	out := formatEntry(t, logrus.Fields{"alpn": "h2"}, "connection")
	if out["ja4proxy.alpn"] != "h2" {
		t.Errorf("ja4proxy.alpn = %v, want 'h2'", out["ja4proxy.alpn"])
	}
}

func TestECSFormatter_CountryCode(t *testing.T) {
	out := formatEntry(t, logrus.Fields{"country": "US"}, "connection")
	if out["ja4proxy.country_code"] != "US" {
		t.Errorf("ja4proxy.country_code = %v, want 'US'", out["ja4proxy.country_code"])
	}
}

// ── ja4proxy.signals ─────────────────────────────────────────────────────────

func TestECSFormatter_Signals_Array(t *testing.T) {
	signals := []map[string]interface{}{
		{"name": "tor_exit", "score": 40, "reason": "IP is a known Tor exit node"},
		{"name": "missing_sni", "score": 15, "reason": "No SNI extension in ClientHello"},
	}
	out := formatEntry(t, logrus.Fields{"signals": signals}, "connection")
	raw, ok := out["ja4proxy.signals"]
	if !ok {
		t.Fatal("ECS output missing 'ja4proxy.signals' field")
	}
	arr, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("ja4proxy.signals should be array, got %T", raw)
	}
	if len(arr) != 2 {
		t.Fatalf("ja4proxy.signals length = %d, want 2", len(arr))
	}
	for i, elem := range arr {
		m, ok := elem.(map[string]interface{})
		if !ok {
			t.Fatalf("signals[%d] should be an object, got %T", i, elem)
		}
		if _, ok := m["name"]; !ok {
			t.Errorf("signals[%d] missing 'name' key", i)
		}
		if _, ok := m["score"]; !ok {
			t.Errorf("signals[%d] missing 'score' key", i)
		}
		if _, ok := m["reason"]; !ok {
			t.Errorf("signals[%d] missing 'reason' key — must use 'reason' not 'detail'", i)
		}
	}
}

func TestECSFormatter_Signals_UseReasonNotDetail(t *testing.T) {
	signals := []map[string]interface{}{
		{"name": "test_signal", "score": 10, "reason": "test reason here"},
	}
	out := formatEntry(t, logrus.Fields{"signals": signals}, "connection")
	arr := out["ja4proxy.signals"].([]interface{})
	m := arr[0].(map[string]interface{})
	if _, hasDetail := m["detail"]; hasDetail {
		t.Error("signal element should have 'reason' key, not 'detail'")
	}
	if m["reason"] != "test reason here" {
		t.Errorf("signal reason = %v, want 'test reason here'", m["reason"])
	}
}

// ── legacy mode ───────────────────────────────────────────────────────────────

func TestECSFormatter_LegacyMode_HasTimestamp(t *testing.T) {
	out := formatLegacyEntry(t, logrus.Fields{}, "legacy event")
	if _, ok := out["timestamp"]; !ok {
		t.Error("legacy mode should have 'timestamp' field (not '@timestamp')")
	}
	if _, ok := out["@timestamp"]; ok {
		t.Error("legacy mode should NOT have '@timestamp' field")
	}
}

func TestECSFormatter_LegacyMode_HasLevelAndMessage(t *testing.T) {
	out := formatLegacyEntry(t, logrus.Fields{}, "legacy event")
	if _, ok := out["level"]; !ok {
		t.Error("legacy mode missing 'level' field")
	}
	if _, ok := out["message"]; !ok {
		t.Error("legacy mode missing 'message' field")
	}
}

func TestECSFormatter_LegacyMode_FieldsAtTopLevel(t *testing.T) {
	out := formatLegacyEntry(t, logrus.Fields{"action": "block", "score": 75}, "blocked")
	if out["action"] != "block" {
		t.Errorf("legacy mode: 'action' field should be at top level, got %v", out["action"])
	}
	if int(out["score"].(float64)) != 75 {
		t.Errorf("legacy mode: 'score' field should be at top level, got %v", out["score"])
	}
}

// ── ban event — threat.indicator fields ──────────────────────────────────────

func TestECSFormatter_BanEvent_ThreatIndicatorIP(t *testing.T) {
	out := formatEntry(t, logrus.Fields{
		"action":    "ban",
		"client_ip": "198.51.100.99",
	}, "ban event")
	if out["threat.indicator.ip"] != "198.51.100.99" {
		t.Errorf("threat.indicator.ip = %v, want '198.51.100.99'", out["threat.indicator.ip"])
	}
}

func TestECSFormatter_BanEvent_ThreatIndicatorType_IPv4(t *testing.T) {
	out := formatEntry(t, logrus.Fields{
		"action":    "ban",
		"client_ip": "198.51.100.99",
	}, "ban event")
	if out["threat.indicator.type"] != "ipv4-addr" {
		t.Errorf("threat.indicator.type = %v, want 'ipv4-addr'", out["threat.indicator.type"])
	}
}

func TestECSFormatter_BanEvent_ThreatIndicatorType_IPv6(t *testing.T) {
	out := formatEntry(t, logrus.Fields{
		"action":    "ban",
		"client_ip": "2001:db8::dead:beef",
	}, "ban event")
	if out["threat.indicator.type"] != "ipv6-addr" {
		t.Errorf("threat.indicator.type = %v, want 'ipv6-addr'", out["threat.indicator.type"])
	}
}

func TestECSFormatter_NonBanEvent_NoThreatIndicator(t *testing.T) {
	out := formatEntry(t, logrus.Fields{
		"action":    "block",
		"client_ip": "198.51.100.99",
	}, "block event")
	if _, ok := out["threat.indicator.ip"]; ok {
		t.Error("threat.indicator.ip should only be set for ban events, not block events")
	}
}

// ── schema validation ─────────────────────────────────────────────────────────

func TestECSFormatter_SchemaValidation_RequiredKeys(t *testing.T) {
	out := formatEntry(t, logrus.Fields{
		"client_ip": "1.2.3.4",
		"action":    "allow",
		"score":     50,
	}, "connection event")

	required := []string{
		"@timestamp",
		"event.action",
		"event.kind",
		"event.category",
		"event.outcome",
		"network.transport",
		"network.protocol",
		"service.name",
		"destination.port",
		"source.ip",
	}
	for _, key := range required {
		if _, ok := out[key]; !ok {
			t.Errorf("Required ECS field %q is missing from output", key)
		}
	}
}

func TestECSFormatter_OutputIsValidJSON(t *testing.T) {
	f := &ECSFormatter{}
	entry := &logrus.Entry{
		Logger:  logrus.New(),
		Data:    logrus.Fields{"client_ip": "10.0.0.1", "action": "block", "score": 80},
		Time:    time.Now(),
		Level:   logrus.WarnLevel,
		Message: "blocked connection",
	}
	b, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format returned error: %v", err)
	}
	if !json.Valid(b) {
		t.Fatalf("output is not valid JSON: %s", b)
	}
	// Must end with newline for log aggregator line parsing
	if !bytes.HasSuffix(b, []byte("\n")) {
		t.Error("formatted output should end with newline")
	}
}

func TestECSFormatter_EventRiskScore(t *testing.T) {
	out := formatEntry(t, logrus.Fields{"score": 88}, "high risk")
	score, ok := out["event.risk_score"]
	if !ok {
		t.Fatal("ECS output missing 'event.risk_score' field")
	}
	if int(score.(float64)) != 88 {
		t.Errorf("event.risk_score = %v, want 88", score)
	}
}

func TestECSFormatter_OriginalFieldsNotPassedThrough(t *testing.T) {
	// Raw log fields (client_ip, action, score) should be mapped to ECS names,
	// not also appear at the top level.
	out := formatEntry(t, logrus.Fields{
		"client_ip": "10.0.0.1",
		"action":    "block",
		"score":     70,
	}, "blocked")
	// The original field names should be remapped and not appear raw at top level
	if _, ok := out["client_ip"]; ok {
		t.Error("'client_ip' should be remapped to 'source.ip', not kept at top level")
	}
	if _, ok := out["action"]; ok {
		t.Error("'action' should be remapped to 'event.action', not kept at top level")
	}
}

func TestECSFormatter_MessageField(t *testing.T) {
	out := formatEntry(t, logrus.Fields{}, "proxy: blocked connection")
	if out["message"] != "proxy: blocked connection" {
		t.Errorf("message field = %v, want 'proxy: blocked connection'", out["message"])
	}
}

func TestECSFormatter_LevelField(t *testing.T) {
	f := &ECSFormatter{}
	entry := &logrus.Entry{
		Logger:  logrus.New(),
		Data:    logrus.Fields{},
		Time:    time.Now(),
		Level:   logrus.WarnLevel,
		Message: "warning event",
	}
	b, _ := f.Format(entry)
	var out map[string]interface{}
	json.Unmarshal(b, &out) //nolint:errcheck
	level := strings.ToLower(out["log.level"].(string))
	if level != "warning" {
		t.Errorf("log.level = %q, want 'warning'", level)
	}
}
