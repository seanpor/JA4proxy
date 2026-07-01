package config

import (
	"strings"
	"testing"
)

func makeValidConfig() *Config {
	cfg, err := Load("../../config/proxy.yml")
	if err != nil {
		panic("cannot load proxy.yml for test: " + err.Error())
	}
	return cfg
}

func TestValidate_OK(t *testing.T) {
	cfg := makeValidConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() on proxy.yml should pass, got: %v", err)
	}
}

func TestValidate_InvalidBindPort(t *testing.T) {
	cfg := makeValidConfig()
	cfg.Proxy.BindPort = FlexInt(0)
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "bind port") {
		t.Errorf("expected bind port error, got: %v", err)
	}
}

func TestValidate_InvalidBackendPort(t *testing.T) {
	cfg := makeValidConfig()
	cfg.Proxy.BackendPort = FlexInt(70000)
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "backend port") {
		t.Errorf("expected backend port error, got: %v", err)
	}
}

func TestValidate_EmptyBackendHost(t *testing.T) {
	cfg := makeValidConfig()
	cfg.Proxy.BackendHost = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "backend host") {
		t.Errorf("expected backend host error, got: %v", err)
	}
}

func TestValidate_InvalidMaxConnections(t *testing.T) {
	cfg := makeValidConfig()
	cfg.Proxy.MaxConnections = 0
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "max_connections") {
		t.Errorf("expected max_connections error, got: %v", err)
	}
}

func TestValidate_InvalidDial(t *testing.T) {
	cfg := makeValidConfig()
	cfg.MonitorMode.Dial = 200
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "dial") {
		t.Errorf("expected dial error, got: %v", err)
	}
}

func TestValidate_InvalidRedisTimeout(t *testing.T) {
	cfg := makeValidConfig()
	cfg.Redis.Timeout = FlexInt(0)
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "redis timeout") {
		t.Errorf("expected redis timeout error, got: %v", err)
	}
}

func TestValidate_RiskScorerThresholdsOutOfRange(t *testing.T) {
	cfg := makeValidConfig()
	cfg.RiskScorer.Thresholds.Block = 150
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "block") {
		t.Errorf("expected block threshold error, got: %v", err)
	}
}

func TestValidate_RiskScorerThresholdsNotMonotonic(t *testing.T) {
	cfg := makeValidConfig()
	cfg.RiskScorer.Thresholds.Flag = 50
	cfg.RiskScorer.Thresholds.RateLimit = 30 // flag > rate_limit → non-monotonic
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "non-decreasing") {
		t.Errorf("expected non-decreasing error, got: %v", err)
	}
}

func TestValidate_BlocklistFeedMissingName(t *testing.T) {
	cfg := makeValidConfig()
	cfg.Blocklists.Feeds = append(cfg.Blocklists.Feeds, BlocklistFeedConfigYAML{
		Enabled: true,
		Name:    "",
	})
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "missing name") {
		t.Errorf("expected missing feed name error, got: %v", err)
	}
}

func TestCheckRedisACLStatus_Enabled(t *testing.T) {
	cfg := makeValidConfig()
	cfg.Redis.ACLUsers.Enabled = true
	status := CheckRedisACLStatus(cfg)
	if status != RedisACLEnabled {
		t.Errorf("ACLUsers.Enabled=true: got %v, want %v", status, RedisACLEnabled)
	}
}

func TestCheckRedisACLStatus_DisabledLocal(t *testing.T) {
	cfg := makeValidConfig()
	cfg.Redis.ACLUsers.Enabled = false
	cfg.Redis.Host = "127.0.0.1"
	status := CheckRedisACLStatus(cfg)
	if status != RedisACLDisabledLocal {
		t.Errorf("local host: got %v, want %v", status, RedisACLDisabledLocal)
	}
}

func TestCheckRedisACLStatus_DisabledRemote(t *testing.T) {
	cfg := makeValidConfig()
	cfg.Redis.ACLUsers.Enabled = false
	cfg.Redis.Host = "redis.example.com"
	status := CheckRedisACLStatus(cfg)
	if status != RedisACLDisabledRemote {
		t.Errorf("remote host: got %v, want %v", status, RedisACLDisabledRemote)
	}
}

func TestCheckRedisACLStatus_Nil(t *testing.T) {
	status := CheckRedisACLStatus(nil)
	if status != RedisACLEnabled {
		t.Errorf("nil cfg: got %v, want %v", status, RedisACLEnabled)
	}
}

func TestCheckRedisACLStatus_SentinelFallback(t *testing.T) {
	cfg := makeValidConfig()
	cfg.Redis.ACLUsers.Enabled = false
	cfg.Redis.Host = ""
	cfg.Redis.Sentinels = []string{"127.0.0.1:26379"}
	status := CheckRedisACLStatus(cfg)
	if status != RedisACLDisabledLocal {
		t.Errorf("sentinel localhost: got %v, want %v", status, RedisACLDisabledLocal)
	}
}

func TestRedisACLStatusString(t *testing.T) {
	cases := []struct {
		status RedisACLStatus
		want   string
	}{
		{RedisACLEnabled, "enabled"},
		{RedisACLDisabledLocal, "disabled_local"},
		{RedisACLDisabledRemote, "disabled_remote"},
		{RedisACLStatus(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.status.String(); got != c.want {
			t.Errorf("String(%d) = %q, want %q", c.status, got, c.want)
		}
	}
}

func TestProtocolLockdownEnabled(t *testing.T) {
	var sec SecurityConfig

	// nil pointer → defaults to true
	if !sec.ProtocolLockdownEnabled() {
		t.Error("nil EnforceTLSRecord should default to true")
	}

	// explicit false
	f := false
	sec.EnforceTLSRecord = &f
	if sec.ProtocolLockdownEnabled() {
		t.Error("EnforceTLSRecord=false should return false")
	}

	// explicit true
	tr := true
	sec.EnforceTLSRecord = &tr
	if !sec.ProtocolLockdownEnabled() {
		t.Error("EnforceTLSRecord=true should return true")
	}
}

func TestValidate_RateLimiterInvalidBan(t *testing.T) {
	cfg := makeValidConfig()
	cfg.RateLimiter.ByIP.Enabled = true
	cfg.RateLimiter.ByIP.Ban = 0 // invalid: must be > 0
	cfg.RateLimiter.ByIP.Block = 10
	cfg.RateLimiter.ByIP.Suspicious = 5
	cfg.RateLimiter.ByIP.TTL = 60
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ban") {
		t.Errorf("expected rate_limiter ban error, got: %v", err)
	}
}

