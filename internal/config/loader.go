// Package config provides configuration loading for the JA4proxy Go proxy.
// It reads the same proxy.yml schema used by the Python proxy and supports
// ${VAR:-default} environment variable expansion.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// FlexInt is an int that can be unmarshaled from either a YAML integer or a YAML string
// containing a decimal integer. This is needed because env-var expansion converts
// port numbers (e.g. "${BACKEND_PORT:-443}") into quoted strings in YAML.
type FlexInt int

// Int returns the FlexInt as a plain int.
func (f FlexInt) Int() int { return int(f) }

// UnmarshalYAML implements yaml.Unmarshaler for FlexInt.
func (f *FlexInt) UnmarshalYAML(value *yaml.Node) error {
	// Try as int first (normal YAML integer node)
	var i int
	if err := value.Decode(&i); err == nil {
		*f = FlexInt(i)
		return nil
	}
	// Try as string containing a decimal integer
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("FlexInt: cannot unmarshal %q", value.Value)
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("FlexInt: %q is not an integer", s)
	}
	*f = FlexInt(n)
	return nil
}

// envVarPattern matches ${VAR} and ${VAR:-default} substitution syntax.
var envVarPattern = regexp.MustCompile(`\$\{([^}:]+)(?::-([^}]*))?\}`)

// Load reads proxy.yml from path, expands environment variables, and returns
// a Config. Unknown YAML keys are silently ignored (they are logged at DEBUG
// level when a logger is wired in — not done here to keep the package lean).
//
// Fails open: missing keys return Go zero values / struct defaults.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}

	// Expand ${VAR:-default} before parsing so the YAML parser sees real values.
	expanded := expandEnvVars(string(raw))

	cfg := defaultConfig()
	if strings.TrimSpace(expanded) == "" {
		// Empty config file — return defaults
		return cfg, nil
	}
	decoder := yaml.NewDecoder(strings.NewReader(expanded))
	decoder.KnownFields(false) // unknown keys are ignored, not an error
	if err := decoder.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			// Empty document after expansion — return defaults
			return cfg, nil
		}
		return nil, fmt.Errorf("config: parse %q: %w", path, err)
	}
	return cfg, nil
}

// expandEnvVars replaces ${VAR} and ${VAR:-default} in s with the corresponding
// environment variable value (or the default if the variable is unset/empty).
func expandEnvVars(s string) string {
	return envVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		sub := envVarPattern.FindStringSubmatch(match)
		if sub == nil {
			return match
		}
		varName := sub[1]
		defaultVal := sub[2]
		if val, ok := os.LookupEnv(varName); ok && val != "" {
			return val
		}
		return defaultVal
	})
}

// defaultConfig returns a Config with conservative defaults matching proxy.yml.
func defaultConfig() *Config {
	return &Config{
		Proxy: ProxyConfig{
			BindHost:            "0.0.0.0",
			BindPort:            FlexInt(8080),
			BackendHost:         "backend",
			BackendPort:         FlexInt(443),
			TarpitHost:          "tarpit",
			TarpitPort:          FlexInt(8888),
			MaxConnections:      1000,
			DrainTimeoutSeconds: 30,
			ConnectionTimeout:   30,
			ReadTimeout:         30,
			WriteTimeout:        30,
			ProxyProtocol:       true,
			BufferSize:          8192,
		},
		Redis: RedisConfig{
			Host:    "redis",
			Port:    6379,
			DB:      0,
			Timeout: 5,
			SSL:     false,
		},
		Security: SecurityConfig{
			WhitelistEnabled: true,
			BlacklistEnabled: true,
			RateLimiting:     true,
			TarpitEnabled:    true,
			BanDuration:      604800,
		},
		MonitorMode: MonitorModeConfig{
			Dial:                 0,
			BlockingAcknowledged: false,
			MaxDialChangePerHour: 25,
		},
		RiskScorer: RiskScorerConfig{
			Thresholds: ThresholdsConfig{
				Flag:      20,
				RateLimit: 35,
				Tarpit:    55,
				Block:     70,
				Ban:       85,
			},
		},
		SecurityPolicy: SecurityPolicyConfig{
			ALPNBrowserBypass:      BypassConfig{Enabled: true},
			JA4WhitelistBypass:     BypassConfig{Enabled: true},
			JA4BlacklistBypass:     BypassConfig{Enabled: true},
			MTLSBypass:             BypassConfig{Enabled: true},
			StaticIPAllowlist:      BypassConfig{Enabled: true},
			CountryBlacklistBypass: BypassConfig{Enabled: true},
			SpamhausBypass:         BypassConfig{Enabled: true},
			TLSVersionBypass:       BypassConfig{Enabled: true},
		},
		Logging: LoggingConfig{
			Level:       "INFO",
			JSONEnabled: false,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Port:    9090,
		},
		Tarpit: TarpitConfig{
			MaxConcurrentConnections: 500,
			MaxPerIP:                 3,
			OverflowAction:           "block",
		},
	}
}

// ── Config struct hierarchy ───────────────────────────────────────────────

// Config is the top-level configuration structure. Field names match proxy.yml.
type Config struct {
	Proxy          ProxyConfig          `yaml:"proxy"`
	Redis          RedisConfig          `yaml:"redis"`
	Security       SecurityConfig       `yaml:"security"`
	MonitorMode    MonitorModeConfig    `yaml:"monitor_mode"`
	SecurityPolicy SecurityPolicyConfig `yaml:"security_policy"`
	RiskScorer     RiskScorerConfig     `yaml:"risk_scorer"`
	Logging        LoggingConfig        `yaml:"logging"`
	Metrics        MetricsConfig        `yaml:"metrics"`
	Tarpit         TarpitConfig         `yaml:"tarpit"`
	TLSEnforcer    TLSEnforcerConfigYAML `yaml:"tls_enforcer"`
	SNIAnalyzer    SNIAnalyzerConfigYAML `yaml:"sni_analyzer"`
	GeoIP          GeoIPConfigYAML       `yaml:"geoip"`
}

// ProxyConfig holds network listener and connection settings.
// BackendPort and BackendHost use FlexInt/FlexString to handle env var expansion
// which can produce quoted strings in YAML (e.g. "${BACKEND_PORT:-443}" → "443").
type ProxyConfig struct {
	BindHost            string  `yaml:"bind_host"`
	BindPort            FlexInt `yaml:"bind_port"`
	BackendHost         string  `yaml:"backend_host"`
	BackendPort         FlexInt `yaml:"backend_port"`
	TarpitHost          string  `yaml:"tarpit_host"`
	TarpitPort          FlexInt `yaml:"tarpit_port"`
	MaxConnections      int     `yaml:"max_connections"`
	DrainTimeoutSeconds int     `yaml:"drain_timeout_seconds"`
	ConnectionTimeout   int     `yaml:"connection_timeout"`
	ReadTimeout         int     `yaml:"read_timeout"`
	WriteTimeout        int     `yaml:"write_timeout"`
	ProxyProtocol       bool    `yaml:"proxy_protocol"`
	BufferSize          int     `yaml:"buffer_size"`
}

// RedisConfig holds Redis connection settings.
type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	DB       int    `yaml:"db"`
	Password string `yaml:"password"`
	Timeout  int    `yaml:"timeout"`
	SSL      bool   `yaml:"ssl"`
}

// SecurityConfig holds security-related settings including JA4 lists.
type SecurityConfig struct {
	WhitelistEnabled bool     `yaml:"whitelist_enabled"`
	BlacklistEnabled bool     `yaml:"blacklist_enabled"`
	RateLimiting     bool     `yaml:"rate_limiting"`
	TarpitEnabled    bool     `yaml:"tarpit_enabled"`
	BanDuration      int      `yaml:"ban_duration"`
	Whitelist        []string `yaml:"whitelist"`
	WhitelistPatterns []string `yaml:"whitelist_patterns"`
	Blacklist        []string `yaml:"blacklist"`
}

// MonitorModeConfig holds dial and monitor mode settings.
type MonitorModeConfig struct {
	Dial                 int  `yaml:"dial"`
	BlockingAcknowledged bool `yaml:"blocking_acknowledged"`
	MaxDialChangePerHour int  `yaml:"max_dial_change_per_hour"`
}

// SecurityPolicyConfig holds per-bypass toggle settings.
type SecurityPolicyConfig struct {
	ALPNBrowserBypass      BypassConfig `yaml:"alpn_browser_bypass"`
	JA4WhitelistBypass     BypassConfig `yaml:"ja4_whitelist_bypass"`
	JA4BlacklistBypass     BypassConfig `yaml:"ja4_blacklist_bypass"`
	MTLSBypass             BypassConfig `yaml:"mtls_bypass"`
	StaticIPAllowlist      BypassConfig `yaml:"static_ip_allowlist"`
	CountryBlacklistBypass BypassConfig `yaml:"country_blacklist_bypass"`
	SpamhausBypass         BypassConfig `yaml:"spamhaus_bypass"`
	TLSVersionBypass       BypassConfig `yaml:"tls_version_bypass"`
}

// BypassConfig holds the enabled toggle for a single bypass rule.
type BypassConfig struct {
	Enabled bool `yaml:"enabled"`
}

// RiskScorerConfig holds scoring threshold settings.
type RiskScorerConfig struct {
	Thresholds ThresholdsConfig `yaml:"thresholds"`
}

// ThresholdsConfig holds the action thresholds.
type ThresholdsConfig struct {
	Flag      int `yaml:"flag"`
	RateLimit int `yaml:"rate_limit"`
	Tarpit    int `yaml:"tarpit"`
	Block     int `yaml:"block"`
	Ban       int `yaml:"ban"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level       string `yaml:"level"`
	JSONEnabled bool   `yaml:"json_enabled"`
}

// MetricsConfig holds Prometheus metrics settings.
type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

// TarpitConfig holds tarpit self-protection settings.
type TarpitConfig struct {
	MaxConcurrentConnections int    `yaml:"max_concurrent_connections"`
	MaxPerIP                 int    `yaml:"max_per_ip"`
	OverflowAction           string `yaml:"overflow_action"`
}

// TLSEnforcerConfigYAML holds TLS enforcement settings from proxy.yml.
type TLSEnforcerConfigYAML struct {
	BlockTLS10       bool `yaml:"block_tls_10"`
	BlockTLS11       bool `yaml:"block_tls_11"`
	FlagTLS12        bool `yaml:"flag_tls_12"`
	BlockWeakCiphers bool `yaml:"block_weak_ciphers"`
}

// SNIAnalyzerConfigYAML holds SNI analysis settings from proxy.yml.
type SNIAnalyzerConfigYAML struct {
	MissingSNI struct {
		Enabled bool `yaml:"enabled"`
		Score   int  `yaml:"score"`
	} `yaml:"missing_sni"`
	IPLiteralSNI struct {
		Enabled bool `yaml:"enabled"`
		Score   int  `yaml:"score"`
	} `yaml:"ip_literal_sni"`
	DGADetection struct {
		Enabled  bool `yaml:"enabled"`
		ScoreCap int  `yaml:"score_cap"`
	} `yaml:"dga_detection"`
	UnexpectedSNI struct {
		Enabled bool `yaml:"enabled"`
		Score   int  `yaml:"score"`
	} `yaml:"unexpected_sni"`
	ExpectedHostnames []string `yaml:"expected_hostnames"`
}

// GeoIPConfigYAML holds GeoIP database settings from proxy.yml.
type GeoIPConfigYAML struct {
	DBPath    string `yaml:"db_path"`
	ASNDBPath string `yaml:"asn_db_path"`
}
