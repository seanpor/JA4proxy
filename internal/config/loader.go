// Package config provides configuration loading for the JA4proxy Go proxy.
// It reads the same proxy.yml schema used by the Python proxy and supports
// ${VAR:-default} environment variable expansion.
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
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
	raw, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}

	// Expand ${VAR:-default} before parsing so the YAML parser sees real values.
	expanded := expandEnvVars(string(raw))

	cfg := DefaultConfig()
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

// DefaultConfig returns a Config with conservative defaults matching proxy.yml.
// Exported for use in tests (Phase 200a).
func DefaultConfig() *Config {
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
			// phase-231a: off by default (fail-open); v1 if enabled without a version.
			WriteProxyProtocol:        false,
			WriteProxyProtocolVersion: 1,
			StreamMaxLen:              100000,
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
			// JA4PROXY-2026-0004: ALPN is attacker-controlled. Default OFF.
			ALPNBrowserBypass:      BypassConfig{Enabled: false},
			JA4WhitelistBypass:     BypassConfig{Enabled: true},
			JA4BlockingEnabled:     BypassConfig{Enabled: true},
			MTLSBypass:             BypassConfig{Enabled: true},
			StaticIPAllowlist:      BypassConfig{Enabled: true},
			CountryBlockingEnabled: BypassConfig{Enabled: true},
			SpamhausBypass:         BypassConfig{Enabled: true},
			TLSVersionBypass:       BypassConfig{Enabled: true},
		},
		Logging: LoggingConfig{
			Level:       "INFO",
			JSONEnabled: false,
			Format:      "legacy",
		},
		Metrics: MetricsConfig{
			Enabled:        true,
			Port:           9090,
			BindHost:       "127.0.0.1",
			RateLimitRPS:   20,
			RateLimitBurst: 40,
		},
		Monitoring: MonitoringConfig{
			Enabled:                 false,
			NTPCheckIntervalSeconds: 60,
			MaxDriftSeconds:         0.05,
		},
		Sync: SyncAgentConfig{
			DCID:                 "dc-a",
			ListenAddr:           ":7379",
			RPCListenAddr:        ":7380",
			BufferMaxLen:         50000,
			InboundConsumerGroup: "sync-group",
		},
		Tarpit: TarpitConfig{
			MaxActiveConnections:     500,
			MaxPerIP:                 3,
			OverflowAction:           "block",
			InactivityTimeoutSeconds: 60,
			MaxLifetimeSeconds:       300,
		},
		ASNClassifier: ASNClassifierConfigYAML{
			Enabled:            true,
			DatacenterListPath: "config/asn_datacenter_list.yml",
			MaxMindDBPath:      "config/GeoLite2-ASN.mmdb",
			TorExitList: struct {
				Enabled                bool   `yaml:"enabled"`
				RefreshIntervalSeconds int    `yaml:"refresh_interval_seconds"`
				DownloadURL            string `yaml:"download_url"`
			}{
				Enabled:                true,
				RefreshIntervalSeconds: 3600,
				DownloadURL:            "https://check.torproject.org/tor-exit-consensus",
			},
			RiskContributions: struct {
				Tor         int `yaml:"tor"`
				Datacenter  int `yaml:"datacenter"`
				VPN         int `yaml:"vpn"`
				Unknown     int `yaml:"unknown"`
				Residential int `yaml:"residential"`
				Mobile      int `yaml:"mobile"`
			}{
				Tor:         40,
				Datacenter:  20,
				VPN:         10,
				Unknown:     5,
				Residential: 0,
				Mobile:      0,
			},
		},
		DNSEnrichment: DNSEnrichmentConfigYAML{
			Enabled:                true,
			QueueSize:              1000,
			WorkerCount:            5,
			TTLSeconds:             86400,
			ResolverTimeoutSeconds: 5,
			FCrDNS: struct {
				Enabled                   bool `yaml:"enabled"`
				NoPTRScore                int  `yaml:"no_ptr_score"`
				FCrDNSFailedScore         int  `yaml:"fcrdns_failed_score"`
				ResidentialScoreReduction int  `yaml:"residential_score_reduction"`
			}{
				Enabled:                   true,
				NoPTRScore:                15,
				FCrDNSFailedScore:         20,
				ResidentialScoreReduction: 10,
			},
		},
		Beaconing: BeaconingConfigYAML{
			Enabled:                  true,
			MinObservations:          8,
			WindowSize:               20,
			ObservationWindowSeconds: 3600,
			Score:                    35,
			LongWindow: struct {
				Enabled       bool `yaml:"enabled"`
				WindowSeconds int  `yaml:"window_seconds"`
				Score         int  `yaml:"score"`
			}{
				Enabled:       true,
				WindowSeconds: 86400,
				Score:         20,
			},
		},
		AbuseIPDB: AbuseIPDBConfigYAML{
			Enabled:           false,
			APIURL:            "https://api.abuseipdb.com/api/v2/check",
			CacheTTLSeconds:   14400,
			SharedIPThreshold: 50,
			QueueSize:         500,
			WorkerCount:       3,
			ScoreCap:          40,
		},
		RDAPEnrichment: RDAPConfigYAML{
			Enabled:          true,
			QueueSize:        500,
			WorkerCount:      3,
			MinEnqueueScore:  20,
			KnownBadOrgsPath: "config/known_bad_orgs.yml",
			OrgReputation: struct {
				Enabled bool `yaml:"enabled"`
				Score   int  `yaml:"score"`
			}{
				Enabled: true,
				Score:   45,
			},
			NewNetblockFlagging: struct {
				Enabled    bool `yaml:"enabled"`
				MaxAgeDays int  `yaml:"max_age_days"`
				Score      int  `yaml:"score"`
			}{
				Enabled:    true,
				MaxAgeDays: 90,
				Score:      20,
			},
			BlockExpansion: struct {
				Enabled bool `yaml:"enabled"`
			}{
				Enabled: false,
			},
		},
		Fingerprinting: FingerprintingConfigYAML{
			JA4X: struct {
				Enabled        bool `yaml:"enabled"`
				BlacklistScore int  `yaml:"blacklist_score"`
			}{
				Enabled:        true,
				BlacklistScore: 80,
			},
		},
		TCPAnalyzer: TCPAnalyzerConfigYAML{
			Enabled:                       true,
			SessionResumptionEnabled:      true,
			MinConnectionsForSessionCheck: 10,
			ShortLifespanEnabled:          true,
			ShortLifespanThresholdMS:      500,
			ConcurrencyEnabled:            true,
			ConcurrencyModerate:           20,
			ConcurrencyHigh:               50,
			ConcurrencySevere:             100,
			ReturnVisitorEnabled:          true,
			ReturnVisitorMinDays:          7,
			ReturnVisitorMinAllowRate:     0.90,
		},
		StaticAllowlist: StaticAllowlistConfigYAML{
			Enabled: true,
			IPs:     []StaticIPConfigYAML{},
		},
		Webhooks: WebhooksConfig{
			Enabled:                   false,
			StreamKey:                 "events:connection",
			DLQKey:                    "webhooks:dlq",
			Endpoints:                 []WebhookEndpointConfig{},
			StreamQueueCapacity:       4096,
			StreamWorkers:             4,
			StreamWriteTimeoutSeconds: 2.0,
		},
		AutoEscalate: AutoEscalateConfig{
			Enabled:               false,
			TarpitAtOffense:       1,
			BlockAtOffense:        3,
			BanAtOffense:          5,
			BanHours:              24,
			OffenseTTLHours:       48,
			SharedIPCIDRThreshold: 10,
		},
	}
}

// ── Config struct hierarchy ───────────────────────────────────────────────

// Config is the top-level configuration structure. Field names match proxy.yml.
type Config struct {
	Proxy                  ProxyConfig                  `yaml:"proxy"`
	Redis                  RedisConfig                  `yaml:"redis"`
	Security               SecurityConfig               `yaml:"security"`
	MonitorMode            MonitorModeConfig            `yaml:"monitor_mode"`
	SecurityPolicy         SecurityPolicyConfig         `yaml:"security_policy"`
	RiskScorer             RiskScorerConfig             `yaml:"risk_scorer"`
	Logging                LoggingConfig                `yaml:"logging"`
	Metrics                MetricsConfig                `yaml:"metrics"`
	Tarpit                 TarpitConfig                 `yaml:"tarpit"`
	TLSEnforcer            TLSEnforcerConfigYAML        `yaml:"tls_enforcer"`
	SNIAnalyzer            SNIAnalyzerConfigYAML        `yaml:"sni_analyzer"`
	GeoIP                  GeoIPConfigYAML              `yaml:"geoip"`
	TCPAnalyzer            TCPAnalyzerConfigYAML        `yaml:"tcp_analyzer"`
	RateLimiter            RateLimiterConfigYAML        `yaml:"rate_limiter"`
	ASNClassifier          ASNClassifierConfigYAML      `yaml:"asn_classifier"`
	DNSEnrichment          DNSEnrichmentConfigYAML      `yaml:"dns_enrichment"`
	Blocklists             BlocklistsConfigYAML         `yaml:"blocklists"`
	Beaconing              BeaconingConfigYAML          `yaml:"beaconing_detector"`
	AbuseIPDB              AbuseIPDBConfigYAML          `yaml:"abuseipdb"`
	RDAPEnrichment         RDAPConfigYAML               `yaml:"rdap_enrichment"`
	Fingerprinting         FingerprintingConfigYAML     `yaml:"fingerprinting"`
	StaticAllowlist        StaticAllowlistConfigYAML    `yaml:"static_allowlist"`
	Webhooks               WebhooksConfig               `yaml:"webhooks"`                 // phase-80
	Monitoring             MonitoringConfig             `yaml:"monitoring"`               // phase-88
	Sync                   SyncAgentConfig              `yaml:"sync"`                     // phase-88
	TrustedUpstreamSources TrustedUpstreamSourcesConfig `yaml:"trusted_upstream_sources"` // phase-94i2
	TapConsumer            TapConsumerConfigYAML        `yaml:"tap_consumer"`             // phase-203a
	JA4TConsumer           JA4TConsumerConfigYAML       `yaml:"ja4t_consumer"`            // phase-316c
	AutoEscalate           AutoEscalateConfig           `yaml:"auto_escalate"`            // phase-248
}

// AutoEscalateConfig configures auto-escalating IP defense (Phase 248).
// Off by default. Enabled by setting auto_escalate.enabled: true in proxy.yml,
// or by Attack Mode activation (which sets attack_mode:escalate in Redis).
type AutoEscalateConfig struct {
	Enabled               bool `yaml:"enabled"`
	TarpitAtOffense       int  `yaml:"tarpit_at_offense"`
	BlockAtOffense        int  `yaml:"block_at_offense"`
	BanAtOffense          int  `yaml:"ban_at_offense"`
	BanHours              int  `yaml:"ban_hours"`
	OffenseTTLHours       int  `yaml:"offense_ttl_hours"`
	SharedIPCIDRThreshold int  `yaml:"shared_ip_cidr_threshold"`
}

// TapConsumerConfigYAML configures the phase-203a TAP JA4T OS-mismatch consumer.
// Default: disabled. Requires Phase 20 TAP node to be deployed.
type TapConsumerConfigYAML struct {
	Enabled         bool `yaml:"enabled"`
	SignalScore     int  `yaml:"signal_score"`
	RedisTimeoutMs  int  `yaml:"redis_timeout_ms"`
	CacheTTLSeconds int  `yaml:"cache_ttl_seconds"`
	MaxAgeSeconds   int  `yaml:"max_age_seconds"`
}

// JA4TConsumerConfigYAML configures the phase-316c TAP JA4T blocklist consumer.
// Default: disabled with an empty blocklist (silent). Requires the Go TAP sensor
// (Phase 316a/c) to be deployed writing fp:ja4t:ip:{ip}.
type JA4TConsumerConfigYAML struct {
	Enabled         bool     `yaml:"enabled"`
	SignalScore     int      `yaml:"signal_score"`
	RedisTimeoutMs  int      `yaml:"redis_timeout_ms"`
	CacheTTLSeconds int      `yaml:"cache_ttl_seconds"`
	Blocklist       []string `yaml:"blocklist"`
}

// MonitoringConfig holds multi-DC observability settings.
type MonitoringConfig struct {
	Enabled                 bool    `yaml:"enabled"`
	NTPCheckIntervalSeconds int     `yaml:"ntp_check_interval_seconds"`
	MaxDriftSeconds         float64 `yaml:"max_drift_seconds"`
}

// SyncAgentConfig holds cross-DC replication settings.
type SyncAgentConfig struct {
	DCID                 string   `yaml:"dc_id"`
	ListenAddr           string   `yaml:"listen_addr"`
	RPCListenAddr        string   `yaml:"rpc_listen_addr"`
	RemotePeers          []string `yaml:"remote_peers"`
	BufferMaxLen         int      `yaml:"buffer_maxlen"`
	InboundConsumerGroup string   `yaml:"inbound_consumer_group"`
	CertFile             string   `yaml:"cert_file"`
	KeyFile              string   `yaml:"key_file"`
	CAFile               string   `yaml:"ca_file"`
	IntegrityKeyFile     string   `yaml:"integrity_key_file"`
	IntegrityPubFile     string   `yaml:"integrity_pub_file"`
}

// UpstreamTrustConfig holds PROXY protocol trust settings (Phase 200a).
type UpstreamTrustConfig struct {
	Enabled      bool     `yaml:"enabled"`
	TrustedCIDRs []string `yaml:"trusted_cidrs"`
}

// TrustedUpstreamSourcesConfig holds dynamic trusted-upstream provider settings (phase-94i2).
type TrustedUpstreamSourcesConfig struct {
	NetBox      NetBoxSourceConfig `yaml:"netbox"`
	StaticCIDRs []string           `yaml:"static_cidrs"`
}

// NetBoxSourceConfig holds NetBox IPAM integration settings (phase-94i2).
type NetBoxSourceConfig struct {
	Enabled         bool   `yaml:"enabled"`
	URL             string `yaml:"url"`
	Token           string `yaml:"token"`
	Tag             string `yaml:"tag"`
	RefreshOnSIGHUP bool   `yaml:"refresh_on_sighup"`
}

// ProxyConfig holds network listener and connection settings.
// BackendPort and BackendHost use FlexInt/FlexString to handle env var expansion
// which can produce quoted strings in YAML (e.g. "${BACKEND_PORT:-443}" → "443").
type ProxyConfig struct {
	BindHost            string              `yaml:"bind_host"`
	BindPort            FlexInt             `yaml:"bind_port"`
	BackendHost         string              `yaml:"backend_host"`
	BackendPort         FlexInt             `yaml:"backend_port"`
	TarpitHost          string              `yaml:"tarpit_host"`
	TarpitPort          FlexInt             `yaml:"tarpit_port"`
	MaxConnections      int                 `yaml:"max_connections"`
	DrainTimeoutSeconds int                 `yaml:"drain_timeout_seconds"`
	ConnectionTimeout   int                 `yaml:"connection_timeout"`
	ReadTimeout         int                 `yaml:"read_timeout"`
	WriteTimeout        int                 `yaml:"write_timeout"`
	ProxyProtocol       bool                `yaml:"proxy_protocol"`
	BufferSize          int                 `yaml:"buffer_size"`
	UpstreamTrust       UpstreamTrustConfig `yaml:"upstream_trust"`
	// phase-231a: write a PROXY protocol header to the backend so a passthrough
	// deployment preserves the real client IP without TLS decryption. Off by
	// default; a config missing these fields loads with the safe defaults.
	WriteProxyProtocol        bool  `yaml:"write_proxy_protocol"`
	WriteProxyProtocolVersion int   `yaml:"write_proxy_protocol_version"`
	StreamMaxLen              int64 `yaml:"stream_max_len"`
}

// RedisConfig holds Redis connection settings.
type RedisConfig struct {
	Host       string   `yaml:"host"`
	Port       FlexInt  `yaml:"port"`
	MasterName string   `yaml:"master_name"`
	Sentinels  []string `yaml:"sentinels"`
	DB         int      `yaml:"db"`
	Password   string   `yaml:"password"`
	Username   string   `yaml:"username"`
	Timeout    FlexInt  `yaml:"timeout"`
	SSL        bool     `yaml:"ssl"`
	// JA4PROXY-2026-0019 — HMAC-SHA256 secret for authenticating Redis
	// pub/sub messages on security-critical channels (dial change, JA4
	// whitelist/blacklist mutations, RDAP CIDR bans). When set, the Go
	// subscriber refuses any message on a critical channel that is not
	// signed with this secret. When empty, all messages are accepted —
	// operators are warned at startup. Must match the Python publisher.
	PubSubHMACSecret string `yaml:"pubsub_hmac_secret"`

	// JA4PROXY-2026-0050 — per-service Redis ACL users. When Enabled is
	// false (the historical default), the proxy connects as the "default"
	// user which in a stock Redis install has `+@all ~*` — the exact
	// authority required to rewrite ban lists, whitelists, the dial, and
	// anything else. Leaving the default user unrestricted turns a stolen
	// Redis password (or a process compromise) into full write access to
	// security state. We do NOT flip the default to true because that would
	// break every existing deployment that has not run
	// scripts/redis-acl-setup.sh, but we DO refuse to silently accept a
	// remote unauthenticated-by-ACL Redis: ValidateRedisACL emits a loud
	// startup WARN and sets the ja4proxy_redis_acl_enabled gauge to 0 so
	// dashboards can alert on it.
	ACLUsers ACLUsersConfig `yaml:"acl_users"`
}

// ACLUsersConfig configures per-service Redis ACL usernames. See
// scripts/redis-acl-setup.sh for the matching Redis-side commands.
// JA4PROXY-2026-0050.
type ACLUsersConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ProxyUser     string `yaml:"proxy_user"`
	AnalyticsUser string `yaml:"analytics_user"`
}

// SecurityConfig holds security-related settings including JA4 lists.
type SecurityConfig struct {
	WhitelistEnabled  bool     `yaml:"whitelist_enabled"`
	BlacklistEnabled  bool     `yaml:"blacklist_enabled"`
	RateLimiting      bool     `yaml:"rate_limiting"`
	TarpitEnabled     bool     `yaml:"tarpit_enabled"`
	BanDuration       int      `yaml:"ban_duration"`
	Whitelist         []string `yaml:"whitelist"`
	WhitelistPatterns []string `yaml:"whitelist_patterns"`
	Blacklist         []string `yaml:"blacklist"`
	// JA4PROXY-2026-0011 — TLS protocol lockdown. When true (default), any
	// connection whose first byte after PROXY-header strip is not 0x16
	// (TLS Handshake content type) is dropped immediately. Blocks HTTP
	// smuggling, SSH injection, and subsequent PROXY-header smuggling on
	// what is supposed to be a TLS-aware passthrough listener. Operators
	// who intentionally proxy non-TLS protocols on the listen port can
	// set this to false to preserve the pre-fix scoring-only behavior.
	EnforceTLSRecord *bool `yaml:"enforce_tls_record"`
}

// ProtocolLockdownEnabled reports whether TLS protocol lockdown should be
// enforced on the connection hot path. Centralised here so the default
// (true) lives next to the field docs, and so callers do not scatter
// "if sec.EnforceTLSRecord == nil || *sec.EnforceTLSRecord" across the
// codebase. JA4PROXY-2026-0011.
func (s SecurityConfig) ProtocolLockdownEnabled() bool {
	if s.EnforceTLSRecord == nil {
		return true
	}
	return *s.EnforceTLSRecord
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
	JA4BlockingEnabled     BypassConfig `yaml:"ja4_blocking_enabled"`
	MTLSBypass             BypassConfig `yaml:"mtls_bypass"`
	StaticIPAllowlist      BypassConfig `yaml:"static_ip_allowlist"`
	CountryBlockingEnabled BypassConfig `yaml:"country_blocking_enabled"`
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
	// Format controls the log output format: "legacy" (default) or "ecs".
	// "ecs" emits ECS 8.x-compliant JSON for SIEM ingestion.
	Format string `yaml:"format"` // phase-80
	// DualOutput, when true and Format is "ecs", emits both legacy and ECS
	// JSON lines per log entry — useful during SIEM dashboard migration.
	// Python-only feature; Go logs a warning and uses ECS-only.
	DualOutput bool `yaml:"dual_output"` // phase-80
}

// MetricsConfig holds Prometheus metrics settings.
//
// BindHost controls the interface the metrics HTTP server listens on.
// The secure default is "127.0.0.1" (loopback only): operators who want
// remote scraping must set it explicitly AND supply an AuthToken.
// JA4PROXY-2026-0008 — a 0.0.0.0 bind with no auth exposes ban rates,
// dial setting, cert expiry and the full Prometheus scrape to anyone on
// the network, which is reconnaissance-grade intelligence.
type MetricsConfig struct {
	Enabled   bool    `yaml:"enabled"`
	Port      FlexInt `yaml:"port"`
	BindHost  string  `yaml:"bind_host"`
	AuthToken string  `yaml:"auth_token"`
	// RateLimitRPS caps requests-per-second across all observability endpoints
	// (/metrics, /health, /health/deep, /metrics/summary) per remote IP. 0
	// disables the limiter. JA4PROXY-2026-0026 — without this an attacker (or
	// a misbehaving scraper) can spam the endpoints to flood logs, churn
	// Redis pings, and recycle Prometheus scrape state. Loopback is exempted
	// so co-located Prometheus sidecars are never throttled.
	RateLimitRPS float64 `yaml:"rate_limit_rps"`
	// RateLimitBurst is the token-bucket burst size; a short spike up to this
	// size is allowed before the RPS cap kicks in. 0 means use 2×RateLimitRPS.
	RateLimitBurst int `yaml:"rate_limit_burst"`
}

// TarpitConfig holds tarpit self-protection settings.
type TarpitConfig struct {
	MaxActiveConnections int    `yaml:"max_concurrent_connections"`
	MaxPerIP             int    `yaml:"max_per_ip"`
	OverflowAction       string `yaml:"overflow_action"`
	// InactivityTimeoutSeconds bounds how long a tarpit copy loop will block
	// in Read() with no data. Defaults to 60s. JA4PROXY-2026-0013: without
	// this bound an attacker can send one byte and hang forever, pinning a
	// tarpit slot and eventually exhausting the pool.
	InactivityTimeoutSeconds int `yaml:"inactivity_timeout_seconds"`
	// MaxLifetimeSeconds is the hard cap on total tarpit-hold duration.
	// Even an actively-trickling client is dropped after this many seconds.
	// Defaults to 300s.
	MaxLifetimeSeconds int `yaml:"max_lifetime_seconds"`
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
	MaliciousSNI struct {
		Enabled bool `yaml:"enabled"`
		Score   int  `yaml:"score"`
	} `yaml:"malicious_sni"`
	ExpectedHostnames []string `yaml:"expected_hostnames"`
}

// GeoIPConfigYAML holds GeoIP database settings from proxy.yml.
type GeoIPConfigYAML struct {
	DBPath                  string   `yaml:"database_path"`
	ASNDBPath               string   `yaml:"asn_db_path"`
	CountryWhitelistEnabled bool     `yaml:"country_whitelist_enabled"`
	CountryWhitelist        []string `yaml:"country_whitelist"`
	CountryBlacklistEnabled bool     `yaml:"country_blacklist_enabled"`
	CountryBlacklist        []string `yaml:"country_blacklist"`
}

// TCPAnalyzerConfigYAML holds TCP analyzer settings from proxy.yml.
type TCPAnalyzerConfigYAML struct {
	Enabled                       bool    `yaml:"enabled"`
	SessionResumptionEnabled      bool    `yaml:"session_resumption_enabled"`
	MinConnectionsForSessionCheck int     `yaml:"min_connections_for_session_check"`
	ShortLifespanEnabled          bool    `yaml:"short_lifespan_enabled"`
	ShortLifespanThresholdMS      int     `yaml:"short_lifespan_threshold_ms"`
	ConcurrencyEnabled            bool    `yaml:"concurrency_enabled"`
	ConcurrencyModerate           int     `yaml:"concurrency_moderate"`
	ConcurrencyHigh               int     `yaml:"concurrency_high"`
	ConcurrencySevere             int     `yaml:"concurrency_severe"`
	ReturnVisitorEnabled          bool    `yaml:"return_visitor_enabled"`
	ReturnVisitorMinDays          int     `yaml:"return_visitor_min_days"`
	ReturnVisitorMinAllowRate     float64 `yaml:"return_visitor_min_allow_rate"`
}

// RateLimiterStrategyYAML holds a single rate limiter strategy from proxy.yml.
type RateLimiterStrategyYAML struct {
	Enabled    bool    `yaml:"enabled"`
	Suspicious int     `yaml:"suspicious"`
	Block      int     `yaml:"block"`
	Ban        int     `yaml:"ban"`
	Window     float64 `yaml:"window"`
	TTL        int     `yaml:"ttl"`
}

// RateLimiterConfigYAML holds rate limiter settings from proxy.yml.
type RateLimiterConfigYAML struct {
	Enabled bool                    `yaml:"enabled"`
	ByIP    RateLimiterStrategyYAML `yaml:"by_ip"`
	ByJA4   RateLimiterStrategyYAML `yaml:"by_ja4"`
	ByIPJA4 RateLimiterStrategyYAML `yaml:"by_ip_ja4"`
}

// ASNClassifierConfigYAML holds ASN classifier settings from proxy.yml.
type ASNClassifierConfigYAML struct {
	Enabled            bool     `yaml:"enabled"`
	DatacenterListPath string   `yaml:"datacenter_list_path"`
	MaxMindDBPath      string   `yaml:"maxmind_db_path"`
	DatacenterASNs     []uint   `yaml:"datacenter_asns"`
	DatacenterOrgs     []string `yaml:"datacenter_orgs"`
	TorExitList        struct {
		Enabled                bool   `yaml:"enabled"`
		RefreshIntervalSeconds int    `yaml:"refresh_interval_seconds"`
		DownloadURL            string `yaml:"download_url"`
	} `yaml:"tor_exit_list"`
	RiskContributions struct {
		Tor         int `yaml:"tor"`
		Datacenter  int `yaml:"datacenter"`
		VPN         int `yaml:"vpn"`
		Unknown     int `yaml:"unknown"`
		Residential int `yaml:"residential"`
		Mobile      int `yaml:"mobile"`
	} `yaml:"risk_contributions"`
}

// DNSEnrichmentConfigYAML holds DNS enrichment settings from proxy.yml.
type DNSEnrichmentConfigYAML struct {
	Enabled                bool `yaml:"enabled"`
	QueueSize              int  `yaml:"queue_size"`
	WorkerCount            int  `yaml:"worker_count"`
	TTLSeconds             int  `yaml:"ttl_seconds"`
	ResolverTimeoutSeconds int  `yaml:"resolver_timeout_seconds"`
	FCrDNS                 struct {
		Enabled                   bool `yaml:"enabled"`
		NoPTRScore                int  `yaml:"no_ptr_score"`
		FCrDNSFailedScore         int  `yaml:"fcrdns_failed_score"`
		ResidentialScoreReduction int  `yaml:"residential_score_reduction"`
	} `yaml:"fcrdns"`
}

// BlocklistFeedConfigYAML holds a single blocklist feed config from proxy.yml.
type BlocklistFeedConfigYAML struct {
	Name                   string `yaml:"name"`
	URL                    string `yaml:"url"`
	Format                 string `yaml:"format"`
	IsBypass               bool   `yaml:"is_bypass"`
	Action                 string `yaml:"action"`
	Score                  int    `yaml:"score"`
	RefreshIntervalSeconds int    `yaml:"refresh_interval_seconds"`
	Enabled                bool   `yaml:"enabled"`
	// phase-309 WP-6: local cache path for the downloaded feed. Used for
	// warm-start at boot and rewritten on each successful refresh. If empty,
	// the proxy derives a default under /var/lib/ja4proxy/blocklists/.
	Path string `yaml:"path"`
}

// BlocklistsConfigYAML holds blocklist settings from proxy.yml.
type BlocklistsConfigYAML struct {
	Feeds []BlocklistFeedConfigYAML `yaml:"feeds"`
}

// BeaconingConfigYAML holds beaconing detector settings from proxy.yml.
type BeaconingConfigYAML struct {
	Enabled                  bool `yaml:"enabled"`
	MinObservations          int  `yaml:"min_observations"`
	WindowSize               int  `yaml:"window_size"`
	ObservationWindowSeconds int  `yaml:"observation_window_seconds"`
	Score                    int  `yaml:"score"`
	LongWindow               struct {
		Enabled       bool `yaml:"enabled"`
		WindowSeconds int  `yaml:"window_seconds"`
		Score         int  `yaml:"score"`
	} `yaml:"long_window"`
}

// AbuseIPDBConfigYAML holds AbuseIPDB settings from proxy.yml.
type AbuseIPDBConfigYAML struct {
	Enabled           bool   `yaml:"enabled"`
	APIKey            string `yaml:"api_key"`
	APIURL            string `yaml:"api_url"`
	CacheTTLSeconds   int    `yaml:"cache_ttl_seconds"`
	SharedIPThreshold int    `yaml:"shared_ip_threshold"`
	QueueSize         int    `yaml:"queue_size"`
	WorkerCount       int    `yaml:"worker_count"`
	ScoreCap          int    `yaml:"score_cap"`
}

// RDAPConfigYAML holds RDAP enrichment settings from proxy.yml.
type RDAPConfigYAML struct {
	Enabled          bool   `yaml:"enabled"`
	QueueSize        int    `yaml:"queue_size"`
	WorkerCount      int    `yaml:"worker_count"`
	MinEnqueueScore  int    `yaml:"min_enqueue_score"`
	KnownBadOrgsPath string `yaml:"known_bad_orgs_path"`
	OrgReputation    struct {
		Enabled bool `yaml:"enabled"`
		Score   int  `yaml:"score"`
	} `yaml:"org_reputation"`
	NewNetblockFlagging struct {
		Enabled    bool `yaml:"enabled"`
		MaxAgeDays int  `yaml:"max_age_days"`
		Score      int  `yaml:"score"`
	} `yaml:"new_netblock_flagging"`
	BlockExpansion struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"block_expansion"`
}

// FingerprintingConfigYAML holds extended fingerprinting settings from proxy.yml.
type FingerprintingConfigYAML struct {
	JA4X struct {
		Enabled        bool `yaml:"enabled"`
		BlacklistScore int  `yaml:"blacklist_score"`
	} `yaml:"ja4x"`
}

// StaticIPConfigYAML holds a single IP entry for the static allowlist.
type StaticIPConfigYAML struct {
	IP      string `yaml:"ip"`
	Comment string `yaml:"comment"`
}

// StaticAllowlistConfigYAML holds static allowlist settings from proxy.yml.
type StaticAllowlistConfigYAML struct {
	Enabled bool                 `yaml:"enabled"`
	IPs     []StaticIPConfigYAML `yaml:"ips"`
}

// WebhookEndpointConfig is one webhook delivery target.
type WebhookEndpointConfig struct {
	ID                  string   `yaml:"id"`
	URL                 string   `yaml:"url"`
	Secret              string   `yaml:"secret"`
	Events              []string `yaml:"events"`
	RetryAttempts       int      `yaml:"retry_attempts"`
	RetryBackoffSeconds float64  `yaml:"retry_backoff_seconds"`
	TimeoutSeconds      float64  `yaml:"timeout_seconds"`
}

// WebhooksConfig holds the webhook dispatcher configuration.
type WebhooksConfig struct {
	Enabled   bool                    `yaml:"enabled"`
	StreamKey string                  `yaml:"stream_key"`
	DLQKey    string                  `yaml:"dlq_key"`
	Endpoints []WebhookEndpointConfig `yaml:"endpoints"`
	// JA4PROXY-2026-0031 — bounded XADD queue parameters.
	//
	// StreamQueueCapacity is the hard cap on buffered connection events
	// waiting to be written to Redis. When the queue is full the event is
	// dropped (ja4proxy_stream_event_drops_total) — the connection is
	// handled normally, only the telemetry is shed.
	// StreamWorkers is the number of goroutines draining the queue; each
	// worker calls XAdd with a timeout of StreamWriteTimeoutSeconds.
	StreamQueueCapacity       int     `yaml:"stream_queue_capacity"`
	StreamWorkers             int     `yaml:"stream_workers"`
	StreamWriteTimeoutSeconds float64 `yaml:"stream_write_timeout_seconds"`
}

// ErrRedisAuthRequired is returned by ValidateRedisAuth when the configured
// Redis host is remote but no password was supplied. JA4PROXY-2026-0010 —
// connecting to an unauthenticated remote Redis exposes ban lists, whitelists
// and the dial setting to any network peer who can reach the same Redis.
var ErrRedisAuthRequired = errors.New(
	"redis: password required for non-local host " +
		"(JA4PROXY-2026-0010 — set redis.password or point at 127.0.0.1/::1/localhost; " +
		"set JA4PROXY_ALLOW_UNAUTH_REDIS=1 to override for local test clusters)",
)

// ValidateRedisAuth refuses to start the proxy against a remote Redis without
// credentials. Local Redis (loopback host or unix socket) is permitted because
// it is presumed reachable only from the same host. The env-var escape hatch
// JA4PROXY_ALLOW_UNAUTH_REDIS=1 exists for integration tests that purposely
// run unauthenticated Redis on non-loopback addresses (e.g. docker bridge).
func ValidateRedisAuth(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if strings.TrimSpace(cfg.Redis.Password) != "" {
		return nil
	}
	// Sentinel / managed-cluster deployments may not set a Host at all; the
	// client resolves via the sentinels list. Treat the first sentinel as the
	// effective host for this check.
	host := cfg.Redis.Host
	if host == "" && len(cfg.Redis.Sentinels) > 0 {
		host = cfg.Redis.Sentinels[0]
	}
	if isLocalRedisHost(host) {
		return nil
	}
	if os.Getenv("JA4PROXY_ALLOW_UNAUTH_REDIS") == "1" {
		return nil
	}
	return fmt.Errorf("%w (host=%q)", ErrRedisAuthRequired, host)
}

// isLocalRedisHost returns true when the host string points at the same
// machine — loopback IPs, the "localhost" name, an empty string (which
// defaults to local in most clients), or a unix socket path.
func isLocalRedisHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return true
	}
	// Unix socket — never network-exposed.
	if strings.HasPrefix(h, "/") || strings.HasPrefix(h, "unix:") {
		return true
	}
	// Sentinel entries may be "host:port" — split.
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h, "::") {
		h = h[:i]
	}
	// Strip brackets from IPv6 literals.
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// RedisACLStatus describes whether per-service Redis ACL users are in use
// and, when they are not, whether the Redis target is local or remote.
// JA4PROXY-2026-0050.
type RedisACLStatus int

const (
	// RedisACLEnabled — acl_users.enabled is true. The proxy is expected to
	// connect with a non-"default" username, scoped to the key patterns and
	// commands its operation actually requires. Best posture.
	RedisACLEnabled RedisACLStatus = iota
	// RedisACLDisabledLocal — acl_users.enabled is false but the Redis
	// target is loopback / unix socket. Hardening is desirable but the
	// attack surface is limited to anyone with local host access.
	RedisACLDisabledLocal
	// RedisACLDisabledRemote — acl_users.enabled is false AND the Redis
	// target is network-reachable. Anyone with the Redis password can
	// rewrite ban lists, whitelists, and the dial. Callers emit a loud
	// startup WARN for this state and set the
	// ja4proxy_redis_acl_enabled=0 gauge.
	RedisACLDisabledRemote
)

// String returns a short identifier used in log fields and the regression
// test.
func (s RedisACLStatus) String() string {
	switch s {
	case RedisACLEnabled:
		return "enabled"
	case RedisACLDisabledLocal:
		return "disabled_local"
	case RedisACLDisabledRemote:
		return "disabled_remote"
	default:
		return "unknown"
	}
}

// CheckRedisACLStatus classifies the ACL configuration against the Redis
// target. Never fails — the ACL gap is a hardening concern, not a startup
// gate (flipping the default to on would break every existing deployment
// that has not yet run scripts/redis-acl-setup.sh). Callers decide how to
// react. See RedisACLStatus for semantics. JA4PROXY-2026-0050.
func CheckRedisACLStatus(cfg *Config) RedisACLStatus {
	if cfg == nil {
		return RedisACLEnabled
	}
	if cfg.Redis.ACLUsers.Enabled {
		return RedisACLEnabled
	}
	host := cfg.Redis.Host
	if host == "" && len(cfg.Redis.Sentinels) > 0 {
		host = cfg.Redis.Sentinels[0]
	}
	if isLocalRedisHost(host) {
		return RedisACLDisabledLocal
	}
	return RedisACLDisabledRemote
}

// ErrRedisACLUsernameMissing is returned by ValidateRedisACLConsistency
// when acl_users.enabled is true but acl_users.proxy_user is empty.
// Enabling ACLs without naming the proxy user silently downgrades the
// proxy's Redis connection back to the unrestricted "default" user —
// exactly the state the operator thought they were fixing.
// JA4PROXY-2026-0052.
var ErrRedisACLUsernameMissing = errors.New(
	"redis: acl_users.enabled is true but acl_users.proxy_user is empty " +
		"(JA4PROXY-2026-0052 — set redis.acl_users.proxy_user to the Redis " +
		"ACL username created by scripts/redis-acl-setup.sh, or set " +
		"acl_users.enabled: false to acknowledge the hardening gap)",
)

// ValidateRedisACLConsistency refuses to start the proxy when ACLs are
// enabled but no proxy_user is defined. Without this gate, the config
// reads as hardened (acl_users.enabled: true) but the actual Redis
// connection still opens as the "default" user with +@all ~*. Failing
// closed here forces the operator to either complete the ACL rollout or
// acknowledge the gap. JA4PROXY-2026-0052.
func ValidateRedisACLConsistency(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if !cfg.Redis.ACLUsers.Enabled {
		return nil
	}
	if strings.TrimSpace(cfg.Redis.ACLUsers.ProxyUser) == "" {
		return ErrRedisACLUsernameMissing
	}
	return nil
}

// ResolveRedisUsername returns the Redis ACL username the proxy should
// authenticate as. When acl_users.enabled is true, the acl_users.proxy_user
// is preferred — that is the whole point of the ACL configuration. When
// ACLs are disabled, fall through to the historical redis.username field
// (which is "" by default and resolves to the Redis "default" user).
// JA4PROXY-2026-0052.
func ResolveRedisUsername(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	if cfg.Redis.ACLUsers.Enabled {
		if u := strings.TrimSpace(cfg.Redis.ACLUsers.ProxyUser); u != "" {
			return u
		}
	}
	return cfg.Redis.Username
}

// ErrMetricsAuthRequired is returned by ValidateMetricsAccess when the
// metrics HTTP server is configured to bind to a non-loopback address with
// no AuthToken set. JA4PROXY-2026-0008 — /metrics and /health/deep leak
// dial setting, ban rates, cert expiry and active connection counts.
// An unauthenticated 0.0.0.0 bind gives any network peer reconnaissance
// before they launch an attack.
var ErrMetricsAuthRequired = errors.New(
	"metrics: auth_token required when bind_host is not loopback " +
		"(JA4PROXY-2026-0008 — set metrics.auth_token or bind to 127.0.0.1/::1; " +
		"set JA4PROXY_ALLOW_UNAUTH_METRICS=1 to override for trusted-network test clusters)",
)

// ValidateMetricsAccess refuses to start the proxy with a publicly-reachable
// metrics endpoint that has no authentication. If metrics is disabled the
// check is a no-op. A loopback bind is always accepted because it is
// presumed reachable only from the same host. The env-var escape hatch
// JA4PROXY_ALLOW_UNAUTH_METRICS=1 exists for internal test clusters where
// the metrics port is firewalled to a trusted scrape network.
func ValidateMetricsAccess(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if !cfg.Metrics.Enabled {
		return nil
	}
	if strings.TrimSpace(cfg.Metrics.AuthToken) != "" {
		return nil
	}
	host := strings.TrimSpace(cfg.Metrics.BindHost)
	if isLocalMetricsBind(host) {
		return nil
	}
	if os.Getenv("JA4PROXY_ALLOW_UNAUTH_METRICS") == "1" {
		return nil
	}
	return fmt.Errorf("%w (bind_host=%q)", ErrMetricsAuthRequired, host)
}

// isLocalMetricsBind returns true for bind addresses that restrict the
// metrics server to the local host. "" defaults to loopback here (we flip
// the Go http default of 0.0.0.0 to loopback explicitly in DefaultConfig,
// but if an operator clears the field we still refuse to fail open).
func isLocalMetricsBind(host string) bool {
	h := strings.TrimSpace(host)
	// An empty bind_host means "listen on all interfaces" in net.Listen —
	// that's exactly the 0008 footgun, so treat it as NOT local.
	if h == "" {
		return false
	}
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// MetricsRequestIsLocal reports whether an inbound HTTP request arrived from
// a loopback address. Used by the metrics auth middleware to exempt
// same-host scrapers (the common case for Prometheus running as a sidecar)
// from bearer-token checks.
func MetricsRequestIsLocal(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// Not host:port — treat as untrusted.
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// Validate checks the configuration for logical errors and consistency.
// Validate checks the configuration for logical errors and consistency.

func (c *Config) Validate() error {
	if c.Proxy.BindPort.Int() <= 0 || c.Proxy.BindPort.Int() > 65535 {
		return fmt.Errorf("invalid proxy bind port: %d", c.Proxy.BindPort.Int())
	}
	if c.Proxy.BackendPort.Int() <= 0 || c.Proxy.BackendPort.Int() > 65535 {
		return fmt.Errorf("invalid proxy backend port: %d", c.Proxy.BackendPort.Int())
	}
	if c.Proxy.BackendHost == "" {
		return fmt.Errorf("proxy backend host is required")
	}
	if c.Proxy.MaxConnections <= 0 {
		return fmt.Errorf("proxy max_connections must be > 0, got %d", c.Proxy.MaxConnections)
	}
	if c.MonitorMode.Dial < 0 || c.MonitorMode.Dial > 100 {
		return fmt.Errorf("invalid security dial (0-100): %d", c.MonitorMode.Dial)
	}
	if c.Redis.Timeout.Int() <= 0 {
		return fmt.Errorf("redis timeout must be > 0, got %d", c.Redis.Timeout.Int())
	}
	if c.DNSEnrichment.Enabled {
		if c.DNSEnrichment.QueueSize <= 0 {
			return fmt.Errorf("dns_enrichment queue_size must be > 0, got %d", c.DNSEnrichment.QueueSize)
		}
		if c.DNSEnrichment.WorkerCount <= 0 {
			return fmt.Errorf("dns_enrichment worker_count must be > 0, got %d", c.DNSEnrichment.WorkerCount)
		}
		if c.DNSEnrichment.TTLSeconds < 0 {
			return fmt.Errorf("dns_enrichment ttl_seconds must be >= 0, got %d", c.DNSEnrichment.TTLSeconds)
		}
	}
	if err := c.validateRiskScorerThresholds(); err != nil {
		return err
	}
	if err := c.validateRateLimiterThresholds(); err != nil {
		return err
	}
	for _, feed := range c.Blocklists.Feeds {
		if feed.Enabled && feed.Name == "" {
			return fmt.Errorf("blocklist feed enabled but missing name")
		}
	}
	if c.AbuseIPDB.CacheTTLSeconds < 0 {
		return fmt.Errorf("abuseipdb cache_ttl_seconds must be >= 0, got %d", c.AbuseIPDB.CacheTTLSeconds)
	}
	if c.RDAPEnrichment.QueueSize < 0 {
		return fmt.Errorf("rdap_enrichment queue_size must be >= 0, got %d", c.RDAPEnrichment.QueueSize)
	}
	if c.RDAPEnrichment.WorkerCount < 0 {
		return fmt.Errorf("rdap_enrichment worker_count must be >= 0, got %d", c.RDAPEnrichment.WorkerCount)
	}
	if c.AbuseIPDB.QueueSize < 0 {
		return fmt.Errorf("abuseipdb queue_size must be >= 0, got %d", c.AbuseIPDB.QueueSize)
	}
	if c.AbuseIPDB.WorkerCount < 0 {
		return fmt.Errorf("abuseipdb worker_count must be >= 0, got %d", c.AbuseIPDB.WorkerCount)
	}
	return nil
}

func (c *Config) validateRiskScorerThresholds() error {
	th := c.RiskScorer.Thresholds
	fields := []struct {
		name  string
		value int
	}{
		{"flag", th.Flag},
		{"rate_limit", th.RateLimit},
		{"tarpit", th.Tarpit},
		{"block", th.Block},
		{"ban", th.Ban},
	}
	for _, f := range fields {
		if f.value < 0 || f.value > 100 {
			return fmt.Errorf("risk_scorer thresholds.%s must be in 0-100, got %d", f.name, f.value)
		}
	}
	if th.Flag > th.RateLimit || th.RateLimit > th.Tarpit || th.Tarpit > th.Block || th.Block > th.Ban {
		return fmt.Errorf("risk_scorer thresholds must be non-decreasing: flag(%d) <= rate_limit(%d) <= tarpit(%d) <= block(%d) <= ban(%d)",
			th.Flag, th.RateLimit, th.Tarpit, th.Block, th.Ban)
	}
	return nil
}

func (c *Config) validateRateLimiterThresholds() error {
	strategies := []struct {
		name     string
		strategy RateLimiterStrategyYAML
	}{
		{"by_ip", c.RateLimiter.ByIP},
		{"by_ja4", c.RateLimiter.ByJA4},
		{"by_ip_ja4", c.RateLimiter.ByIPJA4},
	}
	for _, s := range strategies {
		if !s.strategy.Enabled {
			continue
		}
		if s.strategy.Ban <= 0 {
			return fmt.Errorf("rate_limiter %s.ban must be > 0, got %d", s.name, s.strategy.Ban)
		}
		if s.strategy.Block <= 0 {
			return fmt.Errorf("rate_limiter %s.block must be > 0, got %d", s.name, s.strategy.Block)
		}
		if s.strategy.Suspicious <= 0 {
			return fmt.Errorf("rate_limiter %s.suspicious must be > 0, got %d", s.name, s.strategy.Suspicious)
		}
		if s.strategy.TTL < 0 {
			return fmt.Errorf("rate_limiter %s.ttl must be >= 0, got %d", s.name, s.strategy.TTL)
		}
	}
	return nil
}
