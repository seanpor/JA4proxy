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
			Format:      "legacy",
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Port:    9090,
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
			MaxActiveConnections: 500,
			MaxPerIP:             3,
			OverflowAction:       "block",
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
		StaticAllowlist: StaticAllowlistConfigYAML{
			Enabled: true,
			IPs:     []StaticIPConfigYAML{},
		},
		Webhooks: WebhooksConfig{
			Enabled:   false,
			StreamKey: "events:connection",
			DLQKey:    "webhooks:dlq",
			Endpoints: []WebhookEndpointConfig{},
		},
	}
}

// ── Config struct hierarchy ───────────────────────────────────────────────

// Config is the top-level configuration structure. Field names match proxy.yml.
type Config struct {
	Proxy           ProxyConfig               `yaml:"proxy"`
	Redis           RedisConfig               `yaml:"redis"`
	Security        SecurityConfig            `yaml:"security"`
	MonitorMode     MonitorModeConfig         `yaml:"monitor_mode"`
	SecurityPolicy  SecurityPolicyConfig      `yaml:"security_policy"`
	RiskScorer      RiskScorerConfig          `yaml:"risk_scorer"`
	Logging         LoggingConfig             `yaml:"logging"`
	Metrics         MetricsConfig             `yaml:"metrics"`
	Tarpit          TarpitConfig              `yaml:"tarpit"`
	TLSEnforcer     TLSEnforcerConfigYAML     `yaml:"tls_enforcer"`
	SNIAnalyzer     SNIAnalyzerConfigYAML     `yaml:"sni_analyzer"`
	GeoIP           GeoIPConfigYAML           `yaml:"geoip"`
	TCPAnalyzer     TCPAnalyzerConfigYAML     `yaml:"tcp_analyzer"`
	RateLimiter     RateLimiterConfigYAML     `yaml:"rate_limiter"`
	ASNClassifier   ASNClassifierConfigYAML   `yaml:"asn_classifier"`
	DNSEnrichment   DNSEnrichmentConfigYAML   `yaml:"dns_enrichment"`
	Blocklists      BlocklistsConfigYAML      `yaml:"blocklists"`
	Beaconing       BeaconingConfigYAML       `yaml:"beaconing_detector"`
	AbuseIPDB       AbuseIPDBConfigYAML       `yaml:"abuseipdb"`
	RDAPEnrichment  RDAPConfigYAML            `yaml:"rdap_enrichment"`
	Fingerprinting  FingerprintingConfigYAML  `yaml:"fingerprinting"`
	StaticAllowlist StaticAllowlistConfigYAML `static_allowlist"`
	Webhooks        WebhooksConfig            `yaml:"webhooks"`   // phase-80
	Monitoring      MonitoringConfig          `yaml:"monitoring"` // phase-88
	Sync            SyncAgentConfig           `yaml:"sync"`       // phase-88
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
}

// RedisConfig holds Redis connection settings.
type RedisConfig struct {
	Host       string   `yaml:"host"`
	Port       FlexInt  `yaml:"port"`
	MasterName string   `yaml:"master_name"`
	Sentinels  []string `yaml:"sentinels"`
	DB         int      `yaml:"db"`
	Password   string   `yaml:"password"`
	Timeout    FlexInt  `yaml:"timeout"`
	SSL        bool     `yaml:"ssl"`
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
	// Format controls the log output format: "legacy" (default) or "ecs".
	// "ecs" emits ECS 8.x-compliant JSON for SIEM ingestion.
	Format string `yaml:"format"` // phase-80
	// DualOutput, when true and Format is "ecs", emits both legacy and ECS
	// JSON lines per log entry — useful during SIEM dashboard migration.
	// Python-only feature; Go logs a warning and uses ECS-only.
	DualOutput bool `yaml:"dual_output"` // phase-80
}

// MetricsConfig holds Prometheus metrics settings.
type MetricsConfig struct {
	Enabled bool    `yaml:"enabled"`
	Port    FlexInt `yaml:"port"`
}

// TarpitConfig holds tarpit self-protection settings.
type TarpitConfig struct {
	MaxActiveConnections int    `yaml:"max_concurrent_connections"`
	MaxPerIP             int    `yaml:"max_per_ip"`
	OverflowAction       string `yaml:"overflow_action"`
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
}
