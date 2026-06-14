package wizard

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// Answers holds all user-provided configuration values collected by the wizard.
type Answers struct {
	Topology        string   // "inline" (only option post-128)
	BackendHost     string   // backend hostname or IP
	BackendPort     int      // backend port
	Mode            string   // "native" or "container"
	BindIP          string   // admin bind IP
	AdminUser       string   // management UI admin user
	AdminPassword   string   // management UI admin password (generated if empty)
	AllowedSNIs     []string // comma-separated; empty = allow all
	UpstreamLB      bool     // upstream TCP load balancer present
	TrustedCIDRs    []string // upstream_trust.trusted_cidrs
	WritePROXY      bool     // write PROXY protocol to backend
	PROXYVersion    int      // PROXY protocol version (1 or 2)
	TLSCerts        string   // "self-signed" or "user-supplied"
	TLSCertPath     string   // user-supplied cert path
	TLSKeyPath      string   // user-supplied key path
	GeoIPPaths      []string // auto-detected .mmdb paths
	TIKeys          map[string]string // threat intel API keys
	DialValue       int      // 0-100, 0 = monitor mode
	LogLevel        string   // DEBUG/INFO/WARN/ERROR
	Lane            int      // lane number (-1 = auto-assign)
	LaneName        string   // human-friendly lane name
	Firewall        string   // "ufw", "firewalld", "nftables", "none"
	Fail2Ban        bool     // install fail2ban
	CrowdSec        bool     // install crowdsec
	LogForwarding   string   // "loki", "syslog", "none"
	BackupEncrypt   string   // "age", "gpg", "none"
	BackupRecipient string   // encryption recipient
	MonitoringStack bool     // include prometheus/grafana/alertmanager
	DryRun          bool     // preview only, no writes
	ProjectName     string   // compose project name
	PortOffset      int      // manual port offset override
}

type LaneInfo struct {
	Number  int
	Name    string
	Path    string
	Ports   map[string]int
	Project string
}

type GeneratedConfig struct {
	Env     string // .env content
	Systemd string // systemd unit content
	ProxyYML string // proxy.yml content
	HAProxy  string // haproxy.cfg content (empty if not enabled)
}

// Wizard orchestrates the setup wizard flow.
type Wizard struct {
	Answers     Answers
	Out         Output // terminal output helper
	InputFn     func(string) (string, error)
	GetPassFn   func(string) (string, error)
	LaneManager LaneManager
}

type LaneManager interface {
	ListLanes(ctx context.Context) ([]LaneInfo, error)
	AssignLane(ctx context.Context, preferred int) (LaneInfo, error)
	PreviewPorts(lane int) (map[string]int, error)
}

func New(out Output, inputFn, getPassFn func(string) (string, error), lm LaneManager) *Wizard {
	return &Wizard{
		Out:         out,
		InputFn:     inputFn,
		GetPassFn:   getPassFn,
		LaneManager: lm,
	}
}

func (w *Wizard) Run(ctx context.Context) (*Answers, *GeneratedConfig, error) {
	w.Out.Header("JA4proxy Guided Setup Wizard")

	runWizard := func() error {
		if err := w.collectStep1Basics(ctx); err != nil {
			return err
		}
		if err := w.collectStep2Network(ctx); err != nil {
			return err
		}
		if err := w.collectStep3TLS(ctx); err != nil {
			return err
		}
		if err := w.collectStep4Lane(ctx); err != nil {
			return err
		}
		if err := w.collectStep5Security(ctx); err != nil {
			return err
		}
		if err := w.collectStep6Hardening(ctx); err != nil {
			return err
		}
		return nil
	}
	if err := runWizard(); err != nil {
		return nil, nil, err
	}

	if !w.Answers.DryRun {
		if err := w.confirmAndWrite(ctx); err != nil {
			return nil, nil, err
		}
	}
	return &w.Answers, nil, nil
}

func (w *Wizard) collectStep1Basics(ctx context.Context) error {
	val := func(s string) bool { return len(s) > 0 }
	host, err := ask("Protected backend host", "backend", val, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.BackendHost = host

	port, err := ask("Protected backend port", "443", validPort, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.BackendPort = atoi(port, 443)

	mode, err := ask("Deployment mode (native/container)", "container",
		func(s string) bool { return s == "native" || s == "container" }, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.Mode = mode

	ip, err := ask("Admin bind IP (loopback recommended)", "127.0.0.1", validBindIP, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.BindIP = ip

	user, err := ask("Management UI admin user", "admin", func(s string) bool { return len(s) > 0 }, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.AdminUser = user

	pw, err := w.GetPassFn("Management UI admin password (blank = generate): ")
	if err == nil && pw != "" {
		w.Answers.AdminPassword = pw
	} else {
		w.Answers.AdminPassword = genPassword(24)
	}

	ll, err := ask("Log level (DEBUG/INFO/WARN/ERROR)", "INFO",
		func(s string) bool {
			switch s {
			case "DEBUG", "INFO", "WARN", "ERROR":
				return true
			}
			return false
		}, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.LogLevel = ll

	return nil
}

func (w *Wizard) collectStep2Network(ctx context.Context) error {
	dial, err := ask("Dial value (0-100, 0=monitor mode)", "0",
		func(s string) bool {
			v := atoi(s, -1)
			return v >= 0 && v <= 100
		}, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.DialValue = atoi(dial, 0)
	if w.Answers.DialValue > 50 {
		w.Out.Warn("High dial value (%d) — proxy will actively block traffic", w.Answers.DialValue)
	}

	lb, err := askYesNo("Upstream TCP load balancer present?", false, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.UpstreamLB = lb
	if lb {
		cidrs, err := ask("Trusted upstream CIDRs (comma-separated)", "", func(s string) bool { return true }, w.InputFn)
		if err != nil {
			return err
		}
		w.Answers.TrustedCIDRs = splitCSV(cidrs)
	}

	pp, err := askYesNo("Write PROXY protocol to backend?", false, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.WritePROXY = pp
	if pp {
		pv, err := ask("PROXY protocol version (1 or 2)", "1",
			func(s string) bool { return s == "1" || s == "2" }, w.InputFn)
		if err != nil {
			return err
		}
		w.Answers.PROXYVersion = atoi(pv, 1)
	}

	snis, err := ask("Allowed SNIs (comma-separated, empty=allow all)", "",
		func(s string) bool { return true }, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.AllowedSNIs = splitCSV(snis)

	return nil
}

func (w *Wizard) collectStep3TLS(ctx context.Context) error {
	certMode, err := ask("TLS certificates: self-signed or user-supplied", "self-signed",
		func(s string) bool { return s == "self-signed" || s == "user-supplied" }, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.TLSCerts = certMode

	if certMode == "user-supplied" {
		certPath, err := ask("TLS certificate path", "", validCertPath, w.InputFn)
		if err != nil {
			return err
		}
		w.Answers.TLSCertPath = certPath

		keyPath, err := ask("TLS key path", "", validCertPath, w.InputFn)
		if err != nil {
			return err
		}
		w.Answers.TLSKeyPath = keyPath
	}

	geoip := detectGeoIP()
	if len(geoip) == 0 {
		w.Out.Warn("No GeoIP databases found at /opt/ja4proxy/data/geoip/")
		geoipStr, err := ask("GeoIP database directory", "/opt/ja4proxy/data/geoip", validDir, w.InputFn)
		if err != nil {
			return err
		}
		geoip = detectGeoIPAt(geoipStr)
	}
	w.Answers.GeoIPPaths = geoip

	return nil
}

func (w *Wizard) collectStep4Lane(ctx context.Context) error {
	hasLanes := false
	if w.LaneManager != nil {
		lanes, err := w.LaneManager.ListLanes(ctx)
		if err == nil && len(lanes) > 0 {
			hasLanes = true
			w.Out.Info("Existing environments detected:")
			for _, l := range lanes {
				w.Out.Info("  Lane %d: %s (%s)", l.Number, l.Name, l.Path)
			}
		}
	}

	var lane int
	if hasLanes {
		laneChoice, err := ask("Use existing lane or create new? (existing/new)", "new",
			func(s string) bool { return s == "existing" || s == "new" }, w.InputFn)
		if err != nil {
			return err
		}
		if laneChoice == "existing" {
			laneStr, err := ask("Lane number to reuse", "", func(s string) bool {
				v := atoi(s, -1)
				return v >= 0
			}, w.InputFn)
			if err != nil {
				return err
			}
			lane = atoi(laneStr, 0)
		}
	}

	if lane == 0 && !hasLanes {
		laneStr, err := ask("Lane number (0 = auto-assign)", "0", func(s string) bool {
			v := atoi(s, -1)
			return v >= 0
		}, w.InputFn)
		if err != nil {
			return err
		}
		lane = atoi(laneStr, -1)
	}
	w.Answers.Lane = lane

	laneName, err := ask("Environment name (e.g., prod, staging)", "default",
		func(s string) bool { return len(s) > 0 }, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.LaneName = laneName

	return nil
}

func (w *Wizard) collectStep5Security(ctx context.Context) error {
	w.Out.Section("Threat Intelligence API Keys (optional, press Enter to skip)")

	tiKeys := make(map[string]string)
	tis := []struct {
		name string
		env  string
	}{
		{"AbuseIPDB", "ABUSEIPDB_API_KEY"},
		{"GreyNoise", "GREYNOISE_API_KEY"},
		{"AlienVault OTX", "ALIENVAULT_OTX_KEY"},
		{"MISP", "MISP_API_KEY"},
		{"ThreatFox", "THREATFOX_API_KEY"},
		{"VirusTotal", "VIRUSTOTAL_API_KEY"},
		{"Recorded Future", "RECORDED_FUTURE_API_KEY"},
		{"CrowdStrike", "CROWDSTRIKE_API_KEY"},
	}
	for _, ti := range tis {
		key, err := w.GetPassFn(fmt.Sprintf("  %s API key (blank to skip): ", ti.name))
		if err != nil {
			return err
		}
		if key != "" {
			tiKeys[ti.env] = key
		}
	}
	w.Answers.TIKeys = tiKeys

	return nil
}

func (w *Wizard) collectStep6Hardening(ctx context.Context) error {
	w.Out.Section("Production Hardening")

	fw, err := ask("Firewall backend (ufw/firewalld/nftables/none)", detectFirewall(),
		func(s string) bool {
			switch s {
			case "ufw", "firewalld", "nftables", "none":
				return true
			}
			return false
		}, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.Firewall = fw

	f2b, err := askYesNo("Install Fail2Ban integration?", false, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.Fail2Ban = f2b

	cs, err := askYesNo("Install CrowdSec integration?", false, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.CrowdSec = cs

	logFwd, err := ask("Log forwarding (loki/syslog/none)", "loki",
		func(s string) bool {
			switch s {
			case "loki", "syslog", "none":
				return true
			}
			return false
		}, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.LogForwarding = logFwd

	bk, err := ask("Backup encryption (age/gpg/none)", "none",
		func(s string) bool {
			switch s {
			case "age", "gpg", "none":
				return true
			}
			return false
		}, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.BackupEncrypt = bk
	if bk != "none" {
		recip, err := ask(fmt.Sprintf("Backup encryption recipient (%s public key)", bk), "",
			func(s string) bool { return len(s) > 0 }, w.InputFn)
		if err != nil {
			return err
		}
		w.Answers.BackupRecipient = recip
	}

	mon, err := askYesNo("Include monitoring stack? (Prometheus, Grafana, Alertmanager, Loki)", true, w.InputFn)
	if err != nil {
		return err
	}
	w.Answers.MonitoringStack = mon

	return nil
}

func (w *Wizard) confirmAndWrite(ctx context.Context) error {
	w.Out.Section("Configuration Summary")
	w.Out.Info("  Backend:       %s:%d", w.Answers.BackendHost, w.Answers.BackendPort)
	w.Out.Info("  Mode:          %s", w.Answers.Mode)
	w.Out.Info("  Bind IP:       %s", w.Answers.BindIP)
	w.Out.Info("  Admin user:    %s", w.Answers.AdminUser)
	w.Out.Info("  LANE:          %d (%s)", w.Answers.Lane, w.Answers.LaneName)
	w.Out.Info("  Dial:          %d", w.Answers.DialValue)
	w.Out.Info("  Log level:     %s", w.Answers.LogLevel)
	w.Out.Info("  Firewall:      %s", w.Answers.Firewall)
	w.Out.Info("  Monitoring:    %v", w.Answers.MonitoringStack)
	w.Out.Info("  Secrets:       [generated — see .env]")

	confirm, err := askYesNo("Write configuration?", true, w.InputFn)
	if err != nil {
		return err
	}
	if !confirm {
		w.Out.Info("Aborted — no files written.")
		return nil
	}

	env := buildEnv(&w.Answers)
	envContent := renderEnv(env)
	systemdContent := buildSystemdUnit(&w.Answers)

	wd, _ := os.Getwd()
	envPath := filepath.Join(wd, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0600); err != nil {
		return fmt.Errorf("writing .env: %w", err)
	}
	w.Out.Success("Written .env (chmod 600)")

	sysdDir := "/etc/systemd/system"
	if _, err := os.Stat(sysdDir); err == nil {
		sysdPath := filepath.Join(sysdDir, "ja4proxy.service")
		if err := os.WriteFile(sysdPath, []byte(systemdContent), 0644); err != nil {
			w.Out.Warn("Failed to write systemd unit: %v", err)
		} else {
			w.Out.Success("Written systemd unit to %s", sysdPath)
		}
	} else {
		w.Out.Info("Systemd not detected — skipping unit file (running in container?)")
	}

	return nil
}
