package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/seanpor/ja4proxy/internal/cli/engine"
	"github.com/seanpor/ja4proxy/internal/cluster/sync"
	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/redis"
	"github.com/seanpor/ja4proxy/internal/security"
	"github.com/seanpor/ja4proxy/internal/test/bench"
	"github.com/seanpor/ja4proxy/internal/wizard"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	cfgPath string
	version = config.Version
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "ja4p",
		Short: "JA4proxy Operational Toolset",
		Long:  "Unified CLI for JA4proxy environment initialization, configuration validation, and security simulation.",
	}

	rootCmd.PersistentFlags().StringVarP(&cfgPath, "config", "c", "config/proxy.yml", "Path to proxy configuration")

	// 1. Version Command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("JA4proxy %s\n", version)
			fmt.Printf("Built: %s\n", config.BuildDate)
			fmt.Printf("Commit: %s\n", config.GitCommit)
		},
	})

	// 2. Init Command (The Wizard)
	var (
		dryRun         bool
		laneFlag       int
		nonInteractive bool
	)
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Launch the guided setup wizard",
		Long: `Interactive setup wizard for JA4proxy deployment.

Walks through all configuration options (backend, networking, TLS, lanes,
security, hardening) and generates .env, systemd unit, proxy.yml, and
haproxy.cfg.

Use --dry-run to preview without writing anything.
Use --lane to pre-select a lane number (non-interactive hints).
Use --non-interactive with --lane to accept all defaults.`,
		Run: func(cmd *cobra.Command, args []string) {
			out := wizard.NewConsoleOutput()

			// Find project root for lane-env.sh
			laneMgr := findLaneManager()
			wiz := wizard.New(out, wizard.StdinInput, wizard.StdinGetPass, laneMgr)
			wiz.Answers.Lane = laneFlag
			wiz.Answers.DryRun = dryRun
			if nonInteractive {
				wiz.NonInteractive = true
				wiz.Answers.MonitoringStack = true
				wiz.Answers.BackendHost = "backend"
				wiz.Answers.BackendPort = 443
				wiz.Answers.Mode = "container"
				wiz.Answers.BindIP = "127.0.0.1"
				wiz.Answers.AdminUser = "admin"
				wiz.Answers.AdminPassword = ""
				wiz.Answers.LogLevel = "INFO"
				wiz.Answers.DialValue = 0
				wiz.Answers.AllowedSNIs = nil
				wiz.Answers.TLSCerts = "self-signed"
				wiz.Answers.Firewall = "none"
				wiz.Answers.Fail2Ban = false
				wiz.Answers.CrowdSec = false
				wiz.Answers.LogForwarding = "none"
				wiz.Answers.BackupEncrypt = "none"
			}
			_, _, err := wiz.Run(context.Background())
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
	initCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview configuration without writing anything")
	initCmd.Flags().IntVar(&laneFlag, "lane", -1, "Pre-select lane number")
	initCmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "Accept all defaults (requires --lane)")
	rootCmd.AddCommand(initCmd)

	// 3. Config Validate Command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Verify proxy configuration and security feeds",
		Run: func(cmd *cobra.Command, args []string) {
			if err := runConfigValidate(cfgPath); err != nil {
				fmt.Fprintf(os.Stderr, "Config validation failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("✓ Configuration is valid.")
		},
	})

	// 4. Test Command Group
	testCmd := &cobra.Command{
		Use:   "test",
		Short: "Simulation and testing tools",
	}
	testCmd.AddCommand(&cobra.Command{
		Use:   "ip [address]",
		Short: "Simulate a pipeline decision for an IP address",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
				os.Exit(1)
			}
			if err := runTestIP(cfg, args[0]); err != nil {
				fmt.Fprintf(os.Stderr, "Simulation failed: %v\n", err)
				os.Exit(1)
			}
		},
	})
	testCmd.AddCommand(&cobra.Command{
		Use:                "benchmark",
		Short:              "Run built-in Go load generator",
		DisableFlagParsing: true,
		Run: func(cmd *cobra.Command, args []string) {
			bench.RunBenchmark(args)
		},
	})
	rootCmd.AddCommand(testCmd)

	// 5. Management Commands
	mgmtCmd := engine.BuildManagementRoot()
	mgmtCmd.Use = "management"
	rootCmd.AddCommand(mgmtCmd)

	// 6. Cluster Command Group
	clusterCmd := &cobra.Command{
		Use:   "cluster",
		Short: "Cluster-wide synchronization and mesh tools",
	}
	clusterCmd.AddCommand(&cobra.Command{
		Use:   "sync",
		Short: "Start the sync mesh agent",
		Run: func(cmd *cobra.Command, args []string) {
			runSyncAgent(cfgPath)
		},
	})
	rootCmd.AddCommand(clusterCmd)

	// 7. JA4 Check Command
	rootCmd.AddCommand(buildCheckCmd())

	// 8. Backup Command (phase-315a)
	rootCmd.AddCommand(buildBackupCmd())

	// 9. Restore Command (phase-315b)
	rootCmd.AddCommand(buildRestoreCmd())

	// 10. Shell Completion (cobra built-in, phase-161)
	rootCmd.AddCommand(&cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate shell completion script for ja4p.

To enable, run one of the following:

  bash:   source <(ja4p completion bash)
  zsh:    source <(ja4p completion zsh)
  fish:   ja4p completion fish | source

Load on login by adding the source command to your shell's rc file.`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				_ = cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				_ = cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				_ = cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				_ = cmd.Root().GenPowerShellCompletion(os.Stdout)
			}
		},
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func findLaneManager() *wizard.ShellLaneManager {
	cwd, err := os.Getwd()
	if err != nil {
		return nil
	}
	laneScript := cwd + "/scripts/lane-env.sh"
	if _, err := os.Stat(laneScript); err == nil {
		return wizard.NewShellLaneManager(laneScript, cwd)
	}
	return nil
}

func runConfigValidate(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	return cfg.Validate()
}

func runSyncAgent(path string) {
	log := logrus.New()
	cfg, err := config.Load(path)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	baseLog := log.WithFields(logrus.Fields{
		"service.name": "ja4p-cluster-sync",
		"version":      config.Version,
	})

	if cfg.Sync.IntegrityKeyFile == "" {
		baseLog.Fatal("Integrity key required for sync mesh (JA4PROXY-2026-0041)")
	}

	redisCfg := redis.Config{
		Host:       cfg.Redis.Host,
		Port:       cfg.Redis.Port.Int(),
		MasterName: cfg.Redis.MasterName,
		Sentinels:  cfg.Redis.Sentinels,
		DB:         cfg.Redis.DB,
		Password:   cfg.Redis.Password,
		Username:   cfg.Redis.Username,
		SSL:        cfg.Redis.SSL,
		Timeout:    time.Duration(cfg.Redis.Timeout.Int()) * time.Second,
	}
	rc := redis.New(redisCfg, log)
	defer rc.Close()

	agent := sync.NewSyncAgent(cfg, rc, baseLog)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	baseLog.Info("Starting sync mesh agent...")
	if err := agent.Start(ctx); err != nil {
		baseLog.WithError(err).Fatal("syncagent failed")
	}
}

func runTestIP(cfg *config.Config, ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	p := security.NewPipeline(&security.PipelineConfig{
		ALPNBrowserBypass:      cfg.SecurityPolicy.ALPNBrowserBypass.Enabled,
		JA4WhitelistBypass:     cfg.SecurityPolicy.JA4WhitelistBypass.Enabled,
		JA4BlockingEnabled:     cfg.SecurityPolicy.JA4BlockingEnabled.Enabled,
		MTLSBypass:             cfg.SecurityPolicy.MTLSBypass.Enabled,
		CountryBlockingEnabled: cfg.SecurityPolicy.CountryBlockingEnabled.Enabled,
	}, nil, logger)

	ctx := context.Background()
	conn := &security.ConnectionContext{
		ClientIP: ipStr,
		ParsedIP: ip,
	}

	result := p.Process(ctx, conn)

	fmt.Printf("Results for IP: %s\n", ipStr)
	fmt.Printf("Action: %s\n", result.Action)
	fmt.Printf("Score:  %d\n", result.Score)
	if result.Bypassed {
		fmt.Printf("Bypassed: Yes (%s)\n", result.BypassReason)
	}
	fmt.Println("Signals:")
	for _, s := range result.Signals {
		fmt.Printf(" - %s: %d (%s)\n", s.Name, s.Score, s.Reason)
	}

	return nil
}
