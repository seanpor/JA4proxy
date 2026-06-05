package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/security"
	"github.com/seanpor/ja4proxy/internal/cli/engine"
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
	rootCmd.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Launch the guided setup wizard",
		Run: func(cmd *cobra.Command, args []string) {
			runWizard()
		},
	})

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

	// 4. Test IP Command
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
	rootCmd.AddCommand(testCmd)

	// 5. Management Commands (from engine)
	mgmtCmd := engine.BuildManagementRoot()
	mgmtCmd.Use = "management"
	rootCmd.AddCommand(mgmtCmd)

	// 6. JA4 Check Command
	rootCmd.AddCommand(buildCheckCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runConfigValidate(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	return cfg.Validate()
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

func runWizard() {
	fmt.Println("======================================================================")
	fmt.Println("  JA4proxy Guided Setup Wizard")
	fmt.Println("======================================================================")
	fmt.Println("")

	fmt.Println("Select your deployment scenario:")
	fmt.Println("  1) Proof of Concept (POC) - Instant demo with mock backend")
	fmt.Println("  2) Development - Research environment with debug logging")
	fmt.Println("  3) Performance - Optimized for raw throughput testing")
	fmt.Println("  4) Production - Secure-by-default enterprise setup")
	fmt.Println("")

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter choice (1-4): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		setupScenario("POC", "backend", 443, "development")
	case "2":
		setupScenario("Development", "backend", 443, "development")
	case "3":
		setupScenario("Performance", "backend", 443, "production")
	case "4":
		fmt.Print("Enter backend host (e.g., 10.0.0.50): ")
		host, _ := reader.ReadString('\n')
		host = strings.TrimSpace(host)
		setupScenario("Production", host, 443, "production")
	default:
		fmt.Println("Invalid choice. Exiting.")
		os.Exit(1)
	}
}

func setupScenario(name, backendHost string, backendPort int, env string) {
	fmt.Printf("\n▶ Starting %s Setup...\n", name)

	redisPW := randomString(32)
	grafanaPW := randomString(16)
	signingKey := randomHex(32)
	jwtSecret := randomString(32)
	adminUser := "admin"
	adminPW := randomString(24)

	content := fmt.Sprintf("# Auto-generated by ja4p init — %s\n", time.Now().Format(time.RFC3339))
	content += fmt.Sprintf("BACKEND_HOST=%s\n", backendHost)
	content += fmt.Sprintf("BACKEND_PORT=%d\n", backendPort)
	content += fmt.Sprintf("REDIS_PASSWORD=%s\n", redisPW)
	content += fmt.Sprintf("GRAFANA_PASSWORD=%s\n", grafanaPW)
	content += fmt.Sprintf("REDIS_SIGNING_KEY=%s\n", signingKey)
	content += fmt.Sprintf("MANAGEMENT_JWT_SECRET=%s\n", jwtSecret)
	content += fmt.Sprintf("MANAGEMENT_ADMIN_USER=%s\n", adminUser)
	content += fmt.Sprintf("MANAGEMENT_ADMIN_PASSWORD=%s\n", adminPW)
	content += fmt.Sprintf("ENVIRONMENT=%s\n", env)

	if name == "Performance" {
		content += "LOG_LEVEL=WARNING\n"
		content += "JA4PROXY_BUFFER_SIZE=8192\n"
		content += "METRICS_BIND_HOST=0.0.0.0\n"
		content += "METRICS_AUTH_TOKEN=bench-token-123\n"
		fmt.Println("  ✓ Performance tuning applied")
	}

	err := os.WriteFile(".env", []byte(content), 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ❌ Failed to write .env: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("  ✓ .env created (chmod 600)")
	fmt.Println("  ✓ Secure secrets generated")
	fmt.Printf("\n✓ %s Setup complete!\n", name)
	if name == "POC" {
		fmt.Println("Run \"make start-poc\" to begin.")
	} else {
		fmt.Println("Run \"make start\" to begin.")
	}
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = letters[b[i]%byte(len(letters))]
	}
	return string(b)
}

func randomHex(n int) string {
	b := make([]byte, n/2)
	rand.Read(b)
	return hex.EncodeToString(b)
}
