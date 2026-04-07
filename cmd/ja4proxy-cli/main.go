// ja4proxy-cli is the command-line interface for the JA4proxy Management API.
// It provides day-2 operations for SREs and security engineers: IP banning,
// allowlist/blocklist management, dial control, health monitoring, fingerprint
// history, and policy-as-code apply/diff/validate.
//
// Usage:
//
//	ja4proxy-cli [--url URL] [--token TOKEN] [--output FORMAT] <command> [args]
//
// Global flags:
//
//	--url    Management API base URL (overrides JA4PROXY_URL env var)
//	--token  API bearer token (overrides JA4PROXY_TOKEN env var)
//	--output Default output format: table|json|csv (default: table)
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/anomalyco/ja4proxy/internal/cli/auth"
	"github.com/anomalyco/ja4proxy/internal/cli/client"
	"github.com/anomalyco/ja4proxy/internal/cli/commands"
	cliconfig "github.com/anomalyco/ja4proxy/internal/cli/config"
	"github.com/anomalyco/ja4proxy/internal/cli/output"
)

// globalFlags holds the values of persistent global flags.
type globalFlags struct {
	url    string
	token  string
	format string
}

var gf globalFlags

func main() {
	// Load optional config file defaults.
	cfg, _ := cliconfig.Load()
	if cfg != nil {
		if cfg.URL != "" && gf.url == "" {
			gf.url = cfg.URL
		}
		if cfg.Token != "" && gf.token == "" {
			gf.token = cfg.Token
		}
		if cfg.DefaultOutput != "" && gf.format == "" {
			gf.format = cfg.DefaultOutput
		}
	}

	root := buildRoot()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// newClient builds a Management API client using the resolved URL and token.
// Returns an error if either is empty.
func newClient() (*client.Client, error) {
	apiURL := auth.ResolveURL(gf.url)
	token := auth.ResolveToken(gf.token)
	if apiURL == "" {
		return nil, fmt.Errorf("API URL is required — use --url or set JA4PROXY_URL")
	}
	return client.New(apiURL, token), nil
}

// requireConfirm checks for the --confirm flag and exits 1 with a helpful
// message if it was not provided.
func requireConfirm(confirmed bool, cmd *cobra.Command) {
	if !confirmed {
		fmt.Fprintf(os.Stderr, "This is a mutating operation. Add --confirm to proceed.\n")
		os.Exit(1)
	}
}

// renderOutput writes data to stdout in the format specified by gf.format.
func renderOutput(data interface{}) error {
	switch gf.format {
	case "json":
		return output.RenderJSON(os.Stdout, data)
	case "csv":
		return output.RenderCSV(os.Stdout, data)
	default:
		return output.RenderTable(os.Stdout, data)
	}
}

// handleError prints an error and calls os.Exit with the appropriate code.
// PendingApprovalError exits 2; all other errors exit 1.
func handleError(err error) {
	if err == nil {
		return
	}
	var pendErr *commands.PendingApprovalError
	if errors.As(err, &pendErr) {
		fmt.Println(pendErr.Error())
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}

// ── Root ─────────────────────────────────────────────────────────────────────

func buildRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "ja4proxy-cli",
		Short: "JA4proxy Management CLI — day-2 operations for SREs and security engineers",
		Long: `ja4proxy-cli provides terminal access to the JA4proxy Management API.

Token and URL can be supplied via flags or environment variables:
  JA4PROXY_URL    — Management API base URL
  JA4PROXY_TOKEN  — API bearer token`,
	}

	root.PersistentFlags().StringVar(&gf.url, "url", "", "Management API base URL (env: JA4PROXY_URL)")
	root.PersistentFlags().StringVar(&gf.token, "token", "", "API bearer token (env: JA4PROXY_TOKEN)")
	root.PersistentFlags().StringVar(&gf.format, "output", "table", "Output format: table|json|csv")

	root.AddCommand(buildIPCmd())
	root.AddCommand(buildAllowlistCmd())
	root.AddCommand(buildBlocklistCmd())
	root.AddCommand(buildDialCmd())
	root.AddCommand(buildConfigCmd())
	root.AddCommand(buildHealthCmd())
	root.AddCommand(buildFingerprintCmd())
	root.AddCommand(buildPolicyCmd())
	root.AddCommand(buildSimulationCmd())

	return root
}

// ── ip ────────────────────────────────────────────────────────────────────────

func buildIPCmd() *cobra.Command {
	ipCmd := &cobra.Command{
		Use:   "ip",
		Short: "IP address management (ban, release, watchlist, lookup)",
	}
	ipCmd.AddCommand(buildIPLookupCmd())
	ipCmd.AddCommand(buildIPBanCmd())
	ipCmd.AddCommand(buildIPReleaseCmd())
	ipCmd.AddCommand(buildIPWatchlistCmd())
	return ipCmd
}

func buildIPLookupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lookup <ip>",
		Short: "Show active ban and recent connections for an IP",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c, err := newClient()
			handleError(err)
			result, err := commands.RunIPLookup(cmd.Context(), c, args[0])
			handleError(err)
			handleError(output.RenderJSON(os.Stdout, result))
		},
	}
}

func buildIPBanCmd() *cobra.Command {
	var ttl int
	var reason string
	var confirm bool

	cmd := &cobra.Command{
		Use:   "ban <ip-or-cidr>",
		Short: "Ban an IP address or CIDR range",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			requireConfirm(confirm, cmd)
			c, err := newClient()
			handleError(err)
			result, err := commands.RunIPBan(cmd.Context(), c, args[0], ttl, reason)
			handleError(err)
			handleError(output.RenderJSON(os.Stdout, result))
		},
	}
	cmd.Flags().IntVar(&ttl, "ttl", 3600, "Ban duration in seconds")
	cmd.Flags().StringVar(&reason, "reason", "", "Reason for the ban")
	cmd.Flags().BoolVar(&confirm, "confirm", false, "Confirm the mutating operation")
	return cmd
}

func buildIPReleaseCmd() *cobra.Command {
	var confirm bool
	cmd := &cobra.Command{
		Use:   "release <ip-or-cidr>",
		Short: "Remove an active ban for an IP address or CIDR",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			requireConfirm(confirm, cmd)
			c, err := newClient()
			handleError(err)
			handleError(commands.RunIPRelease(cmd.Context(), c, args[0]))
			fmt.Printf("Ban released for %s\n", args[0])
		},
	}
	cmd.Flags().BoolVar(&confirm, "confirm", false, "Confirm the mutating operation")
	return cmd
}

func buildIPWatchlistCmd() *cobra.Command {
	watchlist := &cobra.Command{
		Use:   "watchlist",
		Short: "Manage the IP watchlist",
	}

	var addTTL int
	var addReason string
	addCmd := &cobra.Command{
		Use:   "add <ip>",
		Short: "Add an IP to the watchlist",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c, err := newClient()
			handleError(err)
			handleError(commands.RunWatchlistAdd(cmd.Context(), c, args[0], addTTL, addReason))
			fmt.Printf("Added %s to watchlist\n", args[0])
		},
	}
	addCmd.Flags().IntVar(&addTTL, "ttl", 86400, "Watch duration in seconds")
	addCmd.Flags().StringVar(&addReason, "reason", "", "Reason for watchlisting")

	var removeConfirm bool
	removeCmd := &cobra.Command{
		Use:   "remove <ip>",
		Short: "Remove an IP from the watchlist",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			requireConfirm(removeConfirm, cmd)
			c, err := newClient()
			handleError(err)
			handleError(commands.RunWatchlistRemove(cmd.Context(), c, args[0]))
			fmt.Printf("Removed %s from watchlist\n", args[0])
		},
	}
	removeCmd.Flags().BoolVar(&removeConfirm, "confirm", false, "Confirm the mutating operation")

	watchlist.AddCommand(addCmd, removeCmd)
	return watchlist
}

// ── allowlist ─────────────────────────────────────────────────────────────────

func buildAllowlistCmd() *cobra.Command {
	allowlist := &cobra.Command{
		Use:   "allowlist",
		Short: "Manage the JA4 fingerprint allowlist",
	}

	var addReason, addExpires, addTicket string
	addCmd := &cobra.Command{
		Use:   "add <ja4>",
		Short: "Add a JA4 fingerprint to the allowlist",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c, err := newClient()
			handleError(err)
			entry, err := commands.RunAllowlistAdd(cmd.Context(), c, args[0], addReason, addExpires, addTicket)
			handleError(err)
			handleError(output.RenderJSON(os.Stdout, entry))
		},
	}
	addCmd.Flags().StringVar(&addReason, "reason", "", "Reason for allowlisting")
	addCmd.Flags().StringVar(&addExpires, "expires", "", "Expiry date (ISO 8601)")
	addCmd.Flags().StringVar(&addTicket, "ticket", "", "Change ticket reference")

	var removeConfirm bool
	removeCmd := &cobra.Command{
		Use:   "remove <ja4>",
		Short: "Remove a JA4 fingerprint from the allowlist",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			requireConfirm(removeConfirm, cmd)
			c, err := newClient()
			handleError(err)
			handleError(commands.RunAllowlistRemove(cmd.Context(), c, args[0]))
			fmt.Printf("Removed %s from allowlist\n", args[0])
		},
	}
	removeCmd.Flags().BoolVar(&removeConfirm, "confirm", false, "Confirm the mutating operation")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all allowlist entries",
		Run: func(cmd *cobra.Command, _ []string) {
			c, err := newClient()
			handleError(err)
			items, err := commands.RunAllowlistList(cmd.Context(), c)
			handleError(err)
			handleError(renderOutput(items))
		},
	}

	allowlist.AddCommand(addCmd, removeCmd, listCmd)
	return allowlist
}

// ── blocklist ─────────────────────────────────────────────────────────────────

func buildBlocklistCmd() *cobra.Command {
	blocklist := &cobra.Command{
		Use:   "blocklist",
		Short: "Manage the JA4 fingerprint blocklist",
	}

	var addReason, addTicket string
	addCmd := &cobra.Command{
		Use:   "add <ja4>",
		Short: "Add a JA4 fingerprint to the blocklist",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c, err := newClient()
			handleError(err)
			entry, err := commands.RunBlocklistAdd(cmd.Context(), c, args[0], addReason, addTicket)
			handleError(err)
			handleError(output.RenderJSON(os.Stdout, entry))
		},
	}
	addCmd.Flags().StringVar(&addReason, "reason", "", "Reason for blocklisting")
	addCmd.Flags().StringVar(&addTicket, "ticket", "", "Incident ticket reference")

	var removeConfirm bool
	removeCmd := &cobra.Command{
		Use:   "remove <ja4>",
		Short: "Remove a JA4 fingerprint from the blocklist",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			requireConfirm(removeConfirm, cmd)
			c, err := newClient()
			handleError(err)
			handleError(commands.RunBlocklistRemove(cmd.Context(), c, args[0]))
			fmt.Printf("Removed %s from blocklist\n", args[0])
		},
	}
	removeCmd.Flags().BoolVar(&removeConfirm, "confirm", false, "Confirm the mutating operation")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all blocklist entries",
		Run: func(cmd *cobra.Command, _ []string) {
			c, err := newClient()
			handleError(err)
			items, err := commands.RunBlocklistList(cmd.Context(), c)
			handleError(err)
			handleError(renderOutput(items))
		},
	}

	blocklist.AddCommand(addCmd, removeCmd, listCmd)
	return blocklist
}

// ── dial ─────────────────────────────────────────────────────────────────────

func buildDialCmd() *cobra.Command {
	dialCmd := &cobra.Command{
		Use:   "dial",
		Short: "Get or set the scoring dial (0=monitor, 100=full enforcement)",
	}

	getCmd := &cobra.Command{
		Use:   "get",
		Short: "Show the current dial setting",
		Run: func(cmd *cobra.Command, _ []string) {
			c, err := newClient()
			handleError(err)
			dv, err := commands.RunDialGet(cmd.Context(), c)
			handleError(err)
			handleError(renderOutput([]commands.DialValue{*dv}))
		},
	}

	var setTicket, setNotes string
	var setConfirm bool
	setCmd := &cobra.Command{
		Use:   "set <0-100>",
		Short: "Update the dial setting",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			requireConfirm(setConfirm, cmd)
			var setting int
			if _, err := fmt.Sscanf(args[0], "%d", &setting); err != nil || setting < 0 || setting > 100 {
				fmt.Fprintln(os.Stderr, "Error: dial setting must be an integer 0–100")
				os.Exit(1)
			}
			c, err := newClient()
			handleError(err)
			handleError(commands.RunDialSet(cmd.Context(), c, setting, setTicket, setNotes))
			fmt.Printf("Dial set to %d\n", setting)
		},
	}
	setCmd.Flags().StringVar(&setTicket, "ticket", "", "Change ticket reference")
	setCmd.Flags().StringVar(&setNotes, "notes", "", "Change rationale notes")
	setCmd.Flags().BoolVar(&setConfirm, "confirm", false, "Confirm the mutating operation")

	dialCmd.AddCommand(getCmd, setCmd)
	return dialCmd
}

// ── config ────────────────────────────────────────────────────────────────────

func buildConfigCmd() *cobra.Command {
	var node string
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration management",
	}
	reloadCmd := &cobra.Command{
		Use:   "reload",
		Short: "Trigger a configuration reload on one or all proxy nodes",
		Run: func(cmd *cobra.Command, _ []string) {
			c, err := newClient()
			handleError(err)
			handleError(commands.RunConfigReload(cmd.Context(), c, node))
			if node != "" {
				fmt.Printf("Config reloaded on %s\n", node)
			} else {
				fmt.Println("Config reloaded on all nodes")
			}
		},
	}
	reloadCmd.Flags().StringVar(&node, "node", "", "Specific node hostname (default: all nodes)")
	cmd.AddCommand(reloadCmd)
	return cmd
}

// ── health ────────────────────────────────────────────────────────────────────

func buildHealthCmd() *cobra.Command {
	var allNodes bool
	cmd := &cobra.Command{
		Use:   "health",
		Short: "Show proxy node health status",
		Run: func(cmd *cobra.Command, _ []string) {
			c, err := newClient()
			handleError(err)
			nodes, err := commands.RunHealth(cmd.Context(), c, allNodes)
			handleError(err)
			handleError(renderOutput(nodes))
		},
	}
	cmd.Flags().BoolVar(&allNodes, "all-nodes", false, "Show health for all cluster nodes")
	return cmd
}

// ── fingerprint ───────────────────────────────────────────────────────────────

func buildFingerprintCmd() *cobra.Command {
	var history string
	cmd := &cobra.Command{
		Use:   "fingerprint <ja4>",
		Short: "Show connection history for a JA4 fingerprint",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c, err := newClient()
			handleError(err)
			items, err := commands.RunFingerprintHistory(cmd.Context(), c, args[0], history)
			handleError(err)
			handleError(output.RenderJSON(os.Stdout, items))
		},
	}
	cmd.Flags().StringVar(&history, "history", "", "Time range filter (e.g. 30d)")
	return cmd
}

// ── policy ────────────────────────────────────────────────────────────────────

func buildPolicyCmd() *cobra.Command {
	policyCmd := &cobra.Command{
		Use:   "policy",
		Short: "Policy-as-code operations (validate, apply, diff)",
	}

	var validateFile string
	var validateCurrentDial int
	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a policy YAML file offline (no API calls)",
		Run: func(cmd *cobra.Command, _ []string) {
			if validateFile == "" {
				fmt.Fprintln(os.Stderr, "Error: --file is required")
				os.Exit(1)
			}
			yamlText, err := os.ReadFile(validateFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", validateFile, err)
				os.Exit(1)
			}
			if err := commands.RunPolicyValidate(string(yamlText), validateCurrentDial); err != nil {
				fmt.Fprintln(os.Stderr, "Error:", err)
				os.Exit(1)
			}
			fmt.Println("Policy is valid.")
		},
	}
	validateCmd.Flags().StringVar(&validateFile, "file", "", "Path to policy YAML file")
	validateCmd.Flags().IntVar(&validateCurrentDial, "current-dial", 0, "Current dial setting for increase validation")

	var applyFile string
	var applyDryRun bool
	var applyURL, applyToken string
	applyCmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a policy YAML file to the Management API",
		Run: func(cmd *cobra.Command, _ []string) {
			if applyFile == "" {
				fmt.Fprintln(os.Stderr, "Error: --file is required")
				os.Exit(1)
			}
			yamlText, err := os.ReadFile(applyFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", applyFile, err)
				os.Exit(1)
			}
			policyDict, err := commands.ValidatePolicy(string(yamlText), 0)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Validation error:", err)
				os.Exit(1)
			}
			if applyDryRun {
				fmt.Println("Dry run — policy is valid, no changes applied.")
				return
			}
			resolvedURL := auth.ResolveURL(applyURL)
			if resolvedURL == "" {
				resolvedURL = auth.ResolveURL(gf.url)
			}
			resolvedToken := auth.ResolveToken(applyToken)
			if resolvedToken == "" {
				resolvedToken = auth.ResolveToken(gf.token)
			}
			if resolvedURL == "" {
				fmt.Fprintln(os.Stderr, "Error: --url or JA4PROXY_URL is required for apply")
				os.Exit(1)
			}
			c := client.New(resolvedURL, resolvedToken)
			handleError(commands.RunPolicyApply(cmd.Context(), c, policyDict))
		},
	}
	applyCmd.Flags().StringVar(&applyFile, "file", "", "Path to policy YAML file")
	applyCmd.Flags().BoolVar(&applyDryRun, "dry-run", false, "Validate and report without making API calls")
	applyCmd.Flags().StringVar(&applyURL, "url", "", "Management API base URL")
	applyCmd.Flags().StringVar(&applyToken, "token", "", "API bearer token")

	var diffFile string
	var diffURL, diffToken string
	diffCmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare policy YAML against live API state (exit 0=no drift, 1=drift)",
		Run: func(cmd *cobra.Command, _ []string) {
			if diffFile == "" {
				fmt.Fprintln(os.Stderr, "Error: --file is required")
				os.Exit(1)
			}
			yamlText, err := os.ReadFile(diffFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", diffFile, err)
				os.Exit(1)
			}
			policyDict, err := commands.ValidatePolicy(string(yamlText), 0)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Validation error:", err)
				os.Exit(1)
			}
			resolvedURL := auth.ResolveURL(diffURL)
			if resolvedURL == "" {
				resolvedURL = auth.ResolveURL(gf.url)
			}
			resolvedToken := auth.ResolveToken(diffToken)
			if resolvedToken == "" {
				resolvedToken = auth.ResolveToken(gf.token)
			}
			if resolvedURL == "" {
				fmt.Fprintln(os.Stderr, "Error: --url or JA4PROXY_URL is required for diff")
				os.Exit(1)
			}
			c := client.New(resolvedURL, resolvedToken)
			drift, err := commands.RunPolicyDiff(cmd.Context(), c, policyDict)
			handleError(err)
			if len(drift) == 0 {
				fmt.Println("No drift detected.")
				return
			}
			fmt.Printf("Drift detected: %d unexpected entries\n", len(drift))
			for _, entry := range drift {
				if m, ok := entry.(map[string]interface{}); ok {
					fmt.Printf("  [%s] %s  managed_by=%s\n",
						m["resource_type"], m["identifier"], m["managed_by"])
				}
			}
			os.Exit(1)
		},
	}
	diffCmd.Flags().StringVar(&diffFile, "file", "", "Path to policy YAML file")
	diffCmd.Flags().StringVar(&diffURL, "url", "", "Management API base URL")
	diffCmd.Flags().StringVar(&diffToken, "token", "", "API bearer token")

	policyCmd.AddCommand(validateCmd, applyCmd, diffCmd)
	return policyCmd
}

// ── simulation ────────────────────────────────────────────────────────────────

func buildSimulationCmd() *cobra.Command {
	simCmd := &cobra.Command{
		Use:   "simulation",
		Short: "Traffic simulation commands (requires Phase 100-M)",
	}

	simCmd.AddCommand(&cobra.Command{
		Use:   "run",
		Short: "Run a simulation (not yet available)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return commands.RunSimulationRun()
		},
	})
	simCmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Check simulation status (not yet available)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return commands.RunSimulationStatus()
		},
	})
	simCmd.AddCommand(&cobra.Command{
		Use:   "report",
		Short: "Generate simulation report (not yet available)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return commands.RunSimulationReport()
		},
	})

	return simCmd
}
