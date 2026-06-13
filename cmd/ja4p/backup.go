package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/seanpor/ja4proxy/internal/backup"
	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/redis"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// buildBackupCmd assembles the `ja4p backup` command group: a default action
// that snapshots Redis security state into an encrypted artifact, plus an
// offline `inspect` subcommand.
//
// Grounding note (Phase 315a): the original plan said `ja4pd backup`, but
// `ja4pd` is the long-running proxy daemon with no subcommand dispatch. The
// cobra CLI lives in `ja4p`, so the backup subcommands belong here.
func buildBackupCmd() *cobra.Command {
	var (
		dir            string
		keyFile        string
		key            string
		retentionCount int
		retentionDays  int
		metricsFile    string
	)

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Create an encrypted snapshot of Redis security state",
		Long: "Snapshots the durable security-state Redis keys (bans, dial, allow/block\n" +
			"lists, audit logs, fingerprints) into an AES-256-GCM-encrypted artifact and\n" +
			"emits the ja4proxy_backup_* metrics. Credential/session/MFA keys are excluded.\n" +
			"The passphrase comes from --key-file, --key, or $JA4PROXY_BACKUP_KEY.",
		RunE: func(cmd *cobra.Command, args []string) error {
			passphrase, err := resolvePassphrase(keyFile, key)
			if err != nil {
				return err
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			log := logrus.New()
			rc := redis.New(redisConfigFrom(cfg), log)
			defer rc.Close()

			eng := backup.New(rc.Raw(), backup.Config{
				Dir:             dir,
				KeyPrefixes:     backup.DefaultKeyPrefixes,
				ExcludePrefixes: backup.DefaultExcludePrefixes,
				RetentionCount:  retentionCount,
				RetentionDays:   retentionDays,
				Passphrase:      passphrase,
				ProxyVersion:    config.Version,
				ConfigHash:      configHash(cfgPath),
			}, log, backup.PromMetrics{})

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			res, err := eng.Backup(ctx)
			if err != nil {
				return fmt.Errorf("backup failed: %w", err)
			}
			if metricsFile != "" {
				if werr := writeBackupTextfile(metricsFile, res); werr != nil {
					// Metric emission must not fail the backup itself.
					fmt.Fprintf(os.Stderr, "warning: writing metrics textfile: %v\n", werr)
				}
			}
			fmt.Printf("✓ Backup written: %s (%d keys, %s)\n", res.Path, res.KeyCount, res.Duration().Round(time.Millisecond))
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "/var/lib/ja4proxy/backups", "Destination directory for the artifact")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "File containing the encryption passphrase")
	cmd.Flags().StringVar(&key, "key", "", "Encryption passphrase (prefer --key-file or $JA4PROXY_BACKUP_KEY)")
	cmd.Flags().IntVar(&retentionCount, "retention-count", 7, "Keep at most N newest artifacts (0 = unlimited)")
	cmd.Flags().IntVar(&retentionDays, "retention-days", 30, "Delete artifacts older than N days (0 = unlimited)")
	cmd.Flags().StringVar(&metricsFile, "metrics-textfile", "", "Write a node-exporter .prom textfile here")

	cmd.AddCommand(buildBackupInspectCmd())
	return cmd
}

// buildBackupInspectCmd decrypts an artifact and prints its manifest + per-prefix
// key breakdown, without contacting Redis.
func buildBackupInspectCmd() *cobra.Command {
	var keyFile, key string
	cmd := &cobra.Command{
		Use:   "inspect <artifact>",
		Short: "Decrypt and print a backup artifact's metadata (no Redis needed)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			passphrase, err := resolvePassphrase(keyFile, key)
			if err != nil {
				return err
			}
			man, counts, err := backup.Inspect(args[0], passphrase)
			if err != nil {
				return err
			}
			fmt.Printf("Created:        %s\n", man.CreatedAt.Format(time.RFC3339))
			fmt.Printf("Schema version: %d\n", man.SchemaVersion)
			fmt.Printf("Proxy version:  %s\n", man.ProxyVersion)
			fmt.Printf("Config hash:    %s\n", man.ConfigHash)
			fmt.Printf("Key count:      %d\n", man.KeyCount)
			fmt.Println("By prefix:")
			for _, p := range sortedKeys(counts) {
				fmt.Printf("  %-28s %d\n", p+":*", counts[p])
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&keyFile, "key-file", "", "File containing the decryption passphrase")
	cmd.Flags().StringVar(&key, "key", "", "Decryption passphrase (prefer --key-file or $JA4PROXY_BACKUP_KEY)")
	return cmd
}

// resolvePassphrase resolves the backup passphrase from, in order: --key,
// --key-file, then $JA4PROXY_BACKUP_KEY.
func resolvePassphrase(keyFile, key string) (string, error) {
	if key != "" {
		return key, nil
	}
	if keyFile != "" {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return "", fmt.Errorf("reading key file: %w", err)
		}
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, nil
		}
		return "", fmt.Errorf("key file %q is empty", keyFile)
	}
	if env := strings.TrimSpace(os.Getenv("JA4PROXY_BACKUP_KEY")); env != "" {
		return env, nil
	}
	return "", fmt.Errorf("no passphrase: set --key-file, --key, or $JA4PROXY_BACKUP_KEY")
}

// configHash returns the SHA-256 of the config file, recorded in the manifest so
// restore (315b) can warn on config drift.
func configHash(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// redisConfigFrom maps the loaded proxy config to a redis.Config (mirrors the
// sync-agent wiring in main.go).
func redisConfigFrom(cfg *config.Config) redis.Config {
	return redis.Config{
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
}

// writeBackupTextfile atomically writes a node-exporter textfile-collector .prom
// reflecting the just-completed backup (currently_running back to 0).
func writeBackupTextfile(path string, res *backup.Result) error {
	var b strings.Builder
	b.WriteString("# HELP ja4proxy_backup_last_success_seconds Unix time of the last successful backup.\n")
	b.WriteString("# TYPE ja4proxy_backup_last_success_seconds gauge\n")
	fmt.Fprintf(&b, "ja4proxy_backup_last_success_seconds %d\n", res.FinishedAt.Unix())
	b.WriteString("# HELP ja4proxy_backup_currently_running 1 while a backup is running, else 0.\n")
	b.WriteString("# TYPE ja4proxy_backup_currently_running gauge\n")
	b.WriteString("ja4proxy_backup_currently_running 0\n")
	b.WriteString("# HELP ja4proxy_backup_operations_total Backup operations by outcome.\n")
	b.WriteString("# TYPE ja4proxy_backup_operations_total counter\n")
	fmt.Fprintf(&b, "ja4proxy_backup_operations_total{status=\"success\"} 1\n")

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// simple insertion sort to avoid importing sort for a tiny slice
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
