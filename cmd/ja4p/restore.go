package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/seanpor/ja4proxy/internal/backup"
	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/redis"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// buildRestoreCmd assembles `ja4p restore` (phase-315b) — the dangerous half.
// Defaults are safe: allow-state only, no clobber, real write. Block-state and
// flushing are opt-in; GDPR-erased subjects are never resurrected.
func buildRestoreCmd() *cobra.Command {
	var (
		keyFile       string
		key           string
		includeBlocks bool
		force         bool
		dryRun        bool
		tombstoneFile string
	)
	cmd := &cobra.Command{
		Use:   "restore <artifact>",
		Short: "Restore an encrypted backup into Redis (selective, GDPR-aware)",
		Long: "Loads a `ja4p backup` artifact back into Redis SAFELY. By default only\n" +
			"allow-state is restored — block-state (bans, blacklists, the dial) needs\n" +
			"--include-blocks so a restore can never mass-re-block real users. A\n" +
			"GDPR-erased subject is never resurrected. A non-empty target needs --force\n" +
			"(which FLUSHes first); --dry-run reports what would happen and writes nothing.",
		Args: cobra.ExactArgs(1),
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

			eng := backup.New(rc.Raw(), backup.Config{}, log, nil)

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			res, err := eng.Restore(ctx, args[0], backup.RestoreOptions{
				Passphrase:    passphrase,
				IncludeBlocks: includeBlocks,
				Force:         force,
				DryRun:        dryRun,
				TombstoneFile: tombstoneFile,
				Actor:         "ja4p restore",
				ProxyVersion:  config.Version,
				ConfigHash:    configHash(cfgPath),
			}, backup.RestorePromMetrics{})
			if err != nil {
				return fmt.Errorf("restore failed: %w", err)
			}

			verb := "Restored"
			if res.DryRun {
				verb = "[dry-run] would restore"
			}
			fmt.Printf("✓ %s %d keys (skipped %d block-state, %d GDPR-erased) in %s\n",
				verb, res.Restored, res.SkippedBlocks, res.SkippedErased, res.Duration().Round(1e6))
			if res.SkippedBlocks > 0 && !includeBlocks {
				fmt.Println("  Note: block-state (bans/blacklists/dial) was gated. Re-run with --include-blocks to restore it.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&keyFile, "key-file", "", "File containing the decryption passphrase")
	cmd.Flags().StringVar(&key, "key", "", "Decryption passphrase (prefer --key-file or $JA4PROXY_BACKUP_KEY)")
	cmd.Flags().BoolVar(&includeBlocks, "include-blocks", false, "Also restore block-state (bans, blacklists, dial) — can re-block users")
	cmd.Flags().BoolVar(&force, "force", false, "FLUSH a non-empty target before restoring")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Report what would change; write nothing")
	cmd.Flags().StringVar(&tombstoneFile, "tombstone-file", "", "File of IPs that must never be resurrected (merged with the live erasure log)")
	return cmd
}
