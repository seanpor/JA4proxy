"""
Backup CLI module.
Implements backup, restore, list, and validate commands.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from src.backup.restorer import BackupRestorer, RestoreError
from src.backup.worker import BackupWorker
from src.config.loader import ConfigLoader


class BackupCLI:
    """CLI interface for backup and restore operations."""

    def __init__(self):
        """Initialize Backup CLI."""
        self.worker = BackupWorker()
        self.restorer = BackupRestorer()
        self.config_loader = ConfigLoader()

    def backup_command(self, args) -> int:
        """Execute backup command.

        Args:
            args: Parsed command line arguments.

        Returns:
            Exit code (0 for success, non-zero for failure).
        """
        try:
            # Load config to get backup settings
            config = self.config_loader._read_and_parse()
            backup_config = config.get("backup", {})

            destination_dir = args.destination or backup_config.get(
                "destination", "/app/backups"
            )

            # Create backup
            backup_path = self.worker.create_backup(destination_dir)

            print(f"Backup created successfully: {backup_path}")
            return 0

        except Exception as e:
            print(f"Backup failed: {e}", file=sys.stderr)
            return 1

    def restore_command(self, args) -> int:
        """Execute restore command.

        Args:
            args: Parsed command line arguments.

        Returns:
            Exit code (0 for success, non-zero for failure).
        """
        try:
            # Validate backup file exists
            if not os.path.exists(args.backup_file):
                print(f"Backup file not found: {args.backup_file}", file=sys.stderr)
                return 1

            # Validate manifest file exists
            manifest_file = f"{args.backup_file}.manifest.json"
            if not os.path.exists(manifest_file):
                print(f"Manifest file not found: {manifest_file}", file=sys.stderr)
                return 1

            # Perform restore
            self.restorer.restore_backup(
                args.backup_file, manifest_file, destructive=args.force
            )

            restore_type = "destructive" if args.force else "non-destructive"
            print(f"Restore completed successfully ({restore_type} mode)")
            return 0

        except RestoreError as e:
            print(f"Restore failed: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Unexpected restore error: {e}", file=sys.stderr)
            return 1

    def list_command(self, args) -> int:
        """Execute backup list command.

        Args:
            args: Parsed command line arguments.

        Returns:
            Exit code (0 for success, non-zero for failure).
        """
        try:
            # Load config to get backup directory
            config = self.config_loader._read_and_parse()
            backup_config = config.get("backup", {})

            backup_dir = args.directory or backup_config.get(
                "destination", "/app/backups"
            )

            if not os.path.exists(backup_dir):
                print(f"Backup directory not found: {backup_dir}", file=sys.stderr)
                return 1

            # Find all backup files
            backup_files = list(Path(backup_dir).glob("backup_*.bin"))

            if not backup_files:
                print("No backups found")
                return 0

            # Sort by modification time (newest first)
            backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)

            print(f"Found {len(backup_files)} backups in {backup_dir}:")
            print("-" * 80)

            for backup_file in backup_files:
                manifest_file = backup_file.with_suffix(
                    backup_file.suffix + ".manifest.json"
                )

                if manifest_file.exists():
                    try:
                        with open(manifest_file, "r") as f:
                            manifest = json.load(f)

                        created_at = manifest.get("created_at", "unknown")
                        keys_count = manifest.get("keys_count", 0)
                        size_bytes = manifest.get("size_bytes", 0)

                        print(
                            f"{backup_file.name:40} {created_at:26} {keys_count:6} keys {size_bytes:10} bytes"
                        )
                    except (json.JSONDecodeError, OSError):
                        print(f"{backup_file.name:40} (corrupted manifest)")
                else:
                    print(f"{backup_file.name:40} (missing manifest)")

            return 0

        except Exception as e:
            print(f"List command failed: {e}", file=sys.stderr)
            return 1

    def validate_command(self, args) -> int:
        """Execute backup validate command.

        Args:
            args: Parsed command line arguments.

        Returns:
            Exit code (0 for success, non-zero for failure).
        """
        try:
            # Validate backup file exists
            if not os.path.exists(args.backup_file):
                print(f"Backup file not found: {args.backup_file}", file=sys.stderr)
                return 1

            # Validate manifest file exists
            manifest_file = f"{args.backup_file}.manifest.json"
            if not os.path.exists(manifest_file):
                print(f"Manifest file not found: {manifest_file}", file=sys.stderr)
                return 1

            # Load and validate manifest
            manifest = self.restorer.load_manifest(manifest_file)
            print(f"Manifest validated successfully: {manifest['filename']}")

            # Verify checksum
            checksum_valid = self.restorer.verify_checksum(
                args.backup_file, manifest["checksum_sha256"]
            )

            if checksum_valid:
                print("Checksum verification passed")
                return 0
            else:
                print("Checksum verification failed", file=sys.stderr)
                return 1

        except RestoreError as e:
            print(f"Validation failed: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Unexpected validation error: {e}", file=sys.stderr)
            return 1

    def run(self, argv: Optional[List[str]] = None) -> int:
        """Run backup CLI.

        Args:
            argv: Command line arguments (None for sys.argv).

        Returns:
            Exit code.
        """
        parser = argparse.ArgumentParser(
            description="JA4proxy Backup CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        # Backup command
        backup_parser = subparsers.add_parser("backup", help="Create a new backup")
        backup_parser.add_argument(
            "--destination", help="Backup destination directory (defaults to config)"
        )
        backup_parser.set_defaults(func=self.backup_command)

        # Restore command
        restore_parser = subparsers.add_parser("restore", help="Restore from backup")
        restore_parser.add_argument("backup_file", help="Path to backup file (.bin)")
        restore_parser.add_argument(
            "--force",
            action="store_true",
            help="Perform destructive restore (wipes existing data)",
        )
        restore_parser.set_defaults(func=self.restore_command)

        # List command
        list_parser = subparsers.add_parser("list", help="List available backups")
        list_parser.add_argument(
            "--directory", help="Backup directory to list (defaults to config)"
        )
        list_parser.set_defaults(func=self.list_command)

        # Validate command
        validate_parser = subparsers.add_parser(
            "validate", help="Validate backup integrity"
        )
        validate_parser.add_argument(
            "backup_file", help="Path to backup file to validate (.bin)"
        )
        validate_parser.set_defaults(func=self.validate_command)

        try:
            args = parser.parse_args(argv)

            if hasattr(args, "func"):
                return args.func(args)
            else:
                # No command provided
                parser.print_help()
                return 1

        except Exception as e:
            print(f"CLI error: {e}", file=sys.stderr)
            return 1


def main() -> int:
    """Main entry point for backup CLI."""
    cli = BackupCLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())
