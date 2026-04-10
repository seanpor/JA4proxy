#!/usr/bin/env python3
"""ja4proxy-admin — CLI for JA4proxy operational management.

Reads REDIS_URL from the environment. All destructive commands require --confirm.

Usage:
    export REDIS_URL=redis://:password@localhost:6379/0
    python3 scripts/ja4proxy_admin.py status
    python3 scripts/ja4proxy_admin.py ban 1.2.3.4 --ttl 86400
    python3 scripts/ja4proxy_admin.py dial set 75 --acknowledge-blocking
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any

import click
import redis as redis_lib

# ---------------------------------------------------------------------------
# Redis connection
# ---------------------------------------------------------------------------


def _get_redis() -> redis_lib.Redis:  # type: ignore[type-arg]
    url = os.environ.get("REDIS_URL")
    if not url:
        click.echo(
            "ERROR: REDIS_URL environment variable is not set.\n"
            "Example: export REDIS_URL=redis://:password@localhost:6379/0",
            err=True,
        )
        sys.exit(1)
    try:
        client = redis_lib.from_url(url, decode_responses=True)
        client.ping()
        return client
    except redis_lib.ConnectionError as exc:
        click.echo(f"ERROR: Cannot connect to Redis at {url}: {exc}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _output(data: Any, fmt: str) -> None:
    if fmt == "json":
        click.echo(json.dumps(data, indent=2, default=str))
    else:
        if isinstance(data, dict):
            for k, v in data.items():
                click.echo(f"  {k:<30} {v}")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    click.echo("  " + "  ".join(f"{k}={v}" for k, v in item.items()))
                else:
                    click.echo(f"  {item}")
        else:
            click.echo(f"  {data}")


def _confirm_required(action: str) -> None:
    click.echo(f"WARNING: {action}", err=True)
    click.echo("Re-run with --confirm to proceed.", err=True)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@click.group()
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.pass_context
def cli(ctx: click.Context, fmt: str) -> None:
    """JA4proxy operational management CLI.

    Reads REDIS_URL from environment. Destructive commands require --confirm.
    """
    ctx.ensure_object(dict)
    ctx.obj["fmt"] = fmt


# ---------------------------------------------------------------------------
# ban / unban
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("ip")
@click.option("--ttl", default=3600, show_default=True, help="Ban TTL in seconds (0 = permanent).")
@click.option("--reason", default="manual-admin-ban", show_default=True)
@click.option("--confirm", is_flag=True, default=False)
@click.pass_context
def ban(ctx: click.Context, ip: str, ttl: int, reason: str, confirm: bool) -> None:
    """Ban an IP address."""
    if not confirm:
        _confirm_required(f"This will ban {ip} for {ttl}s (reason={reason}).")
    r = _get_redis()
    key = f"ban:{ip}"
    if ttl > 0:
        r.set(key, reason, ex=ttl)
    else:
        r.set(key, reason)
    result = {"ip": ip, "key": key, "ttl": ttl if ttl > 0 else "permanent", "reason": reason}
    click.echo(f"Banned {ip}.")
    _output(result, ctx.obj["fmt"])


@cli.command()
@click.argument("ip")
@click.option("--confirm", is_flag=True, default=False)
@click.pass_context
def unban(ctx: click.Context, ip: str, confirm: bool) -> None:
    """Remove an IP ban."""
    if not confirm:
        _confirm_required(f"This will remove the ban on {ip}.")
    r = _get_redis()
    deleted = r.delete(f"ban:{ip}")
    result = {"ip": ip, "deleted": bool(deleted)}
    click.echo(f"Unbanned {ip} ({'was banned' if deleted else 'was not banned'}).")
    _output(result, ctx.obj["fmt"])


# ---------------------------------------------------------------------------
# dial
# ---------------------------------------------------------------------------


@cli.group()
def dial() -> None:
    """Get or set the blocking dial (0=monitor-only, 100=full blocking)."""


@dial.command("get")
@click.pass_context
def dial_get(ctx: click.Context) -> None:
    """Show current dial value."""
    r = _get_redis()
    value = r.get("config:dial") or "0"
    result = {"dial": int(value)}
    _output(result, ctx.obj["fmt"])


@dial.command("set")
@click.argument("value", type=click.IntRange(0, 100))
@click.option("--acknowledge-blocking", is_flag=True, default=False,
              help="Required when setting dial > 0 to confirm you accept blocking risk.")
@click.option("--confirm", is_flag=True, default=False)
@click.pass_context
def dial_set(ctx: click.Context, value: int, acknowledge_blocking: bool, confirm: bool) -> None:
    """Set the dial value (0–100)."""
    if value > 0 and not acknowledge_blocking:
        click.echo(
            "ERROR: Dial > 0 will cause the proxy to block connections.\n"
            "Re-run with --acknowledge-blocking to proceed.",
            err=True,
        )
        sys.exit(1)
    if not confirm:
        _confirm_required(f"This will set the dial to {value}.")
    r = _get_redis()
    r.set("config:dial", str(value))
    result = {"dial": value}
    click.echo(f"Dial set to {value}.")
    _output(result, ctx.obj["fmt"])


# ---------------------------------------------------------------------------
# whitelist / blacklist
# ---------------------------------------------------------------------------


@cli.group()
def whitelist() -> None:
    """Manage the JA4 fingerprint whitelist."""


@whitelist.command("add")
@click.argument("ja4")
@click.option("--confirm", is_flag=True, default=False)
@click.pass_context
def whitelist_add(ctx: click.Context, ja4: str, confirm: bool) -> None:
    """Add a JA4 fingerprint to the whitelist."""
    if not confirm:
        _confirm_required(f"Adding {ja4} to whitelist — connections with this fingerprint will bypass scoring.")
    r = _get_redis()
    r.sadd("ja4:whitelist", ja4)
    click.echo(f"Added {ja4} to whitelist.")
    _output({"ja4": ja4, "list": "whitelist", "action": "added"}, ctx.obj["fmt"])


@whitelist.command("remove")
@click.argument("ja4")
@click.option("--confirm", is_flag=True, default=False)
@click.pass_context
def whitelist_remove(ctx: click.Context, ja4: str, confirm: bool) -> None:
    """Remove a JA4 fingerprint from the whitelist."""
    if not confirm:
        _confirm_required(f"Removing {ja4} from whitelist.")
    r = _get_redis()
    removed = r.srem("ja4:whitelist", ja4)
    click.echo(f"{'Removed' if removed else 'Not found'}: {ja4} in whitelist.")
    _output({"ja4": ja4, "list": "whitelist", "action": "removed", "was_present": bool(removed)}, ctx.obj["fmt"])


@whitelist.command("list")
@click.pass_context
def whitelist_list(ctx: click.Context) -> None:
    """List all JA4 fingerprints in the whitelist."""
    r = _get_redis()
    members = sorted(r.smembers("ja4:whitelist"))
    _output(list(members), ctx.obj["fmt"])


@cli.group()
def blacklist() -> None:
    """Manage the JA4 fingerprint blacklist."""


@blacklist.command("add")
@click.argument("ja4")
@click.option("--confirm", is_flag=True, default=False)
@click.pass_context
def blacklist_add(ctx: click.Context, ja4: str, confirm: bool) -> None:
    """Add a JA4 fingerprint to the blacklist (immediate RST on match)."""
    if not confirm:
        _confirm_required(f"Adding {ja4} to blacklist — connections with this fingerprint will be blocked.")
    r = _get_redis()
    r.sadd("ja4:blacklist", ja4)
    click.echo(f"Added {ja4} to blacklist.")
    _output({"ja4": ja4, "list": "blacklist", "action": "added"}, ctx.obj["fmt"])


@blacklist.command("remove")
@click.argument("ja4")
@click.option("--confirm", is_flag=True, default=False)
@click.pass_context
def blacklist_remove(ctx: click.Context, ja4: str, confirm: bool) -> None:
    """Remove a JA4 fingerprint from the blacklist."""
    if not confirm:
        _confirm_required(f"Removing {ja4} from blacklist.")
    r = _get_redis()
    removed = r.srem("ja4:blacklist", ja4)
    click.echo(f"{'Removed' if removed else 'Not found'}: {ja4} in blacklist.")
    _output({"ja4": ja4, "list": "blacklist", "action": "removed", "was_present": bool(removed)}, ctx.obj["fmt"])


@blacklist.command("list")
@click.pass_context
def blacklist_list(ctx: click.Context) -> None:
    """List all JA4 fingerprints in the blacklist."""
    r = _get_redis()
    members = sorted(r.smembers("ja4:blacklist"))
    _output(list(members), ctx.obj["fmt"])


# ---------------------------------------------------------------------------
# suspect
# ---------------------------------------------------------------------------


@cli.group()
def suspect() -> None:
    """Inspect the beaconing suspects leaderboard."""


@suspect.command("list")
@click.option("--top", default=20, show_default=True, help="Number of top suspects to show.")
@click.pass_context
def suspect_list(ctx: click.Context, top: int) -> None:
    """List the top beaconing suspects by confidence score."""
    r = _get_redis()
    entries = r.zrevrange("beacon:suspects", 0, top - 1, withscores=True)
    results = [{"suspect": member, "confidence": round(score, 4)} for member, score in entries]
    if not results:
        click.echo("No beaconing suspects found.")
    _output(results, ctx.obj["fmt"])


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------


@cli.group()
def inspect() -> None:
    """Inspect all Redis state for an IP or JA4 fingerprint."""


@inspect.command("ip")
@click.argument("ip")
@click.pass_context
def inspect_ip(ctx: click.Context, ip: str) -> None:
    """Show all Redis keys and values for a given IP address."""
    r = _get_redis()
    result: dict[str, Any] = {"ip": ip}

    ban_val = r.get(f"ban:{ip}")
    result["ban"] = ban_val or None
    if ban_val:
        ttl = r.ttl(f"ban:{ip}")
        result["ban_ttl_seconds"] = ttl

    visitor = r.hgetall(f"visitor:{ip}")
    result["visitor"] = visitor or None

    abuseipdb = r.get(f"abuseipdb:score:{ip}")
    result["abuseipdb_score"] = int(abuseipdb) if abuseipdb else None

    rdap = r.hgetall(f"rdap:{ip}")
    result["rdap"] = rdap or None

    beacon_keys = r.keys(f"beacon:{ip}:*")
    result["beacon_windows"] = len(beacon_keys)

    # Rate limiting windows
    rate_keys = r.keys(f"rate:{ip}:*")
    result["active_rate_windows"] = len(rate_keys)

    _output(result, ctx.obj["fmt"])


@inspect.command("ja4")
@click.argument("ja4")
@click.pass_context
def inspect_ja4(ctx: click.Context, ja4: str) -> None:
    """Show whitelist/blacklist/suspect status for a JA4 fingerprint."""
    r = _get_redis()
    in_whitelist = bool(r.sismember("ja4:whitelist", ja4))
    in_blacklist = bool(r.sismember("ja4:blacklist", ja4))
    candidate_score = r.zscore("analytics:ja4:candidates", ja4)

    result = {
        "ja4": ja4,
        "whitelist": in_whitelist,
        "blacklist": in_blacklist,
        "candidate_score": candidate_score,
    }
    _output(result, ctx.obj["fmt"])


# ---------------------------------------------------------------------------
# flush
# ---------------------------------------------------------------------------


@cli.group()
def flush() -> None:
    """Clear cached data for a specific IP."""


@flush.command("abuseipdb")
@click.argument("ip")
@click.option("--confirm", is_flag=True, default=False)
@click.pass_context
def flush_abuseipdb(ctx: click.Context, ip: str, confirm: bool) -> None:
    """Clear the cached AbuseIPDB score for an IP (forces fresh lookup)."""
    if not confirm:
        _confirm_required(f"Clearing AbuseIPDB cache for {ip}.")
    r = _get_redis()
    deleted = r.delete(f"abuseipdb:score:{ip}")
    click.echo(f"AbuseIPDB cache {'cleared' if deleted else 'was not present'} for {ip}.")
    _output({"ip": ip, "deleted": bool(deleted)}, ctx.obj["fmt"])


@flush.command("beaconing")
@click.argument("ip")
@click.option("--confirm", is_flag=True, default=False)
@click.pass_context
def flush_beaconing(ctx: click.Context, ip: str, confirm: bool) -> None:
    """Clear all beaconing timestamp history for an IP."""
    if not confirm:
        _confirm_required(f"Clearing all beaconing history for {ip}.")
    r = _get_redis()
    keys = r.keys(f"beacon:{ip}:*")
    if keys:
        r.delete(*keys)
    click.echo(f"Cleared {len(keys)} beaconing window(s) for {ip}.")
    _output({"ip": ip, "windows_cleared": len(keys)}, ctx.obj["fmt"])


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show proxy cluster status: dial, Redis memory, stream lag."""
    r = _get_redis()

    dial_val = r.get("config:dial") or "0"

    info = r.info("memory")
    used_mb = round(int(info.get("used_memory", 0)) / 1024 / 1024, 1)
    max_mb_raw = info.get("maxmemory", 0)
    max_mb = round(int(max_mb_raw) / 1024 / 1024, 1) if max_mb_raw else "unlimited"

    ban_count = len(r.keys("ban:*"))
    whitelist_count = r.scard("ja4:whitelist")
    blacklist_count = r.scard("ja4:blacklist")
    suspect_count = r.zcard("beacon:suspects")

    stream_len = r.xlen("ja4proxy:events") if r.exists("ja4proxy:events") else 0

    # Stream consumer lag (first consumer group found)
    stream_lag: int | str = "n/a"
    try:
        groups = r.xinfo_groups("ja4proxy:events")
        if groups:
            stream_lag = int(groups[0].get("lag", 0))
    except Exception:
        pass

    # Proxy instance heartbeats
    proxy_keys = r.keys("proxy:heartbeat:*")
    alive_instances: list[str] = []
    now = time.time()
    for key in proxy_keys:
        ts_raw = r.get(key)
        if ts_raw:
            try:
                age = now - float(ts_raw)
                if age < 30:
                    alive_instances.append(key.replace("proxy:heartbeat:", ""))
            except ValueError:
                pass

    result: dict[str, Any] = {
        "dial": int(dial_val),
        "redis_memory_mb": used_mb,
        "redis_maxmemory_mb": max_mb,
        "active_bans": ban_count,
        "ja4_whitelist_size": whitelist_count,
        "ja4_blacklist_size": blacklist_count,
        "beaconing_suspects": suspect_count,
        "event_stream_length": stream_len,
        "stream_consumer_lag": stream_lag,
        "proxy_instances_alive": len(alive_instances),
        "proxy_instances": alive_instances,
    }
    _output(result, ctx.obj["fmt"])


# ---------------------------------------------------------------------------
# backup
# ---------------------------------------------------------------------------


@cli.group()
def backup() -> None:
    """Manage proxy state backups."""


@backup.command("create")
@click.option("--dest", default="backups", show_default=True, help="Destination directory.")
@click.option("--encryption-key", envvar="BACKUP_ENCRYPTION_KEY", help="Secret key for encryption.")
@click.pass_context
def backup_create(ctx: click.Context, dest: str, encryption_key: str) -> None:
    """Create a new Redis state backup."""
    # Extract host/port/db from REDIS_URL
    import urllib.parse

    from src.backup.worker import BackupWorker
    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    p = urllib.parse.urlparse(url)
    
    worker = BackupWorker(
        redis_host=p.hostname or "localhost",
        redis_port=p.port or 6379,
        redis_db=int(p.path.lstrip("/") or 0),
        encryption_key=encryption_key
    )
    
    click.echo(f"Starting backup to {dest}...")
    try:
        path = worker.create_backup(dest)
        click.echo(f"Backup successful: {path}")
        if encryption_key:
            click.echo("Artifact is ENCRYPTED (AES-256-GCM).")
    except Exception as e:
        click.echo(f"ERROR: Backup failed: {e}", err=True)
        sys.exit(1)


@backup.command("restore")
@click.argument("artifact")
@click.argument("manifest")
@click.option("--encryption-key", envvar="BACKUP_ENCRYPTION_KEY", help="Secret key for decryption.")
@click.option("--destructive", is_flag=True, default=False, help="Wipe Redis before restore.")
@click.option(
    "--fallback",
    "fallbacks",
    multiple=True,
    help=(
        "Path to a fallback artifact to try if the primary fails. "
        "The corresponding manifest must exist alongside it "
        "(<artifact>.manifest.json). Can be repeated; tried in order."
    ),
)
@click.option("--confirm", is_flag=True, default=False)
@click.pass_context
def backup_restore(
    ctx: click.Context,
    artifact: str,
    manifest: str,
    encryption_key: str,
    destructive: bool,
    fallbacks: tuple[str, ...],
    confirm: bool,
) -> None:
    """Restore Redis state from an artifact.

    ARTIFACT is the path to the backup .bin file.
    MANIFEST is the path to the .manifest.json sidecar.

    Use --fallback to specify additional artifacts to try if the primary fails
    (useful for disaster recovery when the newest backup may be corrupt).
    The manifest for each fallback artifact is expected at
    <fallback_path>.manifest.json.
    """
    if destructive and not confirm:
        _confirm_required("This will DESTRUCTIVELY wipe Redis before restoring.")
    if not confirm:
        _confirm_required(f"Restoring backup from {artifact}.")

    import urllib.parse
    from pathlib import Path

    from src.backup.restorer import BackupRestorer

    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    p = urllib.parse.urlparse(url)

    restorer = BackupRestorer(
        redis_host=p.hostname or "localhost",
        redis_port=p.port or 6379,
        redis_db=int(p.path.lstrip("/") or 0),
        encryption_key=encryption_key,
    )

    if fallbacks:
        # Use restore_with_fallback for DR scenarios with multiple artifacts
        click.echo(
            f"Restoring {artifact} (with {len(fallbacks)} fallback(s) if primary fails)..."
        )
        try:
            used = restorer.restore_with_fallback(
                primary_path=Path(artifact),
                fallback_paths=[Path(f) for f in fallbacks],
            )
            click.echo(f"Restore successful. Used: {used.name}")
        except Exception as exc:
            click.echo(f"ERROR: Restore failed: {exc}", err=True)
            sys.exit(1)
    else:
        click.echo(f"Restoring {artifact}...")
        try:
            restorer.restore_backup(artifact, manifest, destructive=destructive)
            click.echo("Restore successful.")
        except Exception as exc:
            click.echo(f"ERROR: Restore failed: {exc}", err=True)
            sys.exit(1)


@backup.command("redact")
@click.argument("artifact")
@click.option("--ip", "ips", multiple=True, required=True, help="IP address to redact (can be repeated).")
@click.option("--output", "out_path", help="Output path for redacted artifact (defaults to overwrite).")
@click.option("--confirm", is_flag=True, default=False)
@click.pass_context
def backup_redact(ctx: click.Context, artifact: str, ips: list[str], out_path: str, confirm: bool) -> None:
    """Redact PII (IP addresses) from a backup artifact (DSAR tool)."""
    if not out_path and not confirm:
        _confirm_required(f"This will OVERWRITE {artifact} with redacted data.")

    import hashlib
    from pathlib import Path

    from src.backup.redactor import BackupRedactor

    artifact_path = Path(artifact)
    if not artifact_path.exists():
        click.echo(f"ERROR: Artifact {artifact} not found.", err=True)
        sys.exit(1)

    redactor = BackupRedactor()
    data = artifact_path.read_bytes()

    click.echo(f"Redacting {len(ips)} IP(s) from {artifact}...")
    new_data, count = redactor.redact(data, list(ips))

    if count == 0:
        click.echo("No matching entries found. Artifact unchanged.")
        return

    target = out_path if out_path else artifact
    Path(target).write_bytes(new_data)

    # If we overwrote, we MUST update the manifest checksum
    manifest_path = artifact_path.with_suffix(".manifest.json")
    if not out_path and manifest_path.exists():
        import json
        manifest = json.loads(manifest_path.read_text())
        manifest["checksum_sha256"] = hashlib.sha256(new_data).hexdigest()
        manifest["size_bytes"] = len(new_data)
        manifest["redacted_ips"] = list(ips)
        manifest_path.write_text(json.dumps(manifest, indent=2))
        click.echo("Updated manifest checksum.")

    click.echo(f"Successfully redacted {count} entries. Saved to {target}.")


@backup.command("dsar-redact")
@click.argument("artifact_path")
@click.option("--ip", "ips", multiple=True, required=True, help="IP address to redact (can be repeated).")
@click.option("--output", "out_path", help="Output path (defaults to <artifact>.redacted.bin).")
@click.pass_context
def backup_dsar_redact(ctx: click.Context, artifact_path: str, ips: list[str], out_path: str) -> None:
    """Redact a GDPR data subject's IP from a backup artifact (key names and JSON values).

    Scans both Redis key names and decoded JSON values for the target IP(s).
    Sets dsar_scanned: true in the manifest sidecar after redaction.
    Use before cloud upload when DSAR compliance is required.
    """
    import hashlib
    from pathlib import Path

    from src.backup.redactor import BackupRedactor

    source = Path(artifact_path)
    if not source.exists():
        click.echo(f"ERROR: Artifact {artifact_path} not found.", err=True)
        sys.exit(1)

    dest = Path(out_path) if out_path else source.with_suffix("").with_suffix(".redacted.bin")

    redactor = BackupRedactor()
    data = source.read_bytes()

    click.echo(f"Scanning {source.name} for {len(ips)} IP(s)...")
    new_data, count = redactor.redact(data, list(ips))

    dest.write_bytes(new_data)
    click.echo(f"Redacted {count} entries. Saved to {dest}.")

    # Update manifest sidecar: set dsar_scanned and refresh checksum
    manifest_path = source.parent / f"{source.name}.manifest.json"
    if manifest_path.exists():
        import json as _json
        manifest = _json.loads(manifest_path.read_text())
        manifest["checksum_sha256"] = hashlib.sha256(new_data).hexdigest()
        manifest["size_bytes"] = len(new_data)
        manifest["dsar_scanned"] = True
        manifest["redacted_ips"] = list(ips)
        # Write manifest alongside the new artifact
        dest_manifest = dest.parent / f"{dest.name}.manifest.json"
        dest_manifest.write_text(_json.dumps(manifest, indent=2))
        click.echo(f"Updated manifest written to {dest_manifest}.")


# ---------------------------------------------------------------------------
# backup cloud subgroup (Phase 57b/57c)
# ---------------------------------------------------------------------------


@backup.group("cloud")
def backup_cloud() -> None:
    """Upload, list, and download backup artifacts from cloud storage (S3 or GCS)."""


def _make_storage_adapter(provider: str) -> "Any":
    """Instantiate the correct StorageAdapter from environment variables.

    Args:
        provider: ``"s3"`` or ``"gcs"``.

    Returns:
        A configured StorageAdapter instance.
    """
    import asyncio
    import importlib
    if provider == "s3":
        try:
            mod = importlib.import_module("src.backup.cloud.s3_adapter")
            cls = getattr(mod, "S3StorageAdapter")
        except (ImportError, AttributeError) as exc:
            click.echo(f"ERROR: S3 adapter not available: {exc}", err=True)
            click.echo("Ensure boto3 is installed: pip install boto3", err=True)
            sys.exit(1)
        bucket = os.environ.get("BACKUP_S3_BUCKET")
        region = os.environ.get("BACKUP_S3_REGION", "us-east-1")
        prefix = os.environ.get("BACKUP_S3_PREFIX", "backups/")
        if not bucket:
            click.echo(
                "ERROR: BACKUP_S3_BUCKET environment variable is not set.", err=True
            )
            sys.exit(1)
        return cls(bucket=bucket, region=region, prefix=prefix)
    elif provider == "gcs":
        try:
            mod = importlib.import_module("src.backup.cloud.gcs_adapter")
            cls = getattr(mod, "GCSStorageAdapter")
        except (ImportError, AttributeError) as exc:
            click.echo(f"ERROR: GCS adapter not available: {exc}", err=True)
            click.echo(
                "Ensure google-cloud-storage is installed: pip install google-cloud-storage",
                err=True,
            )
            sys.exit(1)
        bucket = os.environ.get("BACKUP_GCS_BUCKET")
        project_id = os.environ.get("BACKUP_GCS_PROJECT_ID")
        credentials_path = os.environ.get("BACKUP_GCS_CREDENTIALS_PATH")
        prefix = os.environ.get("BACKUP_GCS_PREFIX", "backups/")
        if not bucket:
            click.echo(
                "ERROR: BACKUP_GCS_BUCKET environment variable is not set.", err=True
            )
            sys.exit(1)
        return cls(
            bucket=bucket,
            project_id=project_id,
            credentials_path=credentials_path,
            prefix=prefix,
        )
    else:
        click.echo(f"ERROR: Unknown provider '{provider}'. Use 's3' or 'gcs'.", err=True)
        sys.exit(1)


@backup_cloud.command("upload")
@click.argument("artifact_path")
@click.option(
    "--provider",
    type=click.Choice(["s3", "gcs"]),
    default="s3",
    show_default=True,
    help="Cloud storage provider.",
)
@click.pass_context
def backup_cloud_upload(ctx: click.Context, artifact_path: str, provider: str) -> None:
    """Upload a local backup artifact to cloud storage.

    Prints the cloud URI on success.
    Reads credentials from environment variables (AWS_* for S3, BACKUP_GCS_* for GCS).
    """
    import asyncio
    from pathlib import Path

    source = Path(artifact_path)
    if not source.exists():
        click.echo(f"ERROR: Artifact {artifact_path} not found.", err=True)
        sys.exit(1)

    # Load manifest sidecar for metadata
    manifest_path = source.parent / f"{source.name}.manifest.json"
    manifest: dict[str, Any] = {}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())

    adapter = _make_storage_adapter(provider)

    click.echo(f"Uploading {source.name} to {provider}...")
    try:
        metadata = asyncio.run(adapter.upload(source, manifest))
        click.echo(f"Uploaded: {metadata.uri}")
        _output(
            {
                "uri": metadata.uri,
                "filename": metadata.filename,
                "size_bytes": metadata.size_bytes,
                "provider": metadata.provider,
            },
            ctx.obj["fmt"],
        )
    except Exception as exc:
        click.echo(f"ERROR: Upload failed: {exc}", err=True)
        sys.exit(1)


@backup_cloud.command("list")
@click.option(
    "--provider",
    type=click.Choice(["s3", "gcs"]),
    default="s3",
    show_default=True,
    help="Cloud storage provider.",
)
@click.option("--prefix", default="", show_default=False, help="Filename prefix filter.")
@click.pass_context
def backup_cloud_list(ctx: click.Context, provider: str, prefix: str) -> None:
    """List backup artifacts available in cloud storage.

    Columns: uri, filename, size_bytes, created_at.
    """
    import asyncio

    adapter = _make_storage_adapter(provider)

    try:
        artifacts = asyncio.run(adapter.list_backups(prefix=prefix))
    except Exception as exc:
        click.echo(f"ERROR: List failed: {exc}", err=True)
        sys.exit(1)

    if not artifacts:
        click.echo("No artifacts found.")
        return

    results = [
        {
            "uri": m.uri,
            "filename": m.filename,
            "size_bytes": m.size_bytes,
            "created_at": m.created_at,
        }
        for m in artifacts
    ]
    _output(results, ctx.obj["fmt"])


@backup_cloud.command("download")
@click.argument("artifact_id")
@click.option(
    "--provider",
    type=click.Choice(["s3", "gcs"]),
    default="s3",
    show_default=True,
    help="Cloud storage provider.",
)
@click.option(
    "--dest",
    default=".",
    show_default=True,
    help="Local destination directory.",
)
@click.pass_context
def backup_cloud_download(ctx: click.Context, artifact_id: str, provider: str, dest: str) -> None:
    """Download a backup artifact from cloud storage.

    ARTIFACT_ID is the filename or full cloud URI returned by ``backup cloud list``.
    Prints the path of the downloaded file on success.
    """
    import asyncio
    from pathlib import Path

    dest_dir = Path(dest)
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Derive local filename from artifact_id (strip any path prefix)
    filename = artifact_id.split("/")[-1]
    local_path = dest_dir / filename

    adapter = _make_storage_adapter(provider)

    click.echo(f"Downloading {artifact_id} from {provider}...")
    try:
        result_path = asyncio.run(adapter.download(artifact_id, local_path))
        click.echo(f"Downloaded: {result_path}")
        _output({"local_path": str(result_path), "provider": provider}, ctx.obj["fmt"])
    except Exception as exc:
        click.echo(f"ERROR: Download failed: {exc}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
