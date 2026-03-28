#!/usr/bin/env python3
"""
JA4proxy Master CLI
The unified entry point for administrative, diagnostic, and operational tasks.
Replaces fragmented scripts with a single, enterprise-ready tool.
"""

import json
import os
import subprocess
import sys

import click

# Add project root to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

# Import admin logic (will be refactored from ja4proxy_admin.py)
# For now, we'll keep it simple and grow it.


@click.group()
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.pass_context
def cli(ctx, fmt):
    """JA4proxy Master CLI."""
    ctx.ensure_object(dict)
    ctx.obj["fmt"] = fmt


# --- Diagnostic Commands ---


@cli.command()
@click.pass_context
def health(ctx):
    """Perform a deep health and integrity audit of the workspace."""
    click.echo("Running Workspace Integrity Audit...")
    from scripts.workspace_integrity_tool import WorkspaceIntegrityTool

    wit = WorkspaceIntegrityTool(".")
    orphans, broken = wit.run()

    result = {
        "status": "pass" if not broken else "fail",
        "orphan_count": len(orphans),
        "broken_reference_count": len(broken),
        "details": {"broken_references": {k: list(v) for k, v in broken.items() if v}},
    }

    if ctx.obj["fmt"] == "json":
        click.echo(json.dumps(result, indent=2))
    else:
        if broken:
            click.echo(
                click.style(
                    f"FAIL: Found {len(broken)} files with broken references.", fg="red"
                )
            )
            for src, refs in broken.items():
                if refs:
                    click.echo(f"  {src}: {', '.join(refs)}")
        else:
            click.echo(click.style("PASS: No broken references found.", fg="green"))

        click.echo(f"INFO: Found {len(orphans)} potential orphan files.")


# --- Proxy Management ---


@cli.group()
def proxy():
    """Manage JA4proxy instances."""


@proxy.command("scale")
@click.argument("n", type=int)
def proxy_scale(n):
    """Scale the proxy to N instances behind HAProxy."""
    click.echo(f"Scaling to {n} instances...")
    try:
        subprocess.run(["bash", "scripts/scale-proxies.sh", str(n)], check=True)
    except subprocess.CalledProcessError as e:
        click.echo(f"Error scaling: {e}", err=True)


# --- Threat Management (Ported from ja4proxy_admin.py) ---


@cli.group()
def threat():
    """Manage threats: bans, blacklists, and whitelists."""


# (In a real implementation, I'd import and mount the groups from ja4proxy_admin.py here)

# --- GeoIP Management ---


@cli.group()
def geoip():
    """Manage GeoIP settings and country blocking."""


@geoip.command("update")
def geoip_update():
    """Download latest GeoIP databases."""
    subprocess.run(["bash", "scripts/update-geoip.sh"], check=True)


if __name__ == "__main__":
    cli()
