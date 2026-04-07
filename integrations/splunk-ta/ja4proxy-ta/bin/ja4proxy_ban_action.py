#!/usr/bin/env python3
"""
ja4proxy_ban_action.py — Splunk alert action: ban a source IP via the JA4proxy Management API.

Splunk executes this script when the "JA4proxy Ban IP" alert action fires.  The
alert framework pipes a JSON payload to stdin containing the triggering event's
fields.  The script reads the source IP from that payload, then POSTs a ban
request to the JA4proxy Management API.

Configuration is via environment variables (set in Splunk's alert action UI or
in the container/system environment):

  JA4PROXY_MGMT_URL   Base URL of the Management API, e.g. https://ja4proxy.internal:8090
  JA4PROXY_API_TOKEN  Bearer token for the /api/v1/bans endpoint

Exit codes:
  0  — ban posted successfully
  1  — failure (API error, missing config, or invalid payload)
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log(level: str, message: str) -> None:
    """Write a log line to stderr (captured by Splunk as the action log)."""
    print(f"[{level}] ja4proxy_ban_action: {message}", file=sys.stderr, flush=True)


def _read_payload() -> dict:
    """Read and parse the JSON payload that Splunk writes to stdin."""
    raw = sys.stdin.read()
    if not raw.strip():
        _log("ERROR", "Empty stdin — no alert payload received")
        sys.exit(1)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        _log("ERROR", f"Failed to parse stdin JSON: {exc}")
        sys.exit(1)


def _extract_src_ip(payload: dict) -> str:
    """
    Extract the source IP from the Splunk alert payload.

    Splunk puts the triggering event's fields under ``payload["result"]``.
    The JA4proxy ECS schema puts the IP in ``source.ip``; the CIM alias
    maps it to ``src``.  We check both to be resilient to different
    correlation search configurations.
    """
    result: dict = payload.get("result", {})

    for field in ("src_ip", "src", "source.ip"):
        ip = result.get(field, "").strip()
        if ip:
            return ip

    _log("ERROR", f"Could not find source IP in payload result fields: {list(result.keys())}")
    sys.exit(1)


def _get_config() -> tuple[str, str]:
    """Return (mgmt_url, api_token) from environment variables."""
    mgmt_url = os.environ.get("JA4PROXY_MGMT_URL", "").rstrip("/")
    api_token = os.environ.get("JA4PROXY_API_TOKEN", "")

    if not mgmt_url:
        _log("ERROR", "JA4PROXY_MGMT_URL environment variable is not set")
        sys.exit(1)
    if not api_token:
        _log("ERROR", "JA4PROXY_API_TOKEN environment variable is not set")
        sys.exit(1)

    return mgmt_url, api_token


def _post_ban(mgmt_url: str, api_token: str, src_ip: str, ttl_seconds: int, reason: str) -> None:
    """POST a ban request to the JA4proxy Management API."""
    endpoint = f"{mgmt_url}/api/v1/bans"

    body = json.dumps({
        "ip": src_ip,
        "ttl_seconds": ttl_seconds,
        "reason": reason,
    }).encode("utf-8")

    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_token}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status = response.getcode()
            response_body = response.read().decode("utf-8", errors="replace")
            if status in (200, 201):
                _log("INFO", f"Ban posted successfully for {src_ip} — HTTP {status}: {response_body}")
            else:
                _log("WARN", f"Unexpected HTTP {status} for {src_ip}: {response_body}")
                sys.exit(1)
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        _log("ERROR", f"HTTP {exc.code} from Management API for {src_ip}: {error_body}")
        sys.exit(1)
    except urllib.error.URLError as exc:
        _log("ERROR", f"Network error reaching Management API at {endpoint}: {exc.reason}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    payload = _read_payload()
    mgmt_url, api_token = _get_config()
    src_ip = _extract_src_ip(payload)

    # ttl_seconds and reason can be overridden via the alert action parameter
    # block in savedsearches.conf or via the alert action UI form.
    configuration: dict = payload.get("configuration", {})
    ttl_seconds = int(configuration.get("ttl_seconds", 3600))
    reason = str(configuration.get("reason", "Splunk alert action")).strip() or "Splunk alert action"

    _log("INFO", f"Banning {src_ip} for {ttl_seconds}s — reason: {reason!r}")
    _post_ban(mgmt_url, api_token, src_ip, ttl_seconds, reason)


if __name__ == "__main__":
    main()
