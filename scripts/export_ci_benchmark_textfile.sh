#!/usr/bin/env bash
# Phase 805 — host-side puller for the nightly benchmark regression job.
#
# Runs ONLY on the self-hosted monitoring host, via a systemd timer (see
# docs/runbooks/nightly_benchmark_regression.md for install steps). GitHub
# Actions has no inbound network path to the monitoring host (see
# docs/phases/PHASE_805.md's design section for why remote_write/Pushgateway
# were rejected), so this pulls instead: outbound-only HTTPS GET of the
# public "nightly-benchmark-latest" GitHub Release asset, converted to
# Prometheus text exposition format for node-exporter's textfile collector.
#
# Fail-open (CLAUDE.md convention): a fetch or parse failure NEVER blanks
# out the last-known-good textfile — it leaves the existing file untouched
# and exits 0. Staleness (not a crash) is what the separate
# JA4ProxyNightlyBenchmarkStale alert exists to catch.
set -euo pipefail

RELEASE_URL="${RELEASE_URL:-https://github.com/seanpor/JA4proxy/releases/download/nightly-benchmark-latest/result.json}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/node_exporter/textfile_collector}"
OUT_FILE="$TEXTFILE_DIR/ja4proxy_nightly_benchmark.prom"

TMP_JSON="$(mktemp)"
TMP_PROM="$(mktemp)"
trap 'rm -f "$TMP_JSON" "$TMP_PROM"' EXIT

log() { echo "export_ci_benchmark_textfile: $*" >&2; }

if ! curl -fsSL --max-time 30 -o "$TMP_JSON" "$RELEASE_URL"; then
  log "fetch failed ($RELEASE_URL) — leaving existing textfile untouched"
  exit 0
fi

if ! python3 - "$TMP_JSON" > "$TMP_PROM" <<'PYEOF'
import json
import sys
import time

def gauge(name: str, help_text: str, value: float) -> None:
    print(f"# HELP {name} {help_text}")
    print(f"# TYPE {name} gauge")
    print(f"{name} {value}")

def counter(name: str, help_text: str, value: float) -> None:
    print(f"# HELP {name} {help_text}")
    print(f"# TYPE {name} counter")
    print(f"{name} {value}")

with open(sys.argv[1]) as f:
    data = json.load(f)

total_good = data["total_good"]
total_bad = data["total_bad"]
errors = data["errors"]

counter(
    "ja4proxy_loadtest_connections_attempted_total",
    "Connections the nightly load test attempted to open",
    total_good + total_bad + errors,
)
counter(
    "ja4proxy_loadtest_connections_completed_total",
    "Connections that completed successfully",
    total_good + total_bad,
)
counter(
    "ja4proxy_loadtest_errors_total",
    "Connection errors during the nightly load test",
    errors,
)
gauge(
    "ja4proxy_loadtest_throughput_cps",
    "Achieved throughput of the nightly load test (connections per second)",
    data.get("throughput_cps", 0.0),
)
gauge("ja4proxy_loadtest_p50_latency_ms", "p50 connection latency in milliseconds", data.get("p50_latency_ms", 0.0))
gauge("ja4proxy_loadtest_p95_latency_ms", "p95 connection latency in milliseconds", data.get("p95_latency_ms", 0.0))
gauge("ja4proxy_loadtest_p99_latency_ms", "p99 connection latency in milliseconds", data.get("p99_latency_ms", 0.0))
gauge(
    "ja4proxy_loadtest_baseline_throughput_cps",
    "Regression-gate baseline throughput (connections per second)",
    data.get("baseline_throughput_cps", 0.0),
)
gauge(
    "ja4proxy_loadtest_baseline_p95_latency_ms",
    "Regression-gate baseline p95 latency in milliseconds",
    data.get("baseline_p95_latency_ms", 0.0),
)
gauge(
    "ja4proxy_loadtest_last_ci_run_timestamp_seconds",
    "Unix timestamp this nightly benchmark textfile was last refreshed",
    time.time(),
)
PYEOF
then
  log "parse failed ($TMP_JSON malformed?) — leaving existing textfile untouched"
  exit 0
fi

mkdir -p "$TEXTFILE_DIR"
mv "$TMP_PROM" "$OUT_FILE"
log "wrote $OUT_FILE"
