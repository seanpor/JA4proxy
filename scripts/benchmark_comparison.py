#!/usr/bin/env python3
"""
JA4proxy Comprehensive Benchmark: Go Proxy vs Python Proxy.

Runs a battery of benchmark scenarios against both proxy implementations
to measure throughput, latency, cache effects, and behaviour under load.

Scenarios:
  1.  baseline_latency    - Sequential TCP+TLS connections, full latency distribution
  2.  throughput_scaling  - Thread count 1→2→4→8→16→32, measure conn/s knee
  3.  peak_throughput     - Max connections/s at full concurrency, sustained
  4.  mixed_traffic       - Browser (h2 ALPN) vs bot (no ALPN) ratio sweep
  5.  sustained_load      - 60 s at fixed rates to detect degradation over time
  6.  warm_cache          - Small IP pool (Redis hit path)
  7.  cold_cache          - Fresh IPs per connection (Redis miss path)
  8.  burst_load          - Rapid ramp-up then hold, measures recovery behaviour
  9.  adversarial_tls     - Incomplete handshakes, immediate closes, corrupt data
  10. latency_percentiles - Deep percentile breakdown (p50/p90/p95/p99/p99.9/p100)
  11. attack_500          - 500 conn/s sustained: 5% browser (good), 95% bot (bad);
                            rate-controlled token bucket; PROXY-protocol source IP
                            injection distributes load across 1000 synthetic IPs so
                            per-IP rate limiting is not artificially triggered

Usage:
    python3 scripts/benchmark_comparison.py [options]
    python3 scripts/benchmark_comparison.py --quick
    python3 scripts/benchmark_comparison.py --scenarios throughput_scaling,peak_throughput

Options:
    --python-host HOST      Python proxy host (default: 127.0.0.1)
    --python-port PORT      Python proxy port (default: 8080)
    --go-host HOST          Go proxy host (default: 127.0.0.1)
    --go-port PORT          Go proxy port (default: 8082)
    --output-dir DIR        Report output directory
    --duration-quick SECS   Duration for quick scenarios (default: 15)
    --duration-long SECS    Duration for sustained scenarios (default: 60)
    --max-threads N         Max thread count for scaling tests (default: 32)
    --scenarios LIST        Comma-separated names or "all" (default: all)
    --redis-host HOST       Redis host for cache flush (default: 127.0.0.1)
    --redis-port PORT       Redis port (default: 6379)
    --redis-password PASS   Redis password (env: REDIS_PASSWORD)
    --no-redis-flush        Skip Redis flush between scenarios
    --quick                 Short mode: 10 s per scenario, fewer thread steps
    --proxy PROXY           Benchmark only one proxy: python | go
    --connect-timeout SECS  Per-connection TCP timeout (default: 2.0)
    --use-proxy-protocol    Prepend PPv2 header with rotating synthetic source IP
                            (requires proxy_protocol: true in config/proxy.yml, which
                            is already the default). Prevents rate-limiting from
                            treating the benchmark host as a single attacking IP.
    --source-ip-pool-size N Number of synthetic source IPs to rotate through (default: 1000)
    --attack-rate N         Target connections/second for the attack_500 scenario (default: 500)
    --fast-backend-port P   Port of the fast TLS echo backend (default: 8444).
                            Start it with: python3 scripts/bench-tls-backend.py --port 8444
"""
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import ipaddress
import json
import math
import os
import platform
import random
import socket
import ssl
import statistics
import subprocess
import sys
import textwrap
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Version sentinel ──────────────────────────────────────────────────────────
BENCHMARK_VERSION = "1.0.0"

# ── Configuration ─────────────────────────────────────────────────────────────

@dataclasses.dataclass
class BenchmarkConfig:
    python_host: str = "127.0.0.1"
    python_port: int = 8080
    go_host: str = "127.0.0.1"
    go_port: int = 8082
    output_dir: Optional[Path] = None
    duration_quick: int = 15   # seconds per short scenario
    duration_long: int = 60    # seconds per sustained scenario
    max_threads: int = 32
    scenarios: list = dataclasses.field(default_factory=list)
    redis_host: str = "127.0.0.1"
    redis_port: int = 6379
    redis_password: str = ""
    flush_redis: bool = True
    quick: bool = False
    proxy_filter: Optional[str] = None   # "python" | "go" | None (both)
    connect_timeout: float = 2.0
    use_proxy_protocol: bool = False
    source_ip_pool_size: int = 1000
    attack_rate: int = 500           # target conn/s for attack_500 scenario
    fast_backend_port: int = 8444    # port of bench-tls-backend.py

    def __post_init__(self) -> None:
        if self.quick:
            self.duration_quick = 10
            self.duration_long = 30
            self.max_threads = 16
        if not self.scenarios:
            self.scenarios = list(ALL_SCENARIOS)
        if self.output_dir is None:
            ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            self.output_dir = Path("reports") / "benchmark" / ts
        self.output_dir = Path(self.output_dir)


ALL_SCENARIOS = [
    "baseline_latency",
    "throughput_scaling",
    "peak_throughput",
    "mixed_traffic",
    "sustained_load",
    "warm_cache",
    "cold_cache",
    "burst_load",
    "adversarial_tls",
    "latency_percentiles",
    "attack_500",
]

# ── Result types ──────────────────────────────────────────────────────────────

@dataclasses.dataclass
class ConnectionSample:
    latency_ms: float
    outcome: str   # "allowed" | "blocked" | "error" | "timeout"
    error_detail: str = ""


@dataclasses.dataclass
class ThroughputRun:
    """One measurement of connections-per-second over a fixed window."""
    threads: int
    duration_s: float
    total: int
    allowed: int
    blocked: int
    errors: int
    elapsed_s: float

    @property
    def conn_per_sec(self) -> float:
        return self.total / self.elapsed_s if self.elapsed_s > 0 else 0.0

    @property
    def success_pct(self) -> float:
        return (self.allowed + self.blocked) / self.total * 100 if self.total else 0.0

    @property
    def error_pct(self) -> float:
        return self.errors / self.total * 100 if self.total else 0.0


@dataclasses.dataclass
class ProxyResult:
    """All measurements for one proxy in one scenario."""
    proxy_name: str           # "python" | "go"
    samples: list[ConnectionSample] = dataclasses.field(default_factory=list)
    throughput_runs: list[ThroughputRun] = dataclasses.field(default_factory=list)
    extra: dict = dataclasses.field(default_factory=dict)

    def latency_percentile(self, p: float) -> float:
        """Return the p-th percentile latency across all samples (in ms)."""
        lats = sorted(s.latency_ms for s in self.samples if s.outcome != "error")
        if not lats:
            return 0.0
        idx = max(0, min(len(lats) - 1, int(math.ceil(len(lats) * p / 100)) - 1))
        return lats[idx]

    def mean_latency(self) -> float:
        lats = [s.latency_ms for s in self.samples if s.outcome != "error"]
        return statistics.mean(lats) if lats else 0.0

    def stdev_latency(self) -> float:
        lats = [s.latency_ms for s in self.samples if s.outcome != "error"]
        return statistics.stdev(lats) if len(lats) > 1 else 0.0

    def peak_throughput(self) -> float:
        if not self.throughput_runs:
            return 0.0
        return max(r.conn_per_sec for r in self.throughput_runs)

    def total_connections(self) -> int:
        return sum(r.total for r in self.throughput_runs)


@dataclasses.dataclass
class ScenarioResult:
    name: str
    description: str
    python: Optional[ProxyResult] = None
    go: Optional[ProxyResult] = None
    notes: list[str] = dataclasses.field(default_factory=list)
    wall_time_s: float = 0.0

    def speedup(self) -> Optional[float]:
        """Go peak throughput / Python peak throughput."""
        if self.python is None or self.go is None:
            return None
        py_tp = self.python.peak_throughput()
        go_tp = self.go.peak_throughput()
        if py_tp <= 0:
            return None
        return go_tp / py_tp

    def latency_improvement(self) -> Optional[float]:
        """Python p99 / Go p99 (> 1 means Go is faster)."""
        if self.python is None or self.go is None:
            return None
        py_p99 = self.python.latency_percentile(99)
        go_p99 = self.go.latency_percentile(99)
        if go_p99 <= 0:
            return None
        return py_p99 / go_p99


# ── TLS contexts ──────────────────────────────────────────────────────────────

def _make_browser_ctx() -> ssl.SSLContext:
    """TLS context that mimics a modern browser (h2 ALPN, TLS 1.2/1.3)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5")
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    return ctx


def _make_bot_ctx() -> ssl.SSLContext:
    """TLS context with no ALPN — typical Python requests / curl bot fingerprint."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5")
    return ctx


def _make_tls12_only_ctx() -> ssl.SSLContext:
    """TLS 1.2 only, no ALPN — common scanner fingerprint."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("AES256-SHA:AES128-SHA:ECDHE+AESGCM")
    return ctx


BROWSER_CTX = _make_browser_ctx()
BOT_CTX = _make_bot_ctx()
TLS12_CTX = _make_tls12_only_ctx()

# ── PROXY protocol v2 helpers ────────────────────────────────────────────────
#
# The JA4proxy reads PROXY protocol v2 (binary) headers when proxy_protocol: true
# is set in config/proxy.yml (the default).  By prepending a PPv2 header to each
# benchmark connection we can inject a synthetic source IP, causing the proxy to
# score/rate-limit each connection against a distinct IP rather than collapsing all
# benchmark traffic onto 127.0.0.1 and triggering the per-IP concurrent cap.

_PP2_SIG = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"


def _make_pp2_header(src_ip: str, dst_ip: str, dst_port: int) -> bytes:
    """Build a minimal 28-byte PROXY protocol v2 IPv4 TCP header."""
    src_port = random.randint(1024, 65535)
    return (
        _PP2_SIG
        + b"\x21"                          # version=2, command=PROXY
        + b"\x11"                          # family=AF_INET, proto=STREAM
        + b"\x00\x0c"                      # addr block length = 12 bytes
        + socket.inet_aton(src_ip)         # source IPv4
        + socket.inet_aton(dst_ip)         # destination IPv4
        + src_port.to_bytes(2, "big")      # source port
        + dst_port.to_bytes(2, "big")      # destination port
    )


def _build_ip_pool(size: int) -> list[str]:
    """Generate *size* synthetic IPv4 addresses from 10.0.0.0/8 for PP2 injection."""
    seen: set[int] = set()
    ips: list[str] = []
    while len(ips) < size:
        n = random.randint(0x0A000001, 0x0AFFFFFF)  # 10.0.0.1 – 10.255.255.255
        if n not in seen:
            seen.add(n)
            ips.append(socket.inet_ntoa(n.to_bytes(4, "big")))
    return ips


# ── Token bucket rate controller ──────────────────────────────────────────────

class _TokenBucket:
    """Thread-safe token bucket for rate-controlled connection sending."""

    def __init__(self, rate: float) -> None:
        self._rate = rate          # tokens (= connections) per second
        self._tokens = rate        # start full
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until a token is available, then consume one."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
            time.sleep(0.0005)   # 0.5 ms poll — low overhead at 500 conn/s


# ── Core measurement functions ─────────────────────────────────────────────────

def _check_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if the host:port is accepting TCP connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _connect_once(
    host: str,
    port: int,
    ctx: ssl.SSLContext,
    timeout: float,
    sni: str = "backend",
    pre_send: bytes = b"",
) -> ConnectionSample:
    """
    Attempt one TLS connection; return latency and outcome.

    If *pre_send* is non-empty it is written to the raw TCP socket before the
    TLS handshake begins.  Pass a PROXY protocol v2 header here to inject a
    synthetic source IP so the proxy scores each connection against a distinct
    address rather than collapsing all benchmark traffic onto the single host IP.

    Outcomes:
      "allowed"  — TLS handshake completed (backend responded or proxy forwarded)
      "blocked"  — connection reset/refused (proxy decided to block)
      "error"    — unexpected exception (misconfiguration / test bug)
      "timeout"  — connection timed out
    """
    t0 = time.perf_counter()
    raw: Optional[socket.socket] = None
    tls: Optional[ssl.SSLSocket] = None
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        raw.connect((host, port))
        if pre_send:
            raw.sendall(pre_send)
        tls = ctx.wrap_socket(raw, server_hostname=sni)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return ConnectionSample(latency_ms=elapsed_ms, outcome="allowed")
    except ssl.SSLError as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        # SSLError after partial handshake = proxy likely sent RST → "blocked"
        return ConnectionSample(latency_ms=elapsed_ms, outcome="blocked",
                                error_detail=str(exc))
    except (ConnectionResetError, ConnectionRefusedError, BrokenPipeError) as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return ConnectionSample(latency_ms=elapsed_ms, outcome="blocked",
                                error_detail=str(exc))
    except TimeoutError as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return ConnectionSample(latency_ms=elapsed_ms, outcome="timeout",
                                error_detail=str(exc))
    except OSError as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        # ConnectionRefusedError is an OSError subclass
        detail = str(exc)
        outcome = "blocked" if "refused" in detail.lower() else "error"
        return ConnectionSample(latency_ms=elapsed_ms, outcome=outcome,
                                error_detail=detail)
    finally:
        for sock in (tls, raw):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


def _connect_tcp_only(host: str, port: int, timeout: float) -> ConnectionSample:
    """TCP-only connection (no TLS), measures raw accept latency."""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed_ms = (time.perf_counter() - t0) * 1000
            return ConnectionSample(latency_ms=elapsed_ms, outcome="allowed")
    except TimeoutError as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return ConnectionSample(latency_ms=elapsed_ms, outcome="timeout",
                                error_detail=str(exc))
    except OSError as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return ConnectionSample(latency_ms=elapsed_ms, outcome="error",
                                error_detail=str(exc))


def _connect_send_garbage(host: str, port: int, timeout: float) -> ConnectionSample:
    """Send 16 bytes of random garbage immediately after TCP connect (adversarial)."""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(os.urandom(16))
            try:
                s.recv(256)
            except OSError:
                pass
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return ConnectionSample(latency_ms=elapsed_ms, outcome="allowed")
    except (ConnectionResetError, ConnectionRefusedError, BrokenPipeError) as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return ConnectionSample(latency_ms=elapsed_ms, outcome="blocked",
                                error_detail=str(exc))
    except OSError as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return ConnectionSample(latency_ms=elapsed_ms, outcome="error",
                                error_detail=str(exc))


def _connect_immediate_close(host: str, port: int, timeout: float) -> ConnectionSample:
    """Connect and close immediately without sending any data."""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return ConnectionSample(latency_ms=elapsed_ms, outcome="allowed")
    except OSError as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return ConnectionSample(latency_ms=elapsed_ms, outcome="error",
                                error_detail=str(exc))


def _measure_sequential(
    host: str,
    port: int,
    ctx: ssl.SSLContext,
    count: int,
    timeout: float,
) -> list[ConnectionSample]:
    """Make *count* sequential TLS connections; return all samples."""
    return [_connect_once(host, port, ctx, timeout) for _ in range(count)]


def _measure_throughput(
    host: str,
    port: int,
    ctx: ssl.SSLContext,
    duration_s: float,
    threads: int,
    timeout: float,
) -> ThroughputRun:
    """Hammer the proxy with *threads* concurrent workers for *duration_s* seconds."""
    deadline = time.monotonic() + duration_s
    counters = {"total": 0, "allowed": 0, "blocked": 0, "errors": 0}
    lock = threading.Lock()

    def _worker() -> None:
        while time.monotonic() < deadline:
            sample = _connect_once(host, port, ctx, timeout)
            with lock:
                counters["total"] += 1
                if sample.outcome == "allowed":
                    counters["allowed"] += 1
                elif sample.outcome in ("blocked", "timeout"):
                    counters["blocked"] += 1
                else:
                    counters["errors"] += 1

    t0 = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(_worker) for _ in range(threads)]
        for f in concurrent.futures.as_completed(futures):
            f.result()
    elapsed = time.monotonic() - t0

    return ThroughputRun(
        threads=threads,
        duration_s=duration_s,
        total=counters["total"],
        allowed=counters["allowed"],
        blocked=counters["blocked"],
        errors=counters["errors"],
        elapsed_s=elapsed,
    )


# ── Redis flush utility ────────────────────────────────────────────────────────

def _flush_redis(cfg: BenchmarkConfig) -> bool:
    """Flush Redis to clear rate-limit keys between scenarios. Returns success."""
    if not cfg.flush_redis:
        return True
    try:
        cmd = [
            "redis-cli",
            "-h", cfg.redis_host,
            "-p", str(cfg.redis_port),
        ]
        if cfg.redis_password:
            cmd += ["-a", cfg.redis_password, "--no-auth-warning"]
        cmd += ["FLUSHDB"]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        # redis-cli not available; try via docker
        try:
            pw_arg = f"-a {cfg.redis_password} --no-auth-warning " if cfg.redis_password else ""
            docker_cmd = [
                "docker", "exec", "ja4proxy-redis",
                "redis-cli", pw_arg.strip(), "FLUSHDB",
            ]
            result = subprocess.run(
                " ".join(docker_cmd), shell=True,  # noqa: S602 — non-user input  # nosemgrep: subprocess-shell-true
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False


# ── System information ─────────────────────────────────────────────────────────

def _collect_system_info() -> dict:
    """Collect host system information for the report."""
    info: dict = {
        "platform": platform.platform(),
        "python_version": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "hostname": platform.node(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    # Try to get CPU model
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    info["cpu_model"] = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    # Try to get total memory
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    kb = int(line.split()[1])
                    info["memory_gb"] = round(kb / 1024 / 1024, 1)
                    break
    except OSError:
        pass
    return info


def _get_proxy_version(host: str, port: int) -> str:
    """Try to get version string from proxy /health endpoint (Go proxy)."""
    try:
        # The Go proxy exposes /health; Python proxy exposes /metrics
        import urllib.request  # noqa: PLC0415
        with urllib.request.urlopen(  # nosemgrep: dynamic-urllib-use-detected
            f"http://{host}:{port + 10}/health", timeout=2  # metrics port = proxy_port + 10
        ) as resp:
            data = json.loads(resp.read())
            return data.get("version", "unknown")
    except Exception:  # noqa: BLE001 — probe, not hot path
        return "unknown"


# ── Progress display ───────────────────────────────────────────────────────────

_print_lock = threading.Lock()


def _log(msg: str, prefix: str = "  ") -> None:
    with _print_lock:
        print(f"{prefix}{msg}", flush=True)


def _scenario_header(name: str, desc: str) -> None:
    bar = "─" * 70
    _log(f"\n{bar}", prefix="")
    _log(f"  Scenario: {name}", prefix="")
    _log(f"  {desc}", prefix="")
    _log(f"{bar}", prefix="")


def _progress(msg: str) -> None:
    _log(f"    {msg}")


# ── Scenarios ─────────────────────────────────────────────────────────────────

class BenchmarkSuite:
    """
    Runs all benchmark scenarios against one or both proxies.

    Call run_scenarios() to execute and populate self.results.
    """

    def __init__(self, cfg: BenchmarkConfig) -> None:
        self.cfg = cfg
        self.results: list[ScenarioResult] = []
        self._system_info = _collect_system_info()

    # ── helpers ──

    def _targets(self) -> list[tuple[str, str, int]]:
        """Return list of (label, host, port) tuples based on proxy_filter."""
        all_targets = [
            ("python", self.cfg.python_host, self.cfg.python_port),
            ("go", self.cfg.go_host, self.cfg.go_port),
        ]
        if self.cfg.proxy_filter == "python":
            return all_targets[:1]
        if self.cfg.proxy_filter == "go":
            return all_targets[1:]
        return all_targets

    def _available_targets(self) -> list[tuple[str, str, int]]:
        """Filter _targets() to only those that are currently reachable."""
        return [
            (label, host, port)
            for label, host, port in self._targets()
            if _check_port(host, port, timeout=1.0)
        ]

    def _flush(self) -> None:
        if _flush_redis(self.cfg):
            _progress("Redis flushed")
        else:
            _progress("Redis flush skipped / unavailable")

    def _run_throughput(
        self,
        label: str,
        host: str,
        port: int,
        threads: int,
        duration: float,
        ctx: ssl.SSLContext = BROWSER_CTX,
    ) -> ThroughputRun:
        _progress(f"{label}: {threads} threads × {duration:.0f}s ...")
        run = _measure_throughput(host, port, ctx, duration, threads, self.cfg.connect_timeout)
        _progress(
            f"  → {run.conn_per_sec:.0f} conn/s  "
            f"(ok={run.allowed} blk={run.blocked} err={run.errors})"
        )
        return run

    def _run_sequential(
        self,
        label: str,
        host: str,
        port: int,
        count: int,
        ctx: ssl.SSLContext = BROWSER_CTX,
    ) -> list[ConnectionSample]:
        _progress(f"{label}: {count} sequential connections ...")
        samples = _measure_sequential(host, port, ctx, count, self.cfg.connect_timeout)
        ok = sum(1 for s in samples if s.outcome == "allowed")
        lat = sorted(s.latency_ms for s in samples if s.outcome != "error")
        p99 = lat[max(0, int(len(lat) * 0.99) - 1)] if lat else 0
        _progress(f"  → {ok}/{count} allowed, p99={p99:.1f}ms")
        return samples

    # ── Scenario 1: Baseline latency ──────────────────────────────────────────

    def scenario_baseline_latency(self) -> ScenarioResult:
        _scenario_header("baseline_latency", "100 sequential browser-like TLS connections, latency distribution")
        t0 = time.monotonic()
        result = ScenarioResult(
            name="baseline_latency",
            description="100 sequential TLS connections (browser context, no load)",
        )
        self._flush()
        for label, host, port in self._available_targets():
            pr = ProxyResult(proxy_name=label)
            pr.samples = self._run_sequential(label, host, port, 100, BROWSER_CTX)
            setattr(result, label, pr)
        result.wall_time_s = time.monotonic() - t0
        return result

    # ── Scenario 2: Throughput vs concurrency ────────────────────────────────

    def scenario_throughput_scaling(self) -> ScenarioResult:
        _scenario_header("throughput_scaling",
                         "Increase thread count 1→2→4→8→16→N, measure conn/s at each step")
        t0 = time.monotonic()
        result = ScenarioResult(
            name="throughput_scaling",
            description="Throughput vs concurrency scaling curve (browser TLS, 15 s per step)",
        )
        thread_steps = [1, 2, 4, 8, 16]
        if self.cfg.max_threads >= 32:
            thread_steps.append(32)
        if self.cfg.max_threads >= 64:
            thread_steps.append(64)

        dur = self.cfg.duration_quick
        self._flush()

        for label, host, port in self._available_targets():
            pr = ProxyResult(proxy_name=label)
            for threads in thread_steps:
                run = self._run_throughput(label, host, port, threads, dur)
                pr.throughput_runs.append(run)
                time.sleep(1)  # brief cooldown between steps
            setattr(result, label, pr)

        result.wall_time_s = time.monotonic() - t0
        return result

    # ── Scenario 3: Peak throughput ───────────────────────────────────────────

    def scenario_peak_throughput(self) -> ScenarioResult:
        _scenario_header("peak_throughput",
                         f"Max conn/s at {self.cfg.max_threads} threads sustained")
        t0 = time.monotonic()
        result = ScenarioResult(
            name="peak_throughput",
            description=f"Peak throughput: {self.cfg.max_threads} threads × {self.cfg.duration_quick}s",
        )
        self._flush()
        for label, host, port in self._available_targets():
            pr = ProxyResult(proxy_name=label)
            run = self._run_throughput(
                label, host, port, self.cfg.max_threads, self.cfg.duration_quick
            )
            pr.throughput_runs.append(run)
            setattr(result, label, pr)
        result.wall_time_s = time.monotonic() - t0
        return result

    # ── Scenario 4: Mixed traffic ─────────────────────────────────────────────

    def scenario_mixed_traffic(self) -> ScenarioResult:
        _scenario_header("mixed_traffic",
                         "Browser (h2 ALPN) vs bot (no ALPN) ratio sweep: 100/0, 75/25, 50/50, 25/75, 0/100")
        t0 = time.monotonic()
        result = ScenarioResult(
            name="mixed_traffic",
            description="Browser vs bot ratio sweep: 100/0, 75/25, 50/50, 25/75, 0/100",
        )
        # ratios = (browser_pct, bot_pct)
        ratios = [(100, 0), (75, 25), (50, 50), (25, 75), (0, 100)]
        threads = min(16, self.cfg.max_threads)
        dur = self.cfg.duration_quick

        for label, host, port in self._available_targets():
            pr = ProxyResult(proxy_name=label)
            ratio_results = []

            for browser_pct, bot_pct in ratios:
                self._flush()
                _progress(f"{label}: {browser_pct}% browser / {bot_pct}% bot ({threads} threads) ...")

                deadline = time.monotonic() + dur
                counters: dict = {
                    "browser_allowed": 0, "browser_blocked": 0, "browser_error": 0,
                    "bot_allowed": 0, "bot_blocked": 0, "bot_error": 0,
                    "total": 0,
                }
                lock = threading.Lock()

                def _mixed_worker(bpct: int) -> None:  # noqa: ANN001
                    while time.monotonic() < deadline:
                        is_browser = random.randint(1, 100) <= bpct
                        ctx = BROWSER_CTX if is_browser else BOT_CTX
                        s = _connect_once(host, port, ctx, self.cfg.connect_timeout)
                        kind = "browser" if is_browser else "bot"
                        with lock:
                            counters["total"] += 1
                            if s.outcome == "allowed":
                                counters[f"{kind}_allowed"] += 1
                            elif s.outcome in ("blocked", "timeout"):
                                counters[f"{kind}_blocked"] += 1
                            else:
                                counters[f"{kind}_error"] += 1

                # bind browser_pct in closure
                bpct_val = browser_pct
                with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
                    futures = [pool.submit(_mixed_worker, bpct_val) for _ in range(threads)]
                    for f in concurrent.futures.as_completed(futures):
                        f.result()

                ratio_results.append({
                    "browser_pct": browser_pct,
                    "bot_pct": bot_pct,
                    **counters,
                })
                _progress(
                    f"  → total={counters['total']} "
                    f"browser_pass={counters['browser_allowed']} "
                    f"bot_pass={counters['bot_allowed']}"
                )
                time.sleep(2)

            pr.extra["ratio_results"] = ratio_results
            # Create a synthetic ThroughputRun from the 50/50 case for comparison
            for rr in ratio_results:
                if rr["browser_pct"] == 50:
                    synthetic_total = rr["total"]
                    pr.throughput_runs.append(ThroughputRun(
                        threads=threads,
                        duration_s=dur,
                        total=synthetic_total,
                        allowed=rr["browser_allowed"] + rr["bot_allowed"],
                        blocked=rr["browser_blocked"] + rr["bot_blocked"],
                        errors=rr["browser_error"] + rr["bot_error"],
                        elapsed_s=dur,
                    ))
                    break
            setattr(result, label, pr)

        result.wall_time_s = time.monotonic() - t0
        return result

    # ── Scenario 5: Sustained load ────────────────────────────────────────────

    def scenario_sustained_load(self) -> ScenarioResult:
        _scenario_header("sustained_load",
                         "60 s sustained load at multiple rates; look for throughput degradation")
        t0 = time.monotonic()
        result = ScenarioResult(
            name="sustained_load",
            description=f"Sustained load ({self.cfg.duration_long}s each): 8, 16, {self.cfg.max_threads} threads",
        )
        thread_levels = [8, 16, self.cfg.max_threads]
        dur = self.cfg.duration_long

        for label, host, port in self._available_targets():
            pr = ProxyResult(proxy_name=label)
            for threads in thread_levels:
                self._flush()
                # Collect time-series: split duration into 6 windows to detect drift
                window_s = dur / 6
                window_results = []
                _progress(f"{label}: {threads} threads × {dur:.0f}s (6 windows) ...")
                for w in range(6):
                    wr = _measure_throughput(
                        host, port, BROWSER_CTX, window_s, threads,
                        self.cfg.connect_timeout,
                    )
                    window_results.append(wr.conn_per_sec)
                    _progress(f"  window {w+1}: {wr.conn_per_sec:.0f} conn/s")
                # Combine into one ThroughputRun
                run = _measure_throughput(host, port, BROWSER_CTX, dur, threads,
                                         self.cfg.connect_timeout)
                pr.throughput_runs.append(run)
                pr.extra.setdefault("sustained_windows", {})[threads] = window_results
            setattr(result, label, pr)

        # Detect drift: compare first vs last window
        for label in ("python", "go"):
            pr = getattr(result, label, None)
            if pr is None:
                continue
            windows = pr.extra.get("sustained_windows", {})
            for threads, wrs in windows.items():
                if len(wrs) >= 2:
                    drift_pct = (wrs[-1] - wrs[0]) / wrs[0] * 100 if wrs[0] else 0
                    if abs(drift_pct) > 15:
                        result.notes.append(
                            f"{label} @ {threads} threads: throughput drifted "
                            f"{drift_pct:+.0f}% from window 1 to window 6"
                        )

        result.wall_time_s = time.monotonic() - t0
        return result

    # ── Scenario 6: Warm cache ────────────────────────────────────────────────

    def scenario_warm_cache(self) -> ScenarioResult:
        _scenario_header("warm_cache",
                         "Small pool of 10 IPs recycled — Redis hit path via PROXY-protocol spoofing workaround")
        t0 = time.monotonic()
        result = ScenarioResult(
            name="warm_cache",
            description="Warm-cache path: 10 source IPs cycling through proxy (all paths pre-warmed)",
        )
        # Since we can't control source IP in user space without raw sockets,
        # we approximate "warm cache" by running 20 connections first to prime Redis
        # then measuring the hot-path throughput.
        threads = min(8, self.cfg.max_threads)
        dur = self.cfg.duration_quick

        self._flush()
        # Warm-up: 20 sequential connections to prime any in-process LRU caches
        _progress("Pre-warming caches (20 connections) ...")
        for _, host, port in self._available_targets():
            _measure_sequential(host, port, BROWSER_CTX, 20, self.cfg.connect_timeout)

        time.sleep(1)
        for label, host, port in self._available_targets():
            pr = ProxyResult(proxy_name=label)
            run = self._run_throughput(label, host, port, threads, dur)
            pr.throughput_runs.append(run)
            setattr(result, label, pr)
        result.notes.append(
            "Warm cache approximated by 20-connection pre-warm; "
            "true cache key variation requires PROXY-protocol source IP control."
        )
        result.wall_time_s = time.monotonic() - t0
        return result

    # ── Scenario 7: Cold cache ─────────────────────────────────────────────────

    def scenario_cold_cache(self) -> ScenarioResult:
        _scenario_header("cold_cache",
                         "Fresh Redis flush before each run — every decision hits Redis miss path")
        t0 = time.monotonic()
        result = ScenarioResult(
            name="cold_cache",
            description="Cold-cache path: Redis flushed immediately before run",
        )
        threads = min(8, self.cfg.max_threads)
        dur = self.cfg.duration_quick

        for label, host, port in self._available_targets():
            self._flush()
            time.sleep(0.5)  # let any pending Redis writes complete
            pr = ProxyResult(proxy_name=label)
            run = self._run_throughput(label, host, port, threads, dur)
            pr.throughput_runs.append(run)
            setattr(result, label, pr)
        result.wall_time_s = time.monotonic() - t0
        return result

    # ── Scenario 8: Burst load ────────────────────────────────────────────────

    def scenario_burst_load(self) -> ScenarioResult:
        _scenario_header("burst_load",
                         "Ramp from 1→max threads over 10 s, hold at max for 20 s, drop back to 1")
        t0 = time.monotonic()
        result = ScenarioResult(
            name="burst_load",
            description="Burst: ramp 1→max threads over 10s, hold 20s, drop to 1 for 10s",
        )
        self._flush()
        max_t = self.cfg.max_threads

        for label, host, port in self._available_targets():
            pr = ProxyResult(proxy_name=label)
            phases = [
                ("ramp", max(1, max_t // 4), 10),
                ("peak", max_t, 20),
                ("recovery", 1, 10),
            ]
            phase_data = []
            _progress(f"{label}: burst (ramp / peak / recovery) ...")
            for phase_name, threads, dur in phases:
                run = _measure_throughput(
                    host, port, BROWSER_CTX, float(dur), threads,
                    self.cfg.connect_timeout
                )
                pr.throughput_runs.append(run)
                phase_data.append({"phase": phase_name, "threads": threads,
                                   "conn_per_sec": run.conn_per_sec})
                _progress(f"  {phase_name}: {run.conn_per_sec:.0f} conn/s")
            pr.extra["burst_phases"] = phase_data
            setattr(result, label, pr)

        result.wall_time_s = time.monotonic() - t0
        return result

    # ── Scenario 9: Adversarial TLS ───────────────────────────────────────────

    def scenario_adversarial_tls(self) -> ScenarioResult:
        _scenario_header("adversarial_tls",
                         "Incomplete handshakes, garbage data, immediate closes, TLS 1.2-only")
        t0 = time.monotonic()
        result = ScenarioResult(
            name="adversarial_tls",
            description="Adversarial inputs: garbage bytes, immediate close, TLS 1.2-only, no SNI",
        )
        count = 50  # per adversarial type

        for label, host, port in self._available_targets():
            pr = ProxyResult(proxy_name=label)
            adv_results = {}

            # Type 1: Garbage data (no valid TLS)
            _progress(f"{label}: {count} garbage-data connections ...")
            garbage_samples = [
                _connect_send_garbage(host, port, self.cfg.connect_timeout)
                for _ in range(count)
            ]
            pr.samples.extend(garbage_samples)
            adv_results["garbage"] = {
                "count": count,
                "blocked": sum(1 for s in garbage_samples if s.outcome == "blocked"),
                "error": sum(1 for s in garbage_samples if s.outcome == "error"),
                "mean_ms": statistics.mean(s.latency_ms for s in garbage_samples),
            }
            _progress(f"  blocked={adv_results['garbage']['blocked']}, "
                      f"mean={adv_results['garbage']['mean_ms']:.1f}ms")

            # Type 2: Immediate close (zero-byte connection)
            _progress(f"{label}: {count} immediate-close connections ...")
            close_samples = [
                _connect_immediate_close(host, port, self.cfg.connect_timeout)
                for _ in range(count)
            ]
            adv_results["immediate_close"] = {
                "count": count,
                "allowed": sum(1 for s in close_samples if s.outcome == "allowed"),
                "error": sum(1 for s in close_samples if s.outcome == "error"),
                "mean_ms": statistics.mean(s.latency_ms for s in close_samples),
            }
            _progress(f"  accepted={adv_results['immediate_close']['allowed']}, "
                      f"mean={adv_results['immediate_close']['mean_ms']:.1f}ms")

            # Type 3: TLS 1.2-only (older scanner fingerprint)
            _progress(f"{label}: {count} TLS-1.2-only connections ...")
            tls12_samples = [
                _connect_once(host, port, TLS12_CTX, self.cfg.connect_timeout)
                for _ in range(count)
            ]
            pr.samples.extend(tls12_samples)
            adv_results["tls12_only"] = {
                "count": count,
                "allowed": sum(1 for s in tls12_samples if s.outcome == "allowed"),
                "blocked": sum(1 for s in tls12_samples if s.outcome == "blocked"),
                "mean_ms": statistics.mean(s.latency_ms for s in tls12_samples),
            }
            _progress(f"  allowed={adv_results['tls12_only']['allowed']}, "
                      f"mean={adv_results['tls12_only']['mean_ms']:.1f}ms")

            # Type 4: Bot-like TLS (no ALPN)
            _progress(f"{label}: {count} bot-fingerprint connections ...")
            bot_samples = [
                _connect_once(host, port, BOT_CTX, self.cfg.connect_timeout)
                for _ in range(count)
            ]
            pr.samples.extend(bot_samples)
            adv_results["bot_noalpn"] = {
                "count": count,
                "allowed": sum(1 for s in bot_samples if s.outcome == "allowed"),
                "blocked": sum(1 for s in bot_samples if s.outcome == "blocked"),
                "mean_ms": statistics.mean(s.latency_ms for s in bot_samples),
            }
            _progress(f"  allowed={adv_results['bot_noalpn']['allowed']}, "
                      f"mean={adv_results['bot_noalpn']['mean_ms']:.1f}ms")

            pr.extra["adversarial"] = adv_results
            setattr(result, label, pr)

        result.wall_time_s = time.monotonic() - t0
        return result

    # ── Scenario 10: Deep latency percentiles ─────────────────────────────────

    def scenario_latency_percentiles(self) -> ScenarioResult:
        _scenario_header("latency_percentiles",
                         "500 sequential connections; full p50/p90/p95/p99/p99.9 distribution")
        t0 = time.monotonic()
        result = ScenarioResult(
            name="latency_percentiles",
            description="Deep latency percentile breakdown: 500 sequential browser-TLS connections",
        )
        self._flush()
        for label, host, port in self._available_targets():
            pr = ProxyResult(proxy_name=label)
            pr.samples = self._run_sequential(label, host, port, 500, BROWSER_CTX)
            setattr(result, label, pr)
        result.wall_time_s = time.monotonic() - t0
        return result

    # ── Scenario 11: 500 conn/s DDoS simulation ───────────────────────────────

    def scenario_attack_500(self) -> ScenarioResult:
        rate = self.cfg.attack_rate
        good_pct = 5    # % browser (h2 ALPN) — the legitimate traffic
        bad_pct = 95    # % bot (no ALPN)      — the attack traffic
        dur = self.cfg.duration_long
        n_threads = max(8, rate // 40)  # threads needed to sustain the rate

        pp_note = (
            f"PPv2 source-IP injection enabled: {self.cfg.source_ip_pool_size} "
            "synthetic IPs from 10.0.0.0/8."
            if self.cfg.use_proxy_protocol
            else
            "PPv2 disabled: all connections appear from the benchmark host. "
            "Per-IP rate limiting may cap throughput below the target."
        )
        _scenario_header(
            "attack_500",
            f"DDoS simulation: {rate} conn/s × {dur}s; "
            f"{good_pct}% browser / {bad_pct}% bot; {n_threads} threads; "
            + ("PPv2 IP rotation" if self.cfg.use_proxy_protocol else "no PPv2"),
        )

        ip_pool: list[str] = []
        if self.cfg.use_proxy_protocol:
            _progress(f"Building IP pool ({self.cfg.source_ip_pool_size} addresses) ...")
            ip_pool = _build_ip_pool(self.cfg.source_ip_pool_size)

        t0_scenario = time.monotonic()
        result = ScenarioResult(
            name="attack_500",
            description=(
                f"DDoS simulation: {rate} conn/s, {good_pct}% browser, "
                f"{bad_pct}% bot, {dur}s sustained"
            ),
            notes=[pp_note],
        )

        bucket = _TokenBucket(float(rate))
        self._flush()

        for label, host, port in self._available_targets():
            _progress(
                f"{label}: {rate} conn/s target × {dur}s  "
                f"({good_pct}% browser / {bad_pct}% bot, {n_threads} threads) ..."
            )

            deadline = time.monotonic() + dur
            counters: dict[str, int] = {
                "total": 0,
                "good_allowed": 0, "good_blocked": 0, "good_error": 0,
                "bad_allowed":  0, "bad_blocked":  0, "bad_error":  0,
            }
            ctr_lock = threading.Lock()

            def _attack_worker(
                _host: str = host,
                _port: int = port,
                _deadline: float = deadline,
                _ip_pool: list = ip_pool,
            ) -> None:
                while time.monotonic() < _deadline:
                    bucket.acquire()
                    if time.monotonic() >= _deadline:
                        break
                    is_browser = random.randint(1, 100) <= good_pct
                    ctx = BROWSER_CTX if is_browser else BOT_CTX
                    pre_send = b""
                    if _ip_pool:
                        src_ip = random.choice(_ip_pool)  # noqa: S311 — not crypto
                        pre_send = _make_pp2_header(src_ip, _host, _port)
                    sample = _connect_once(
                        _host, _port, ctx,
                        self.cfg.connect_timeout,
                        pre_send=pre_send,
                    )
                    kind = "good" if is_browser else "bad"
                    with ctr_lock:
                        counters["total"] += 1
                        if sample.outcome == "allowed":
                            counters[f"{kind}_allowed"] += 1
                        elif sample.outcome in ("blocked", "timeout"):
                            counters[f"{kind}_blocked"] += 1
                        else:
                            counters[f"{kind}_error"] += 1

            t0_run = time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=n_threads) as pool:
                futures = [pool.submit(_attack_worker) for _ in range(n_threads)]
                for f in concurrent.futures.as_completed(futures):
                    f.result()
            elapsed = time.monotonic() - t0_run

            actual_rate = counters["total"] / elapsed if elapsed > 0 else 0.0
            good_total = (
                counters["good_allowed"] + counters["good_blocked"] + counters["good_error"]
            )
            bad_total = (
                counters["bad_allowed"] + counters["bad_blocked"] + counters["bad_error"]
            )
            good_pass_pct = (
                counters["good_allowed"] / good_total * 100 if good_total else 0.0
            )
            bad_block_pct = (
                counters["bad_blocked"] / bad_total * 100 if bad_total else 0.0
            )

            _progress(
                f"  → {actual_rate:.0f} conn/s actual  (target={rate})"
            )
            _progress(
                f"     good (browser): {good_total} total, "
                f"{good_pass_pct:.1f}% pass, "
                f"{counters['good_blocked']} blocked"
            )
            _progress(
                f"     bad  (bot):     {bad_total} total, "
                f"{bad_block_pct:.1f}% block, "
                f"{counters['bad_allowed']} slipped through"
            )

            pr = ProxyResult(proxy_name=label)
            pr.throughput_runs.append(ThroughputRun(
                threads=n_threads,
                duration_s=dur,
                total=counters["total"],
                allowed=counters["good_allowed"] + counters["bad_allowed"],
                blocked=counters["good_blocked"] + counters["bad_blocked"],
                errors=counters["good_error"] + counters["bad_error"],
                elapsed_s=elapsed,
            ))
            pr.extra["attack_detail"] = {
                "target_rate":           rate,
                "actual_rate":           round(actual_rate, 1),
                "good_pct":              good_pct,
                "bad_pct":               bad_pct,
                "good_allowed":          counters["good_allowed"],
                "good_blocked":          counters["good_blocked"],
                "bad_allowed":           counters["bad_allowed"],
                "bad_blocked":           counters["bad_blocked"],
                "good_pass_pct":         round(good_pass_pct, 2),
                "bad_block_pct":         round(bad_block_pct, 2),
                "proxy_protocol":        self.cfg.use_proxy_protocol,
                "ip_pool_size":          len(ip_pool),
            }
            setattr(result, label, pr)
            self._flush()

        result.wall_time_s = time.monotonic() - t0_scenario
        return result

    # ── Dispatcher ────────────────────────────────────────────────────────────

    _DISPATCH = {
        "baseline_latency":    scenario_baseline_latency,
        "throughput_scaling":  scenario_throughput_scaling,
        "peak_throughput":     scenario_peak_throughput,
        "mixed_traffic":       scenario_mixed_traffic,
        "sustained_load":      scenario_sustained_load,
        "warm_cache":          scenario_warm_cache,
        "cold_cache":          scenario_cold_cache,
        "burst_load":          scenario_burst_load,
        "adversarial_tls":     scenario_adversarial_tls,
        "latency_percentiles": scenario_latency_percentiles,
        "attack_500":          scenario_attack_500,
    }

    def run_scenarios(self) -> None:
        targets = self._available_targets()
        if not targets:
            _log(
                "ERROR: no proxies reachable. Start services first.\n"
                f"  Python proxy: {self.cfg.python_host}:{self.cfg.python_port}\n"
                f"  Go proxy:     {self.cfg.go_host}:{self.cfg.go_port}",
                prefix="",
            )
            sys.exit(1)

        _log(f"\nAvailable targets: {[t[0] for t in targets]}", prefix="")
        _log(f"Scenarios to run:  {self.cfg.scenarios}", prefix="")

        for name in self.cfg.scenarios:
            fn = self._DISPATCH.get(name)
            if fn is None:
                _log(f"WARNING: unknown scenario '{name}', skipping")
                continue
            scenario_result = fn(self)
            self.results.append(scenario_result)
            time.sleep(2)  # brief inter-scenario cooldown

        _log(f"\nAll {len(self.results)} scenarios complete.", prefix="")


# ── ASCII chart ────────────────────────────────────────────────────────────────

def _ascii_bar_chart(
    data: list[tuple[str, float]],
    title: str,
    width: int = 50,
) -> str:
    """Simple horizontal bar chart for Markdown code blocks."""
    if not data:
        return ""
    max_val = max(v for _, v in data) or 1
    lines = [title, ""]
    for label, val in data:
        bar_len = int(val / max_val * width)
        bar = "█" * bar_len
        lines.append(f"  {label:>20} │{bar:<{width}} {val:.0f}")
    return "\n".join(lines)


def _sparkline(values: list[float], width: int = 20) -> str:
    """Generate a tiny spark-line from a list of floats."""
    if not values:
        return ""
    chars = "▁▂▃▄▅▆▇█"
    mn, mx = min(values), max(values)
    rng = mx - mn or 1
    return "".join(chars[int((v - mn) / rng * (len(chars) - 1))] for v in values)


# ── Markdown report ───────────────────────────────────────────────────────────

class ReportGenerator:
    """Renders benchmark results to Markdown and JSON."""

    def __init__(
        self,
        results: list[ScenarioResult],
        cfg: BenchmarkConfig,
        system_info: dict,
    ) -> None:
        self.results = results
        self.cfg = cfg
        self.sys = system_info

    # ── helpers ──

    def _fmt_ms(self, ms: float) -> str:
        return f"{ms:.2f} ms"

    def _fmt_ratio(self, r: Optional[float]) -> str:
        if r is None:
            return "N/A"
        return f"{r:.1f}×"

    def _lat_row(self, pr: Optional[ProxyResult]) -> str:
        if pr is None:
            return "| — | — | — | — | — | — |"
        lats = [pr.latency_percentile(p) for p in (50, 90, 95, 99)]
        mean = pr.mean_latency()
        std = pr.stdev_latency()
        return (
            f"| {self._fmt_ms(mean)} | {self._fmt_ms(std)} "
            + " ".join(f"| {self._fmt_ms(lat)}" for lat in lats)
            + " |"
        )

    # ── sections ──

    def _executive_summary(self) -> str:
        lines = ["## Executive Summary\n"]

        # Collect speedup ratios across all throughput-heavy scenarios
        speedups = []
        latency_improvements = []
        for sr in self.results:
            if sr.name in ("throughput_scaling", "peak_throughput", "sustained_load"):
                s = sr.speedup()
                if s is not None:
                    speedups.append((sr.name, s))
            if sr.name in ("baseline_latency", "latency_percentiles"):
                li = sr.latency_improvement()
                if li is not None:
                    latency_improvements.append((sr.name, li))

        if speedups:
            avg_speedup = statistics.mean(v for _, v in speedups)
            min_speedup = min(v for _, v in speedups)
            max_speedup = max(v for _, v in speedups)
            lines.append(
                f"**Go proxy throughput advantage:** {avg_speedup:.1f}× average "
                f"(range: {min_speedup:.1f}–{max_speedup:.1f}× across scenarios)\n"
            )
        else:
            lines.append("*Both proxies tested. Throughput comparison not available "
                         "(only one proxy reached).*\n")

        if latency_improvements:
            avg_lat = statistics.mean(v for _, v in latency_improvements)
            lines.append(
                f"**Go proxy p99 latency improvement:** {avg_lat:.1f}× lower "
                f"(Python p99 / Go p99)\n"
            )

        lines.append("### Throughput Speedup by Scenario\n")
        lines.append("| Scenario | Go conn/s | Python conn/s | Speedup |")
        lines.append("|----------|-----------|---------------|---------|")
        for sr in self.results:
            go_tp = sr.go.peak_throughput() if sr.go else None
            py_tp = sr.python.peak_throughput() if sr.python else None
            speedup = sr.speedup()
            lines.append(
                f"| {sr.name} "
                f"| {go_tp:.0f}" if go_tp is not None else "| —"
                + f"| {py_tp:.0f}" if py_tp is not None else " | —"
                + f"| {self._fmt_ratio(speedup)} |"
            )

        # Build proper table
        lines2 = ["### Throughput Speedup by Scenario\n"]
        lines2.append("| Scenario | Go conn/s | Python conn/s | Speedup |")
        lines2.append("|----------|-----------|---------------|---------|")
        for sr in self.results:
            go_tp = f"{sr.go.peak_throughput():.0f}" if sr.go else "—"
            py_tp = f"{sr.python.peak_throughput():.0f}" if sr.python else "—"
            speedup = self._fmt_ratio(sr.speedup())
            lines2.append(f"| {sr.name} | {go_tp} | {py_tp} | {speedup} |")

        # Return only the clean version
        return "\n".join(
            ["## Executive Summary\n"]
            + (
                [f"**Go proxy throughput advantage:** {avg_speedup:.1f}× average "
                 f"(range: {min_speedup:.1f}–{max_speedup:.1f}×)\n"]
                if speedups else
                ["*Throughput comparison unavailable — only one proxy reachable.*\n"]
            )
            + (
                [f"**Go proxy p99 latency improvement:** {avg_lat:.1f}× "
                 f"(Python p99 / Go p99)\n"]
                if latency_improvements else []
            )
            + [""]
            + lines2
        )

    def _system_section(self) -> str:
        lines = ["## Test Environment\n"]
        lines.append(f"- **Date:**       {self.sys.get('timestamp', 'unknown')}")
        lines.append(f"- **Host:**       {self.sys.get('hostname', 'unknown')}")
        lines.append(f"- **Platform:**   {self.sys.get('platform', 'unknown')}")
        lines.append(f"- **CPU:**        {self.sys.get('cpu_model', 'unknown')} "
                     f"({self.sys.get('cpu_count', '?')} logical cores)")
        lines.append(f"- **Memory:**     {self.sys.get('memory_gb', '?')} GB")
        lines.append(f"- **Python:**     {self.sys.get('python_version', 'unknown')}")
        lines.append(f"- **Benchmark v:** {BENCHMARK_VERSION}")
        lines.append("")
        lines.append("### Proxy Configuration")
        lines.append(f"- **Python proxy:** {self.cfg.python_host}:{self.cfg.python_port}")
        lines.append(f"- **Go proxy:**     {self.cfg.go_host}:{self.cfg.go_port}")
        lines.append(f"- **Quick duration:** {self.cfg.duration_quick}s")
        lines.append(f"- **Long duration:**  {self.cfg.duration_long}s")
        lines.append(f"- **Max threads:**    {self.cfg.max_threads}")
        lines.append(f"- **Connect timeout:** {self.cfg.connect_timeout}s")
        return "\n".join(lines)

    def _scenario_section(self, sr: ScenarioResult) -> str:
        lines = [f"## Scenario: `{sr.name}`\n", f"*{sr.description}*\n"]
        lines.append(f"**Wall time:** {sr.wall_time_s:.1f}s\n")

        if sr.notes:
            lines.append("**Notes:**")
            for note in sr.notes:
                lines.append(f"- {note}")
            lines.append("")

        # ── Latency table (for scenarios with sequential samples) ──
        has_samples = (
            (sr.python and sr.python.samples) or
            (sr.go and sr.go.samples)
        )
        if has_samples:
            lines.append("### Latency Distribution\n")
            lines.append("| Proxy | Mean | StdDev | p50 | p90 | p95 | p99 |")
            lines.append("|-------|------|--------|-----|-----|-----|-----|")
            for label, pr in (("Python", sr.python), ("Go", sr.go)):
                if pr is None:
                    lines.append(f"| {label} | — | — | — | — | — | — |")
                else:
                    row = self._lat_row(pr)
                    lines.append(f"| {label} {row}")
            lines.append("")

        # ── Throughput table (for scenarios with throughput runs) ──
        has_tp = (
            (sr.python and sr.python.throughput_runs) or
            (sr.go and sr.go.throughput_runs)
        )
        if has_tp:
            lines.append("### Throughput Results\n")
            lines.append("| Proxy | Threads | conn/s | Total | Allowed | Blocked | Errors |")
            lines.append("|-------|---------|--------|-------|---------|---------|--------|")
            for label, pr in (("Python", sr.python), ("Go", sr.go)):
                if pr is None:
                    continue
                for run in pr.throughput_runs:
                    lines.append(
                        f"| {label} | {run.threads} | {run.conn_per_sec:.0f} "
                        f"| {run.total} | {run.allowed} | {run.blocked} | {run.errors} |"
                    )
            lines.append("")

        # ── Speedup comparison ──
        speedup = sr.speedup()
        lat_imp = sr.latency_improvement()
        if speedup is not None or lat_imp is not None:
            lines.append("### Comparison\n")
            if speedup is not None:
                icon = "✅" if speedup >= 5 else ("⚠️" if speedup >= 2 else "❌")
                lines.append(f"- **Throughput speedup:** {speedup:.1f}× (Go/Python) {icon}")
            if lat_imp is not None:
                icon = "✅" if lat_imp >= 3 else ("⚠️" if lat_imp >= 1.5 else "❌")
                lines.append(f"- **p99 latency improvement:** {lat_imp:.1f}× {icon}")
            lines.append("")

        # ── Scenario-specific sections ──

        if sr.name == "throughput_scaling":
            # ASCII bar chart of throughput vs threads
            for label, pr in (("Python", sr.python), ("Go", sr.go)):
                if pr is None or not pr.throughput_runs:
                    continue
                chart_data = [
                    (f"{r.threads} threads", r.conn_per_sec) for r in pr.throughput_runs
                ]
                chart = _ascii_bar_chart(chart_data, f"{label} proxy: throughput vs threads")
                lines.append(f"```\n{chart}\n```\n")

        if sr.name == "mixed_traffic":
            for label, pr in (("Python", sr.python), ("Go", sr.go)):
                if pr is None or "ratio_results" not in pr.extra:
                    continue
                lines.append(f"### {label.capitalize()} proxy: browser/bot ratio sweep\n")
                lines.append("| Browser% | Bot% | Total | Browser pass | Bot pass | Bot block |")
                lines.append("|----------|------|-------|--------------|----------|-----------|")
                for rr in pr.extra["ratio_results"]:
                    total = rr["total"]
                    ba = rr["browser_allowed"]
                    bot_a = rr["bot_allowed"]
                    bot_b = rr["bot_blocked"]
                    lines.append(
                        f"| {rr['browser_pct']}% | {rr['bot_pct']}% "
                        f"| {total} | {ba} | {bot_a} | {bot_b} |"
                    )
                lines.append("")

        if sr.name == "sustained_load":
            for label, pr in (("Python", sr.python), ("Go", sr.go)):
                if pr is None or "sustained_windows" not in pr.extra:
                    continue
                lines.append(f"### {label.capitalize()} proxy: throughput over time\n")
                for threads, windows in pr.extra["sustained_windows"].items():
                    spark = _sparkline(windows)
                    mn = min(windows)
                    mx = max(windows)
                    drift = (windows[-1] - windows[0]) / windows[0] * 100 if windows[0] else 0
                    lines.append(f"- **{threads} threads:** {spark}  "
                                 f"min={mn:.0f} max={mx:.0f} drift={drift:+.0f}%")
                lines.append("")

        if sr.name == "burst_load":
            for label, pr in (("Python", sr.python), ("Go", sr.go)):
                if pr is None or "burst_phases" not in pr.extra:
                    continue
                lines.append(f"### {label.capitalize()} proxy: burst phases\n")
                for phase in pr.extra["burst_phases"]:
                    lines.append(
                        f"- **{phase['phase']}** ({phase['threads']} threads): "
                        f"{phase['conn_per_sec']:.0f} conn/s"
                    )
                lines.append("")

        if sr.name == "adversarial_tls":
            for label, pr in (("Python", sr.python), ("Go", sr.go)):
                if pr is None or "adversarial" not in pr.extra:
                    continue
                lines.append(f"### {label.capitalize()} proxy: adversarial inputs\n")
                lines.append("| Type | Count | Blocked | Error | Mean latency |")
                lines.append("|------|-------|---------|-------|--------------|")
                for atype, data in pr.extra["adversarial"].items():
                    lines.append(
                        f"| {atype} | {data['count']} "
                        f"| {data.get('blocked', '—')} "
                        f"| {data.get('error', '—')} "
                        f"| {self._fmt_ms(data['mean_ms'])} |"
                    )
                lines.append("")

        if sr.name == "attack_500":
            for label, pr in (("Python", sr.python), ("Go", sr.go)):
                if pr is None or "attack_detail" not in pr.extra:
                    continue
                d = pr.extra["attack_detail"]
                lines.append(f"### {label.capitalize()} proxy: DDoS simulation detail\n")
                lines.append(
                    f"- **Target rate:** {d['target_rate']} conn/s  "
                    f"**Actual rate:** {d['actual_rate']:.0f} conn/s  "
                    f"({'✅' if d['actual_rate'] >= d['target_rate'] * 0.9 else '⚠️ below target'})"
                )
                good_total = d["good_allowed"] + d["good_blocked"]
                bad_total = d["bad_allowed"] + d["bad_blocked"]
                lines.append(
                    f"- **Good (browser) traffic:** {good_total} connections — "
                    f"{d['good_pass_pct']:.1f}% passed "
                    f"({'✅ no FPs' if d['good_pass_pct'] >= 99 else '❌ false positives detected'})"
                )
                lines.append(
                    f"- **Bad (bot) traffic:** {bad_total} connections — "
                    f"{d['bad_block_pct']:.1f}% blocked "
                    f"({d['bad_allowed']} slipped through)"
                )
                pp_str = (
                    f"enabled — {d['ip_pool_size']} synthetic source IPs"
                    if d["proxy_protocol"]
                    else "disabled (single source IP)"
                )
                lines.append(f"- **PROXY protocol v2:** {pp_str}")
                lines.append("")

        return "\n".join(lines)

    # ── full report ──

    def generate_markdown(self) -> str:
        sections = [
            "# JA4proxy Benchmark Report: Go vs Python\n",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Benchmark version:** {BENCHMARK_VERSION}  \n",
            self._executive_summary(),
            "",
            self._system_section(),
            "",
            "## Scenario Results\n",
        ]
        for sr in self.results:
            sections.append(self._scenario_section(sr))
            sections.append("---\n")

        sections.append("## Appendix: Phase 15 Acceptance Criteria Check\n")
        sections.append(self._acceptance_criteria_check())

        return "\n".join(sections)

    def _acceptance_criteria_check(self) -> str:
        """Check Phase 15 acceptance criteria from PHASE_15.md."""
        lines = []
        # ≥ 5× connections/second
        peak_sr = next((r for r in self.results if r.name == "peak_throughput"), None)
        if peak_sr:
            speedup = peak_sr.speedup()
            if speedup is not None:
                icon = "✅" if speedup >= 5 else "❌"
                lines.append(
                    f"- {icon} **Throughput ≥ 5× Python:** {speedup:.1f}× "
                    f"(required: 5×, from PHASE_15.md §Acceptance Criteria)"
                )
            else:
                lines.append("- ⚠️ Throughput comparison unavailable (only one proxy tested)")
        else:
            lines.append("- ⚠️ `peak_throughput` scenario not run")

        # 1000 conn/s sustained 60s with FP rate < 0.1%
        sustained_sr = next((r for r in self.results if r.name == "sustained_load"), None)
        if sustained_sr:
            for label, pr in (("Python", sustained_sr.python), ("Go", sustained_sr.go)):
                if pr is None:
                    continue
                max_run = max(pr.throughput_runs, key=lambda r: r.conn_per_sec,
                              default=None)
                if max_run:
                    fp_pct = max_run.blocked / max_run.total * 100 if max_run.total else 0
                    meets_rate = max_run.conn_per_sec >= 1000
                    meets_fp = fp_pct < 0.1
                    r_icon = "✅" if meets_rate else "❌"
                    fp_icon = "✅" if meets_fp else "⚠️"
                    lines.append(
                        f"- {r_icon} **1000 conn/s sustained ({label}):** "
                        f"{max_run.conn_per_sec:.0f} conn/s"
                    )
                    lines.append(
                        f"  - {fp_icon} FP rate ({label}): {fp_pct:.3f}% "
                        f"(target: < 0.1%)"
                    )
        else:
            lines.append("- ⚠️ `sustained_load` scenario not run")

        return "\n".join(lines) + "\n"

    def generate_json(self) -> dict:
        """Serialise all results to a JSON-compatible dict."""

        def _pr_to_dict(pr: Optional[ProxyResult]) -> Optional[dict]:
            if pr is None:
                return None
            return {
                "proxy_name": pr.proxy_name,
                "peak_throughput": pr.peak_throughput(),
                "mean_latency_ms": pr.mean_latency(),
                "stdev_latency_ms": pr.stdev_latency(),
                "p50_ms": pr.latency_percentile(50),
                "p90_ms": pr.latency_percentile(90),
                "p95_ms": pr.latency_percentile(95),
                "p99_ms": pr.latency_percentile(99),
                "total_connections": pr.total_connections(),
                "throughput_runs": [
                    dataclasses.asdict(r) for r in pr.throughput_runs
                ],
                "extra": pr.extra,
            }

        return {
            "benchmark_version": BENCHMARK_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "system": self.sys,
            "config": {
                "python_host": self.cfg.python_host,
                "python_port": self.cfg.python_port,
                "go_host": self.cfg.go_host,
                "go_port": self.cfg.go_port,
                "duration_quick": self.cfg.duration_quick,
                "duration_long": self.cfg.duration_long,
                "max_threads": self.cfg.max_threads,
                "scenarios": self.cfg.scenarios,
            },
            "scenarios": [
                {
                    "name": sr.name,
                    "description": sr.description,
                    "wall_time_s": sr.wall_time_s,
                    "speedup": sr.speedup(),
                    "latency_improvement": sr.latency_improvement(),
                    "notes": sr.notes,
                    "python": _pr_to_dict(sr.python),
                    "go": _pr_to_dict(sr.go),
                }
                for sr in self.results
            ],
        }


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_args() -> BenchmarkConfig:
    p = argparse.ArgumentParser(
        description="JA4proxy comprehensive benchmark: Go vs Python proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(__doc__ or ""),
    )
    p.add_argument("--python-host", default="127.0.0.1")
    p.add_argument("--python-port", type=int, default=8080)
    p.add_argument("--go-host", default="127.0.0.1")
    p.add_argument("--go-port", type=int, default=8082)
    p.add_argument("--output-dir", default=None)
    p.add_argument("--duration-quick", type=int, default=15)
    p.add_argument("--duration-long", type=int, default=60)
    p.add_argument("--max-threads", type=int, default=32)
    p.add_argument("--scenarios", default="all",
                   help="Comma-separated scenario names or 'all'")
    p.add_argument("--redis-host", default="127.0.0.1")
    p.add_argument("--redis-port", type=int, default=6379)
    p.add_argument("--redis-password",
                   default=os.environ.get("REDIS_PASSWORD", ""))
    p.add_argument("--no-redis-flush", action="store_true")
    p.add_argument("--quick", action="store_true",
                   help="10s per scenario, fewer threads")
    p.add_argument("--proxy", choices=["python", "go"], default=None,
                   dest="proxy_filter")
    p.add_argument("--connect-timeout", type=float, default=2.0)
    p.add_argument("--use-proxy-protocol", action="store_true",
                   help="Prepend PPv2 header with rotating synthetic source IP")
    p.add_argument("--source-ip-pool-size", type=int, default=1000,
                   metavar="N",
                   help="Number of synthetic source IPs to rotate through (default: 1000)")
    p.add_argument("--attack-rate", type=int, default=500,
                   metavar="N",
                   help="Target connections/second for attack_500 scenario (default: 500)")
    p.add_argument("--fast-backend-port", type=int, default=8444,
                   metavar="PORT",
                   help="Port of the fast TLS echo backend (default: 8444)")
    args = p.parse_args()

    scenarios: list[str]
    if args.scenarios == "all":
        scenarios = list(ALL_SCENARIOS)
    else:
        scenarios = [s.strip() for s in args.scenarios.split(",")]

    return BenchmarkConfig(
        python_host=args.python_host,
        python_port=args.python_port,
        go_host=args.go_host,
        go_port=args.go_port,
        output_dir=Path(args.output_dir) if args.output_dir else None,
        duration_quick=args.duration_quick,
        duration_long=args.duration_long,
        max_threads=args.max_threads,
        scenarios=scenarios,
        redis_host=args.redis_host,
        redis_port=args.redis_port,
        redis_password=args.redis_password,
        flush_redis=not args.no_redis_flush,
        quick=args.quick,
        proxy_filter=args.proxy_filter,
        connect_timeout=args.connect_timeout,
        use_proxy_protocol=args.use_proxy_protocol,
        source_ip_pool_size=args.source_ip_pool_size,
        attack_rate=args.attack_rate,
        fast_backend_port=args.fast_backend_port,
    )


def main() -> None:
    cfg = _parse_args()
    cfg.output_dir.mkdir(parents=True, exist_ok=True)

    _log("=" * 72, prefix="")
    _log("  JA4proxy Benchmark: Go Proxy vs Python Proxy", prefix="")
    _log("=" * 72, prefix="")
    _log(f"  Python proxy:  {cfg.python_host}:{cfg.python_port}", prefix="")
    _log(f"  Go proxy:      {cfg.go_host}:{cfg.go_port}", prefix="")
    _log(f"  Output dir:    {cfg.output_dir}", prefix="")
    _log(f"  Duration:      quick={cfg.duration_quick}s  long={cfg.duration_long}s", prefix="")
    _log(f"  Threads (max): {cfg.max_threads}", prefix="")
    _log(f"  Quick mode:    {cfg.quick}", prefix="")
    _log("=" * 72, prefix="")

    suite = BenchmarkSuite(cfg)
    suite.run_scenarios()

    # Generate reports
    reporter = ReportGenerator(suite.results, cfg, suite._system_info)

    md_path = cfg.output_dir / "report.md"
    json_path = cfg.output_dir / "raw_results.json"

    md_path.write_text(reporter.generate_markdown(), encoding="utf-8")
    json_path.write_text(
        json.dumps(reporter.generate_json(), indent=2, default=str),
        encoding="utf-8",
    )

    # Also write a per-scenario JSON breakdown
    scenarios_dir = cfg.output_dir / "scenarios"
    scenarios_dir.mkdir(exist_ok=True)
    json_data = reporter.generate_json()
    for i, sdata in enumerate(json_data["scenarios"]):
        (scenarios_dir / f"{i+1:02d}_{sdata['name']}.json").write_text(
            json.dumps(sdata, indent=2, default=str), encoding="utf-8"
        )

    _log("\n" + "=" * 72, prefix="")
    _log("  Benchmark complete.", prefix="")
    _log(f"  Report:      {md_path}", prefix="")
    _log(f"  Raw JSON:    {json_path}", prefix="")
    _log(f"  Scenarios:   {scenarios_dir}/", prefix="")
    _log("=" * 72, prefix="")

    # Print executive summary to stdout
    md = md_path.read_text(encoding="utf-8")
    summary_start = md.find("## Executive Summary")
    summary_end = md.find("\n## ", summary_start + 1)
    if summary_start >= 0:
        print("\n" + md[summary_start:summary_end if summary_end > 0 else summary_start + 2000])


if __name__ == "__main__":
    main()
