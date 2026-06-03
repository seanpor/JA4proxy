from typing import List

import redis
from prometheus_client import Counter, Gauge

from src.security.models import ConnectionContext, RiskSignal

_TCP_SIGNALS = Counter(
    "ja4proxy_tcp_signal_total",
    "TCP signal fires by signal name",
    ["signal"],
)
_CONCURRENT_CONNECTIONS = Gauge(
    "ja4proxy_concurrent_connections",
    "Current concurrent connections observed by TCP analyser",
)


def generate_ja4t(ttl: int, window_size: int, options: str) -> str:
    """
    Generates a JA4T fingerprint from TCP details.
    Format: {ttl}_{mss}_{window_size}_{options_hash}
    """
    import hashlib

    # MSS is not directly available from PROXY protocol, so use a common default.
    mss = 1460

    # JA4 does not use MD5 - only SHA-256 based checksums for hashing
    # Use SHA-256 to generate the options field from the hex string input
    options_hash = hashlib.sha256(options.encode()).hexdigest()

    return f"{ttl}_{mss}_{window_size}_{options_hash[:8]}"


class TCPAnalyzer:
    def __init__(self, config: dict, redis_client: object):
        """
        Initializes the TCPAnalyzer with configuration and a Redis client.
        """
        self._config = config.get("tcp_analyzer", {})
        self._redis = redis_client
        self._ja4t_enabled = self._config.get("tcp_fingerprinting", {}).get(
            "enabled", False
        )
        self._resumption_enabled = self._config.get("session_resumption", {}).get(
            "enabled", False
        )
        self._lifespan_enabled = self._config.get("connection_lifespan", {}).get(
            "enabled", False
        )
        self._concurrent_enabled = self._config.get("concurrent_connections", {}).get(
            "enabled", False
        )
        self._return_visitor_enabled = self._config.get("return_visitor", {}).get(
            "enabled", False
        )
        self._tls_alerts_enabled = self._config.get("tls_alerts", {}).get(
            "enabled", False
        )

    async def analyze(self, ctx: ConnectionContext) -> List[RiskSignal]:
        """
        Analyzes the connection context for TCP-level risk signals.
        """
        signals: List[RiskSignal] = []

        if self._ja4t_enabled:
            signals.extend(self._check_ja4t_mismatch(ctx))

        if self._resumption_enabled:
            signals.extend(await self._check_session_resumption(ctx))

        if self._lifespan_enabled:
            signals.extend(await self._check_connection_lifespan(ctx))

        if self._concurrent_enabled:
            signals.extend(await self._check_concurrent_connections(ctx))

        if self._return_visitor_enabled:
            signals.extend(await self._check_return_visitor(ctx))

        if self._tls_alerts_enabled:
            signals.extend(await self._check_tls_alerts(ctx))

        for sig in signals:
            _TCP_SIGNALS.labels(signal=sig.name).inc()

        return signals

    def _check_ja4t_mismatch(self, ctx: ConnectionContext) -> List[RiskSignal]:
        """
        Checks for a mismatch between the OS implied by JA4 and the OS implied by JA4T.
        """
        if not ctx.tcp_ja4t:
            return []

        # Simplified OS mapping for demonstration
        # A real implementation would use a more extensive database.
        ja4_os_map = {
            "chrome": "windows",
            "firefox": "windows",
            "safari": "macos",
        }

        ja4t_os_map = {
            "64_": "linux",  # High TTL is common for Linux
            "128_": "windows",  # High TTL is common for Windows
        }

        ja4_lower = ctx.ja4.lower()
        ja4_os = "unknown"
        for browser, os in ja4_os_map.items():
            if browser in ja4_lower:
                ja4_os = os
                break

        ja4t = generate_ja4t(ctx.tcp_ttl, ctx.tcp_window_size, ctx.tcp_options)
        ja4t_os = "unknown"
        for prefix, os in ja4t_os_map.items():
            if ja4t.startswith(prefix):
                ja4t_os = os
                break

        if ja4_os != "unknown" and ja4t_os != "unknown" and ja4_os != ja4t_os:
            score = self._config.get("tcp_fingerprinting", {}).get("score", 30)
            return [
                RiskSignal(
                    "ja4t_mismatch",
                    score,
                    f"JA4 OS ({ja4_os}) differs from JA4T OS ({ja4t_os})",
                )
            ]

        return []

    async def _check_session_resumption(
        self, ctx: ConnectionContext
    ) -> List[RiskSignal]:
        """
        Checks the TLS session resumption rate for the client using pipelined I/O.
        """
        try:
            key = f"session:ip:{ctx.client_ip}:ja4:{ctx.ja4}"

            # In a real implementation, we would inspect the ClientHello for a session ticket
            # to determine if this is a resumption attempt. For this simulation, we'll
            # assume a 90% resumption rate for "good" clients and 0% for others.
            is_resumption = (
                "chrome" in ctx.ja4.lower() and __import__("random").random() < 0.9
            )

            # Phase 28a: Use pipeline to reduce RTTs from 2 to 1
            async with self._redis.pipeline(transaction=False) as pipe:
                pipe.hincrby(key, "total", 1)
                if is_resumption:
                    pipe.hincrby(key, "resumed", 1)
                else:
                    pipe.hget(key, "resumed")
                pipe.expire(key, 3600)
                pipe_res = await pipe.execute()

            total = int(pipe_res[0] or 0)
            resumed = int(pipe_res[1] or 0)

            min_connections = self._config.get("session_resumption", {}).get(
                "min_connections", 10
            )
            if total >= min_connections and resumed == 0:
                score = self._config.get("session_resumption", {}).get("score", 15)
                return [
                    RiskSignal(
                        "no_session_resumption",
                        score,
                        f"0% session resumption across {total} sessions",
                    )
                ]
        except Exception:
            # Fail open on Redis error
            pass
        return []

    async def _check_connection_lifespan(
        self, ctx: ConnectionContext
    ) -> List[RiskSignal]:
        """
        Analyzes the median connection lifespan for the client using pipelined I/O.
        """
        try:
            key = f"lifespan:{ctx.client_ip}"

            # The connection lifespan would be calculated in the main proxy loop
            # and passed in the context. We'll use a placeholder value.
            lifespan_ms = ctx.connection_lifespan_ms or __import__("random").randint(
                100, 2000
            )

            # Phase 28a: Use pipeline to reduce RTTs from 3 to 1 for the write+count
            async with self._redis.pipeline(transaction=False) as pipe:
                pipe.zadd(
                    key, {f"{lifespan_ms}:{__import__('time').time()}": lifespan_ms}
                )
                pipe.expire(key, 1800)
                pipe.zcard(key)
                pipe_res = await pipe.execute()

            count = pipe_res[2]

            min_connections = self._config.get("connection_lifespan", {}).get(
                "min_connections", 5
            )

            if count >= min_connections:
                # Get the median (separate RTT)
                median_index = count // 2
                median_list = await self._redis.zrange(
                    key, median_index, median_index, withscores=True
                )
                if median_list:
                    median_lifespan = median_list[0][1]
                    threshold_ms = self._config.get("connection_lifespan", {}).get(
                        "threshold_ms", 500
                    )
                    if median_lifespan < threshold_ms:
                        score = self._config.get("connection_lifespan", {}).get(
                            "score", 20
                        )
                        return [
                            RiskSignal(
                                "short_connection_lifespan",
                                score,
                                f"Median connection lifespan is {median_lifespan:.0f}ms",
                            )
                        ]
        except Exception:
            # Fail open
            pass
        return []

    async def _check_concurrent_connections(
        self, ctx: ConnectionContext
    ) -> List[RiskSignal]:
        """
        Checks for an excessive number of concurrent connections from the client using pipelined I/O.
        """
        try:
            key = f"concurrent:{ctx.client_ip}"

            # Phase 28a: Use pipeline to reduce RTTs from 2 to 1
            async with self._redis.pipeline(transaction=False) as pipe:
                pipe.incr(key)
                pipe.expire(key, 60)
                pipe_res = await pipe.execute()

            count = int(pipe_res[0] or 0)
            _CONCURRENT_CONNECTIONS.set(count)

            thresholds = self._config.get("concurrent_connections", {}).get(
                "thresholds", {}
            )
            scores = self._config.get("concurrent_connections", {}).get(
                "risk_scores", {}
            )

            if count >= thresholds.get("severe", 100):
                return [
                    RiskSignal(
                        "severe_concurrency",
                        scores.get("severe", 40),
                        f"{count} concurrent connections",
                    )
                ]
            if count >= thresholds.get("high", 50):
                return [
                    RiskSignal(
                        "high_concurrency",
                        scores.get("high", 25),
                        f"{count} concurrent connections",
                    )
                ]
            if count >= thresholds.get("moderate", 20):
                return [
                    RiskSignal(
                        "moderate_concurrency",
                        scores.get("moderate", 10),
                        f"{count} concurrent connections",
                    )
                ]
        except redis.RedisError:
            # Fail open
            pass
        return []

    async def decrement_concurrent_connections(self, client_ip: str):
        """
        Decrements the concurrent connection counter for a client IP.
        """
        try:
            key = f"concurrent:{client_ip}"
            await self._redis.decr(key)
        except redis.RedisError:
            # Errors here are not critical
            pass

    async def _check_return_visitor(self, ctx: ConnectionContext) -> List[RiskSignal]:
        """
        Applies a trust modifier for returning visitors with a good history using pipelined I/O.
        """
        try:
            key = f"visitor:{ctx.client_ip}"
            now = int(__import__("time").time())

            # Phase 28a: Use pipeline to reduce RTTs from 4 to 1
            async with self._redis.pipeline(transaction=False) as pipe:
                pipe.hgetall(key)
                pipe.hset(key, "last_seen", now)
                pipe.hincrby(key, "total", 1)
                pipe.hincrby(key, "allowed", 1)
                pipe.expire(key, 604800)  # 7 days
                res = await pipe.execute()

            visitor_data = res[0]

            if not visitor_data:
                # First time visitor (already incremented via pipeline)
                return []

            first_seen = int(
                visitor_data.get(b"first_seen") or visitor_data.get("first_seen") or now
            )
            # Note: total and allowed from visitor_data are the values BEFORE this increment
            total = (
                int(visitor_data.get(b"total") or visitor_data.get("total") or 0) + 1
            )
            allowed = (
                int(visitor_data.get(b"allowed") or visitor_data.get("allowed") or 0)
                + 1
            )

            trusted_days = self._config.get("return_visitor", {}).get("trusted_days", 7)
            trusted_allow_rate = self._config.get("return_visitor", {}).get(
                "trusted_allow_rate", 0.90
            )

            if (now - first_seen) > (trusted_days * 86400):
                allow_rate = allowed / total
                if allow_rate >= trusted_allow_rate:
                    score_reduction_pct = self._config.get("return_visitor", {}).get(
                        "score_reduction_pct", 20
                    )
                    # This is a negative signal, reducing the overall score
                    return [
                        RiskSignal(
                            "return_visitor_trust",
                            -1,
                            f"Trusted visitor, score reduced by {score_reduction_pct}%",
                        )
                    ]
        except Exception:
            # Fail open
            pass
        return []

    async def _check_tls_alerts(self, ctx: ConnectionContext) -> List[RiskSignal]:
        """
        Monitors for a high rate of TLS alert messages from the client using pipelined I/O.
        """
        if not ctx.tls_alerts:
            return []

        try:
            key = f"tls_alerts:{ctx.client_ip}"

            # Phase 28a: Use pipeline to reduce RTTs from 2 to 1
            async with self._redis.pipeline(transaction=False) as pipe:
                pipe.incr(key)
                pipe.expire(key, 60)
                pipe_res = await pipe.execute()

            count = int(pipe_res[0] or 0)

            rate_threshold = self._config.get("tls_alerts", {}).get("rate_threshold", 5)
            if count > rate_threshold:
                score = self._config.get("tls_alerts", {}).get("score", 20)
                return [
                    RiskSignal(
                        "high_tls_alert_rate", score, f"{count} TLS alerts in 60s"
                    )
                ]
        except redis.RedisError:
            # Fail open
            pass
        return []
