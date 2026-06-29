<!--
title: "JA4proxy — Component Design Index"
audience: developers, architects
last_reviewed: 2026-04-24
phase: 106f
-->

# JA4proxy — Component Design Index

**Non-goal:** This is a component index, not an architecture-decision record.
ADRs live in [`docs/decisions/`](../decisions/). Deep design discussions
belong in per-phase docs (`docs/phases/PHASE_NN.md`). This page exists so a
new engineer asking "where is component X designed?" has one place to land
and one phase doc to read first.

The **Source** column points at the canonical implementation file. For
components that exist in both Go (production) and Python (prototype), the Go
path is canonical and the Python path is listed as "see also" in Notes.

The **Design origin (phase)** column points at the phase doc that introduced
the component. Most components have grown beyond their origin phase — Notes
calls out the major extensions.

| Component | Source | Design origin (phase) | Test coverage | Notes |
|---|---|---|---|---|
| TLS ClientHello parser | [`internal/tls/parser.go`](../../internal/tls/parser.go) | Phase 15 | [`internal/tls/parser_test.go`](../../internal/tls/parser_test.go) | Never panics on adversarial input. See also: `proxy.py` (Python prototype, Phase 0). |
| JA4 fingerprint computer | [`internal/tls/ja4.go`](../../internal/tls/ja4.go) | Phase 0 | [`internal/tls/ja4_test.go`](../../internal/tls/ja4_test.go) | SHA-256 + GREASE filter; cross-language parity with Python. |
| JA4X cert fingerprint | [`internal/tls/ja4x.go`](../../internal/tls/ja4x.go) | Phase 16 | [`internal/tls/ja4x_test.go`](../../internal/tls/ja4x_test.go) | Issuer/subject/SAN sha256[:12] triple. |
| JA4T TCP fingerprint | [`internal/security/tcp_analyzer.go`](../../internal/security/tcp_analyzer.go) | Phase 5 | [`internal/security/tcp_analyzer_test.go`](../../internal/security/tcp_analyzer_test.go) | TAP-mode JA4T fingerprint extractor in `src/tap/fingerprints/ja4t.py` (Phase 20). |
| Risk scorer | [`internal/security/risk_scorer.go`](../../internal/security/risk_scorer.go) | Phase 1 | [`internal/security/risk_scorer_test.go`](../../internal/security/risk_scorer_test.go) | Aggregates RiskSignals → score 0-100. |
| Action decider | [`internal/security/action_decider.go`](../../internal/security/action_decider.go) | Phase 1 | [`internal/security/action_decider_test.go`](../../internal/security/action_decider_test.go) | See also: Phase 2 added the dial formula. |
| Pipeline (TCP accept → bypass → signals → scorer → action) | [`internal/security/pipeline.go`](../../internal/security/pipeline.go) | Phase 0 | [`internal/security/pipeline_test.go`](../../internal/security/pipeline_test.go) | Hot path. See also: Phase 16 added JA4X bypass + tracing. |
| Bypass checks (whitelists / mTLS / ALPN h2/h1) | [`internal/security/pipeline.go`](../../internal/security/pipeline.go) | Phase 0 | [`internal/security/pipeline_test.go`](../../internal/security/pipeline_test.go) | ALLOW bypasses unaffected by dial. |
| mTLS verifier | [`internal/security/mtls.go`](../../internal/security/mtls.go) | Phase 5 | [`internal/security/mtls_test.go`](../../internal/security/mtls_test.go) | Hard ALLOW bypass on valid client cert. |
| SNI analyzer | [`internal/security/sni_analyzer.go`](../../internal/security/sni_analyzer.go) | Phase 4 | [`internal/security/sni_analyzer_test.go`](../../internal/security/sni_analyzer_test.go) | Missing-SNI / IP-literal / DGA / unexpected-host. |
| TCP / connection analyzer | [`internal/security/tcp_analyzer.go`](../../internal/security/tcp_analyzer.go) | Phase 5 | [`internal/security/tcp_analyzer_test.go`](../../internal/security/tcp_analyzer_test.go) | Session resumption, lifespan, concurrency, return visitor. |
| ASN classifier (datacenter / Tor / VPN) | [`internal/security/asn_classifier.go`](../../internal/security/asn_classifier.go) | Phase 6 | [`internal/security/asn_classifier_test.go`](../../internal/security/asn_classifier_test.go) | MaxMind GeoLite2-ASN + Tor exit list. |
| FCrDNS / DNS enrichment | [`internal/security/dns_enrichment.go`](../../internal/security/dns_enrichment.go) | Phase 7 | [`internal/security/dns_enrichment_test.go`](../../internal/security/dns_enrichment_test.go) | Async queue + worker restart loop. |
| Spamhaus DROP/EDROP blocklists | [`internal/security/blocklists.go`](../../internal/security/blocklists.go) | Phase 8 | [`internal/security/blocklists_test.go`](../../internal/security/blocklists_test.go) | pytricia (Python) / Go trie; ETag + leader-election feed manager. |
| TLS enforcer (version + cipher) | [`internal/security/tls_enforcer.go`](../../internal/security/tls_enforcer.go) | Phase 3 | [`internal/security/tls_enforcer_test.go`](../../internal/security/tls_enforcer_test.go) | SSLv3 always blocked. |
| Beaconing detector | [`internal/security/beaconing_detector.go`](../../internal/security/beaconing_detector.go) | Phase 9 | [`internal/security/beaconing_detector_test.go`](../../internal/security/beaconing_detector_test.go) | IAT coefficient-of-variation; dual 1h / 24h windows. |
| AbuseIPDB integration | [`internal/security/abuseipdb.go`](../../internal/security/abuseipdb.go) | Phase 10 | [`internal/security/abuseipdb_test.go`](../../internal/security/abuseipdb_test.go) | Three-tier cache + bloom dedup + daily quota. |
| RDAP enrichment + block expansion | [`internal/security/rdap_enrichment.go`](../../internal/security/rdap_enrichment.go) | Phase 11 | [`internal/security/rdap_enrichment_test.go`](../../internal/security/rdap_enrichment_test.go) | IANA bootstrap + per-RIR token buckets; CIDR expansion off by default. |
| Analytics signals (Stream consumer) | [`internal/security/analytics_signals.go`](../../internal/security/analytics_signals.go) | Phase 12 | [`internal/security/analytics_signals_test.go`](../../internal/security/analytics_signals_test.go) | Fail-open: returns `[]` on any error, never partial. |
| Rate limiters (token bucket + sliding window + multi-strategy majority 2-of-3) | [`internal/security/rate_limiter.go`](../../internal/security/rate_limiter.go) | Phase 14 | [`internal/security/rate_limiter_test.go`](../../internal/security/rate_limiter_test.go) | Three strategies; sliding window via Lua. See also: `src/security/rate_strategy.py`, `src/security/rate_tracker.py`. |
| Tarpit / slow-loris responder | [`src/tarpit/tarpit-server.py`](../../src/tarpit/tarpit-server.py) | Phase 14 | [`src/tarpit/test_tarpit.py`](../../src/tarpit/test_tarpit.py) | Phase 14c added per-IP concurrent caps. |
| Local cache (LRU) | [`internal/cache/local.go`](../../internal/cache/local.go) | Phase 0 | [`internal/cache/local_test.go`](../../internal/cache/local_test.go) | "Redis blocks but local allows → local wins." See also: `src/cache/local_cache.py`. |
| Redis client + Lua scripts | [`internal/redis/client.go`](../../internal/redis/client.go) | Phase 0 | [`internal/redis/client_test.go`](../../internal/redis/client_test.go) | Fail-open. Lua scripts in `internal/redis/scripts/`. |
| PubSub handler | [`internal/redis/pubsub.go`](../../internal/redis/pubsub.go) | Phase 0 | [`internal/redis/pubsub_test.go`](../../internal/redis/pubsub_test.go) | Pub/sub for removals/releases only; new blocks propagate via cache TTL. See also: `src/pubsub.py`. |
| Hot-reload config loader | [`internal/config/loader.go`](../../internal/config/loader.go) | Phase 0 | [`internal/config/loader_test.go`](../../internal/config/loader_test.go) | SIGHUP + Redis pub/sub. See also: `src/config/loader.py`. |
| Bloom filter (enrichment dedup) | `archive/python_legacy/src/cache/bloom.py` | Phase 0 | `archive/python_legacy/tests/unit/test_bloom.py` | RedisBloom with SET-fallback. Python legacy; archived. |
| Go proxy entry point (TCP accept loop, forward / tarpit / block) | [`cmd/ja4pd/main.go`](../../cmd/ja4pd/main.go) | Phase 15 | [`cmd/ja4pd/lifecycle_test.go`](../../cmd/ja4pd/lifecycle_test.go) | Production runtime (Phase 15 promotion). |
| Management API (FastAPI) | [`management/api/main.py`](../../management/api/main.py) | Phase 13 | [`management/tests/`](../../management/tests/) | Python-only; not on the proxy hot path. |
| TAP mode pipeline (passive SPAN/TAP capture) | `archive/python_legacy/src/tap/tap_pipeline.py` | Phase 20 | `archive/python_legacy/tests/unit/tap/test_tap_pipeline.py` | AF_PACKET capture; 5-level signal action scale. Python legacy; archived. |
| TAP mode reassembler | `archive/python_legacy/src/tap/reassembler.py` | Phase 20 | `archive/python_legacy/tests/unit/tap/test_reassembler.py` | Out-of-order TCP reordering with stream eviction. Python legacy; archived. |
| TAP fingerprint store | `archive/python_legacy/src/tap/fingerprint_store.py` | Phase 20 | `archive/python_legacy/tests/unit/tap/test_fingerprint_store.py` | 7 Redis key types; conn 7d / IP 30d retention. Python legacy; archived. |
| TAP enforcement bridge | `archive/python_legacy/src/tap/enforcement_bridge.py` | Phase 20 | `archive/python_legacy/tests/unit/tap/test_enforcement_bridge.py` | Pub/sub fan-out: iptables / BGP / webhook (HMAC-SHA256). Python legacy; archived. |

---

*Component count: 30. Last reviewed 2026-04-24 (Phase 106f). Add a row when
a phase introduces a new top-level component. Update Notes when a later
phase materially extends an existing component.*
