# Python-Prototype Test Removal — Audit & Coverage Gaps

**Date:** 2026-06-12
**Phase:** 309 (tidyup)
**Branch:** `phase-309-tidyup-orphaned-python-prototype-tests`

## What happened

Commit `5afeba26` (*"arch: deprecate and archive Python legacy proxy"*, Phase 128)
removed the Python prototype proxy: `proxy.py` is gone and `src/security/`,
`src/cache/`, `src/tap/`, `src/backup/` were emptied. **35 test files were left
behind** that `import` those now-missing modules — they errored on collection
(`pytest tests/` aborted with 27 collection errors) and could never run, so they
provided zero live coverage while reading as if they did. The gated `make test`
already dodged them by only running `tests/unit/` + `tests/integration/`.

This tidyup deletes those files. `pytest tests/ --co` now collects **2034 tests,
0 errors** (was 27 errors).

**Kept deliberately:**
- `tests/fp_corpus/data/` (tranco_top_10k.txt, residential_ips.txt,
  browser_keepalive_timestamps.csv) — reusable corpus for a Go FP-rate port (see
  gaps below).
- `tests/fuzz/README.md` — a Go-fuzz pointer doc (updated to drop the reference
  to the deleted Python harness).

## Per-area verdict

Each deleted file tested one of two things:

**(A) A subsystem that was ported to Go** — covered by Go tests, so deletion is
clean:

| Removed Python test | Go coverage |
|---|---|
| `chaos/test_redis_failure.py` | `pipeline_chaos_test.go` (`TestPipeline_RedisOutage_FailsOpen`), `pipeline_test.go` |
| `chaos/test_analytics_down.py` | `analytics_signals_test.go` |
| `chaos/test_asn_chaos.py` | `asn_classifier_test.go` |
| `chaos/test_dns_chaos.py` | `dns_enrichment_test.go` |
| `chaos/test_sni_chaos.py` | `sni_analyzer_test.go` |
| `chaos/test_tcp_chaos.py` | `tcp_analyzer_test.go`, `pipeline_chaos_test.go` |
| `chaos/test_dial_change_chaos.py` | `action_decider_test.go`, `pipeline_chaos_test.go` |
| `chaos/test_external_api_failure.py` | `abuseipdb_test.go` + `phase309_metrics_test.go` (quota) |
| `chaos/test_feed_staleness.py` | `feed_downloader_test.go` (phase-309 WP-6) |
| `chaos/test_tarpit_cap.py` | tarpit logic in `cmd/ja4pd` |
| `chaos/test_pipeline_remediation.py` | per-signal metrics in `pipeline.go`/`metrics.go` |
| `fuzz/test_properties.py` | `property_test.go`, `cmd/ja4pd/fuzz_test.go` |
| `security/test_owasp_top10.py`, `test_proxy.py` | `cmd/ja4pd/*_test.go`, `internal/security/*` (~120 Go test files) |
| `performance/test_bench_*.py` | Go `Benchmark*` / `make bench-*` |

**(B) A feature intentionally removed with the prototype** — nothing to cover,
so deletion is clean (the feature is gone, not regressed):

| Removed Python test | Removed feature |
|---|---|
| `chaos/test_tap_*_resilience.py`, `tests/tap/**` | TAP **sensor** (packet capture / enforcement bridge / exporters). Go keeps only the *consumer* (`internal/security/tap_consumer.go`), which reads TAP fingerprints from Redis. |
| `fp_corpus/test_backup_fp.py`, `performance/backup/**` | Python backup worker/restorer/policy. No Go backup implementation exists. |
| `compliance/test_gdpr_retention.py` (+ `gdpr_validator.py`) | `GDPRStorage` retention-class abstraction. Subject-erasure still exists via `scripts/gdpr_delete.py`; per-category TTL is now enforced inline at each `SETEX`. |
| `chaos/test_ti_feed_chaos.py` | Per-provider TI lookups (MISP/GreyNoise/AlienVault/VirusTotal/ThreatFox) + their lookup-time circuit breaker. Live TI work is now feed-based STIX ingestion in `src/analytics/ti_feeds/` (a different architecture with its own circuit breaker). |

## Coverage gaps worth porting to Go (backlog — not blockers)

Deleting category-(A) files surfaced scenarios that the Go ports cover more
thinly. None justify keeping un-runnable Python, but they are real and tracked
here:

1. **Quantitative FP-rate thresholds against a corpus.** CLAUDE.md (Testing
   Standards) mandates *"New signals: FP rate test against Tranco top 10k."* The
   Go side has *regression/parity* guards — `internal/tls/ja4_fp_corpus_test.go`
   (golden JA4 corpus) and `internal/security/dga_parity_test.go` (byte-parity
   with a Python golden set ≥80 hosts) — but **no test that asserts a numeric FP
   rate** (e.g. DGA < 1% on Tranco top-10k, ASN datacenter classifier < 2% on a
   residential corpus, beaconing 0% on browser-keepalive traffic). The corpora
   for these live in `tests/fp_corpus/data/` and were retained for exactly this
   port. **Priority gap** — it maps to an explicit project standard.
2. **Thinner chaos sub-scenarios.** Lower priority; Go covers the core fail-open
   path but not every variant:
   - DNS: resolver-timeout / malformed-response / queue-overflow specifics.
   - SNI: null-byte / very-long / unicode-edge / config-reload robustness.
   - DialManager: init from an unacknowledged non-zero dial, `validate_change`
     rate-limiting.
   - Analytics: exact signal scores (campaign 35 / slowscan 30).
   - Pipeline: per-signal `error`/`skipped` metric increments on
     exception/timeout.

## Separate finding (not part of this tidyup)

`deploy/monitoring/alertmanager/rules/backup.rules.yml` alerts on
`ja4proxy_backup_*` metrics that **no Go (or live Python) code emits** — the same
class of dead alert that phase-309 WP-6 fixed for abuseipdb/spamhaus/beaconing.
Because the backup subsystem itself is unimplemented in Go, the right fix is
either to build it or to retire those alerts. Logged here for a follow-up.
