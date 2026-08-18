### Fixed

- **The Intelligence panel had never displayed a finding.** Three independent
  faults sat in series between the proxy and the console. The analytics
  consumer could not read the event stream at all — `xreadgroup(block=5000)`
  against a client whose `socket_timeout` defaulted to 5s in redis-py 8.x, so
  every poll lost the race and raised `TimeoutError` on a retry loop. Behind
  that, the proxy wrote an ECS envelope the consumer could not parse, and the
  consumer required an HMAC the proxy never applied (7,749 events rejected once
  the read was fixed). All three are fixed and the pipeline is verified end to
  end. (Phase 826)
- **JA4 intelligence findings were computed and then discarded.** Campaign and
  slow-scan detections were written through to the console; JA4 intelligence
  only ever reached a sorted set nothing reads. It is the one detector that
  does not require many unique source IPs, so on single-node deployments the
  panel was structurally unable to show anything. (Phase 826)
- **A missing TLS certificate crashed the panel that reports missing
  certificates.** `tls_cert_card.html` called `.get()` on a `subject` that is
  `None` whenever the certificate cannot be read, 500ing the partial. (Phase 826)

### Added

- **Fingerprints are now interpreted, not just displayed.** The JA4 drill-down
  decodes the fingerprint into transport, TLS version, SNI presence, cipher and
  extension counts and ALPN — the information was always in the string. The
  "browser-shaped" badge is labelled as a hint, because ALPN is
  attacker-controlled. (Phase 826)
- **Sidebar link to Grafana**, hidden when `GRAFANA_EXTERNAL_URL` is unset.
  The console previously had no reference to Grafana anywhere. (Phase 826)
- **UI regression tests** covering htmx panel resolution, error-state detection
  and drill-down content — the gap that let every page test pass while panels
  were broken. Plus `make demo-check`, a pre-flight that refuses a stale stack,
  `make demo-bot`, and `docs/DEMO_RUNBOOK.md`. (Phase 826)
- **Analytics ingest metrics** (`ja4proxy_analytics_events_ingested_total`,
  `..._rejected_total`). The `/metrics` endpoint also previously dropped the
  default registry entirely, so `ja4proxy_analytics_stream_lag_seconds` had
  never been scrapeable. (Phase 826)
