# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **316\* series audit — Go TAP/SPAN sensor code review (Phase 334)**: a structured, review-only (no code changes, by design) audit of the entire Go TAP/SPAN passive sensor series (316a-316e) against its ADRs, tests, and manifest entries. Found unregistered during a phase-800 code-health session (2026-07-21) — written 2026-06-19, sat unactioned for a month. 40+ findings across correctness/security, reliability, TLS parsing, concurrency, observability, privacy/GDPR, and cross-component data integrity. Highlights: zero panic recovery (a single crafted packet permanently hangs the sensor — packet-of-death DoS that passes liveness checks while dead), capability drop + seccomp never wired (binary runs with full `CAP_NET_RAW` throughout its lifetime), SIGTERM ignored while blocked in a live packet read, no Makefile target builds the sensor at all, and the shipped Alertmanager rules/Grafana dashboard reference metric names that don't exist (8 of 11 dashboard panels show "No data", 5 of 7 alerts can never fire). None of the 40+ recommended fixes have been implemented — flagged for a dedicated remediation phase. See `docs/phases/PHASE_334.md`.
- **Phase 15 gap closure — browser fixtures + container smoke test (Phase 502)**: added deterministic synthetic ClientHello fixtures mimicking real Chrome 120+/Firefox 122+ patterns (GREASE, `compress_certificate`, `post_handshake_auth`, multi-ALPN) to `tests/fixtures/clienthello/`, generated via a checked-in generator (`internal/tls/gen_browser_fixtures_test.go`) so they're reproducible, not hand-crafted. Also added container-config assertions (no Docker daemon required) verifying management/analytics wire to the Go proxy (`ja4pd`), not any deleted Python proxy service. Closes the two remaining open items from the Phase 15 post-implementation review. See `docs/phases/PHASE_502.md`.
- **Root clutter follow-up (Phase 802)**: relocated 6 stray phase-notes files into `docs/phases/` (matching the convention 14 other phases already follow); deleted the orphaned `dc_head.yml` and the superseded Tailwind v3 pipeline at `management/tailwind/`; moved `.gitlab-ci/ja4proxy-policy.yml` (a customer-facing GitLab CI policy-as-code template, not this repo's own CI config) to `deploy/integrations/gitlab-ci/`, leaving a redirect stub at the old path for one release cycle. Critically reviewed and recommended **against** consolidating linter dotfiles into a `Dots`/`.config` folder — GitHub already hides dotfiles from its default view (so the visible-root-clutter argument that justified every other move doesn't apply), and 3 of the tools involved (`bandit`, `checkmake`, semgrep's ignore-file) rely on implicit cwd auto-discovery with no config-path override, risking a silently-narrower scan if moved. See `docs/phases/PHASE_802.md`.
- **Fix: `make scan` image build on Python 3.14**: bumped `aiohttp` in `management/requirements.txt` from `3.9.5` to `3.14.1`. `3.9.5` predates Python 3.14 and ships no `cp314` wheel, so on the `python:3.14.0-slim` base image pip fell back to building aiohttp from source and failed (no compiler in the image), breaking the Security Scan (`make scan`) job repo-wide. `3.14.1` is the current release with native `cp314` wheels; the management image now installs entirely from wheels. Validated by building `deploy/docker/Dockerfile.management` locally end to end. aiohttp is used only as a client (`ClientSession`/`ClientTimeout`/`ClientError`/`TCPConnector`), whose API is unchanged across the bump.
- **Fix: stack-trace exposure in `GET /api/v1/tls-health`**: the certificate parse-error and expiry-computation branches in `management/api/routes/tls_health.py` embedded the raw exception text into the JSON `message` returned to the client (CodeQL `py/stack-trace-exposure`, medium). They now return a generic message and keep the full detail in the `logger.warning` line the SOC already reads. Added a regression test asserting the error response never echoes the exception text. No behavioural change to the success path or to `status`/`band`/`days_remaining`.
- **ja4-tap seccomp hardening (Phase 15 gap)**: replaced the `LoadSeccomp()` placeholder with a real Linux seccomp BPF implementation (`internal/tap/seccomp_linux.go`). The embedded default profile covers the minimal syscall set for packet capture and metric export; an external profile can be overridden via `--seccomp-profile`. Non-Linux builds compile cleanly via a no-op stub. See `docs/phases/complete/PHASE_15.md`.
- **Single-host native mode now works end-to-end (Phase 231b real-host validation)**: validating `bootstrap.sh` + `ja4p init` on a clean Ubuntu 24.04 host surfaced a cascade of native-mode defects that no integration test had caught — native deployment was effectively non-functional. Fixed: (1) `ja4p init` gains a `--mode native|container` flag so `--non-interactive` can target native (it previously hard-coded container); (2) the generated **systemd unit grants `CAP_NET_BIND_SERVICE`** so the unprivileged `ja4proxy` user can bind `:443`; (3) the generated **`proxy.yml` now uses the real `ja4pd` schema** — `proxy.bind_host`/`bind_port`/`backend_host`/`backend_port` (ingress `0.0.0.0:443`) instead of the ignored top-level `server:`/`backend:` keys (so `ja4pd` no longer silently defaulted to `:8080`), plus a `redis.host` of `127.0.0.1` in native mode (a non-local Redis host without a password is refused at startup, JA4PROXY-2026-0010); (4) `bootstrap.sh` gains `--non-interactive`/`--yes` for unattended installs (forwarded to the wizard), (5) installs `redis-server` for native mode (the unit already ordered after `redis-server.service`), and (6) actually **enables the firewall** (`ufw --force enable`, allowing SSH first) — it previously added allow/deny rules but never activated them, a false sense of security. Verified end-to-end on a real VM: `scripts/validate-single-host.sh` reports **PASS=12 FAIL=0** (service active+enabled, `.env` 0600 with no secrets in the journal, ingress `:443` public, admin ports loopback + ufw-denied, logrotate, daily backup cron producing an archive, monitor-mode dial=0). Pairs with #200 (which made `ja4p init --non-interactive` skip prompts). See `scripts/validate-single-host.sh`.
- **Threat Posture Situation Bar (Phase 232b)**: Full-width HTMX situation bar with 4-state classification (NOMINAL/ELEVATED/ACTIVE/PROXY_DOWN), Go proxy heartbeat goroutine, and 10s polling. See `docs/phases/PHASE_232b.md`.
- **Container networking & port hardening (Phase 232c)**: the POC `analytics` container now joins the internal `ja4proxy-data` network so it can resolve and reach Redis (previously it sat on `ja4proxy-mgmt` only and could not connect). Added two structural guards to `tests/integration/test_container_config.py`: one asserting `analytics` shares a network with `redis`, and a regression guard asserting the internal production services (`proxy`, `analytics`, `tarpit`) are never republished on a wildcard/public interface (locking in the Phase 0046 host-port removal). See `docs/phases/PHASE_232c.md`.
- **Admin-API decommissioning (Phase 232d)**: removed the unauthenticated `admin-api` container (legacy `src/management/app` on host port `8091`, which modified the dial and JA4 lists with no auth) and deleted `deploy/docker/Dockerfile.admin`. All management traffic now flows through the JWT-gated `management` service on port `8090`. Cleaned up the automation touch-points (`scripts/agent-env.sh`, `scripts/check_updates.py`) and the runbooks/inventory (`docs/runbooks/REMOTE_TESTING.md`, `docs/runbooks/multidc.md`, `deploy/docker/README.md`), and added `test_admin_api_absent_from_all_compose_files` to `tests/integration/test_container_config.py` as a regression guard against the backdoor being reintroduced. See `docs/phases/PHASE_232d.md`.
- **Legacy management module removal (Phase 232e)**: deleted the now-orphaned `src/management/` package (the unauthenticated FastAPI `app.py` plus `redis_client.py`, `schemas.py`, `__init__.py`) and its three dedicated test files (`tests/management/test_api.py`, `tests/unit/management/test_redis_client.py`, `tests/unit/test_health_deep.py`), all dead since Phase 232d removed the `admin-api` container that ran them. Dropped `src/management/` from the Makefile static-analysis targets (`lint-security`, `mypy`, `bandit`, `ruff`, and the dockerised `flake8`) and corrected the `CONTRIBUTING.md` repo-layout entry to point at the secure `management/` service. The JWT-gated `management/` service (port `8090`) provides the authenticated equivalents, so no coverage is lost. See `docs/phases/PHASE_232e.md`.
- **Observability Foundations (Phase 233)**: Added tarpit and analytics Prometheus scrape targets; added TarpitDown, AnalyticsDown, ManagementDown, and RedisEvictionsDetected alert rules; replaced `redis/redis-stack:7.4.0-v8` with `redis:7.4.0-alpine` (digest-pinned) for reduced attack surface; capped event stream at 100k entries using XADD MAXLEN~100000; surfaced Redis eviction count in Management UI health cards.
- feat(phase-234): added RBAC role-gated navigation to management UI (`_extract_user_and_role` helper + Jinja2 guards in base.html)
- feat(phase-234): added Threat Posture row with top 10 IPs, top 10 JA4 fingerprints, and action distribution bar (30s HTMX poll)
- feat(phase-234): added Infrastructure row showing Redis memory, analytics/tarpit/proxy status, evictions count (30s HTMX poll)
- feat(phase-234): added Triage Queue table with Block/Watchlist/Dismiss actions for grey-zone IPs (60s HTMX poll)
- feat(phase-234): added `/api/v1/triage/dismiss/{ip}` endpoint with 4h TTL dismiss
- deps(phase-234): added `aiohttp==3.9.5` for Prometheus HTTP API queries
- note(phase-234): Go proxy heartbeat producer deferred to Phase 239; infra row shows "Unknown" until then
- **Fingerprint & IP Drill-Down Pages (Phase 235)**: Reusable confirmation modal (Decision 4) and undo toast components; IP and JA4 fingerprint detail pages with Chart.js risk-score timelines; clickable IP/JA4 links in the live-feed SSE stream; `/api/v1/ip/{ip:path}/profile` and `/api/v1/fingerprints/{ja4}/profile` endpoints reading from `events:connection` with correct ECS-dotted JSON payload parsing. See `docs/phases/PHASE_235.md`.
- **Analytics Intelligence — Redis ACL trust boundary (Phase 236)**: scoped `analytics` Redis user restricted to `analytics:*` keys via `config/redis_acl.conf`. New `src/analytics/output_writer.py` module with schema-validated findings (`FINDING_SCHEMA`). Intelligence dashboard row polling every 60 seconds showing HIGH-confidence findings. Intelligence Review page (`/intelligence-review`) for MEDIUM/LOW findings with tier/type filtering. Dismiss and false-positive feedback endpoints. Schema parity test (`tests/unit/test_schema_parity.py`) catching drift between the two duplicated schema copies. See `docs/phases/PHASE_236.md`.
- **Operational Polish (Phase 237)**: Dial revert scheduling, snapshot export, CIDR ban expansion, TLS health check, manual attribution, and revert cancel. See `docs/phases/PHASE_237.md`.
- **Accessibility Hardening & Docs (Phase 238)**: Triple-enforced status indicators (shape+color+text), focus rings on nav, ARIA live regions, CSS light mode, Grafana self-signed HTTPS, cAdvisor threat model, HAProxy TCP mode CI test, Mermaid network architecture diagram. See `docs/phases/PHASE_238.md`.
### Added (Phase 245.1 — Graceful GeoIP Degradation + Setup Guidance)
- "Under Attack?" emergency banner at the top of README.md linking to emergency deployment and incident response docs
- `docs/operations/EMERGENCY_DEPLOY.md` — 3-command deployment guide for operators under active attack (<5 minutes to protection)
### Added (Phase 245.2 — Root-Level Minimal Docker Compose)
- Root-level `docker-compose.yml` — 2-container quick start (proxy + Redis) with a single `BACKEND_HOST` env var
- `config/proxy.minimal.yml` — minimal proxy config with direct mode (no upstream LB required)
### Added (Phase 245.4 — Emergency Dial Override)
- `POST /api/v1/dial/emergency` — bypasses ±10 step limit for incident response (admin + MFA required, auto-reverts after 1-4 hours)
- Emergency dial presets: `block_known_bad` (50), `active_defense` (75), `lockdown` (90)
- `ja4-admin.sh dial` commands — show current value, set with ±10 limit, or `--emergency` override with auto-revert
- `make admin` target for running the incident response CLI
- `docs/operations/DEPLOYMENT_MODES.md` — deployment guides for direct, HAProxy, nginx, AWS NLB, and Cloudflare
### Phase 246 — Discovery, Onboarding & First-5-Minutes Experience

- **GitHub repo description** rewritten to lead with "bot protection" — now
  discoverable by people searching for anti-bot solutions. Added 13 topics
  (bot-protection, anti-bot, self-hosted, tls-fingerprinting, etc.).
- **README rewritten for website owners**, not just engineers. Opens with the
  problem (bots, scrapers, credential stuffing), explains how it works in
  plain English, and answers "will this break my site?" above the fold.
  Badges and supply-chain governance moved to the bottom.
- **Management dashboard** added to the minimal `docker-compose.yml` — new
  deployers now get a live UI at `localhost:8090` showing traffic, risk
  scores, and one-click blocking out of the box.
- **First-5-minutes guide** in README walks new users from deploy through
  their first block and dial adjustment, including recovery from accidental
  over-blocking.
- **Integration quick-reference** added to README with nginx, Cloudflare,
  AWS NLB, and direct-mode paths linking to full deployment guides.
- **Under Attack Live Dashboard (Phase 247)**: adds `/under-attack` page with real-time top-attacker table (polled every 5s via HTMX), one-click 1h/24h IP ban buttons, and Attack Mode API (`POST/DELETE/GET /api/v1/attack-mode`) that raises the dial to 75 with a 4-hour auto-revert. See `docs/phases/PHASE_247.md`.
- **Auto-escalating IP defense (Phase 248)**: IPs that persist after being tarpitted are automatically escalated to block then ban, without manual intervention. New `auto_escalate` config section (off by default) with configurable thresholds and shared-IP protection. Offense count visible in management API (`GET /api/v1/ip/{ip}/offense`). Attack Mode activates auto-escalation for its 4-hour duration via Redis key. See `docs/phases/PHASE_248.md`.
- **Datacenter ASN one-click block (Phase 249)**: Security Policy page lets operators tarpit or block all cloud/hosting provider traffic with one click — no config file editing, no restart. Hot-reloadable policy applies within seconds via Redis pub/sub. Default exceptions for Cloudflare, Fastly, and Akamai. Prometheus counter `ja4proxy_datacenter_policy_actions_total`. See `docs/phases/PHASE_249.md`.
- **Botnet fingerprint detection (Phase 250)**: Fingerprint tab on Under Attack page groups attack traffic by JA4 — showing unique IP count, the key indicator of a residential botnet. One-click fingerprint block stops all botnet IPs simultaneously including future additions. Safety gate prevents blocking known-browser fingerprints (Chrome, Firefox, Safari) from the attack UI. Botnet signal detection (`detect_botnet_signal`) with configurable Attack Mode thresholds. Expanded JA4 corpus (15+ entries) with label file. See `docs/phases/PHASE_250.md`.
- **Findings register hygiene — repoint 12 stale Python-prototype regression tests (Phase 309 R1)**: the 12 `regression_test:` entries in `docs/security/findings.yaml` that still pointed at deleted Python-proxy-prototype tests (`tests/unit/test_proxy_*`, `tests/unit/test_pentest_*`) were each repointed, per-finding, to the test that guards the equivalent behaviour in the current Go-only runtime — not blanket-sed'd. Eight repoint to existing verified Go tests (0005→TLS protocol lockdown, 0006→untrusted-PROXY-header strip, 0022→trusted-CIDR default-route rejection, 0028→backend dial timeout, 0030→beacon-suspects ZSET trim, 0033→adversarial ClientHello parser, 0036→IPv6 rate-key canonicalisation, 0038→atomic sliding-window Lua). Three got new, purpose-written Go regression tests where the invariant was real but unguarded: `TestRegression_JA4PROXY_2026_0027_CanonicalizeSNIRejectsKeyInjection` (SNI key-injection), `TestRegression_JA4PROXY_2026_0029_ECSFormatterEscapesControlChars` (ANSI/control-char log escaping), `TestRegression_JA4PROXY_2026_0039_RedactorDoesNotPatternMatchDigits` (timestamp false-positive can't recur — the Go redactor does no digit/Luhn matching). One (0054, config path traversal) was reclassified — the attacker-controllable `config_path` parameter is gone (operator CLI arg / `MANAGEMENT_PROXY_CONFIG_PATH` env var only). Findings needing it carry a `Go reclassification (Phase 309 R1)` note explaining why the chosen guard or the architecture covers the original behaviour. `findings_register.py validate` passes (61 findings, all `regression_test` paths resolve) and `FINDINGS_REGISTER.md` re-rendered.
- **OBSERVABILITY_STANDARDS §3/§4 PromQL reconciliation (Phase 309 R2)**: the example Grafana panels (§3) and Alertmanager rules (§4) in `docs/reference/OBSERVABILITY_STANDARDS.md` referenced five metric names from the deleted Python proxy that the Go runtime never emits — so those panels rendered blank and those alerts could never fire. Each was reconciled against the §1 registry / live code: `exception_handled_total`→`handler_panics_total`, `pipeline_unexpected_errors_total`→`connection_errors_total`, `cache_operations_total`→`redis_operations_total{result="error"}`, and the Tor-staleness alert (no Go refresh metric exists) → `TorListEmpty` on the real `tor_exit_list_entries == 0`. The `HighRiskBypassDisabled` example alert was removed: the Go proxy emits `ja4proxy_bypass_total{rule}` (bypass *usage*) but no bypass *config-state* metric, so it is flagged as a WP-6 code follow-on rather than a doc fix. Every `ja4proxy_*` metric now referenced in §3/§4 resolves to an emitted metric (verified against `internal/`+`cmd/`+`src/`+`management/`); the stale "not yet reconciled" caveat was replaced with a reconciliation summary.
- **REDIS_SCHEMA reconciled against the Go proxy (Phase 309 R3)**: Audited `docs/reference/REDIS_SCHEMA.md` key-by-key against the live code. Corrected two key renames (`session:{ip}`, `return_visitor:{ip}`); deprecated keys with no Go writer (`lifespan:{ip}`, the Phase 6 `tor:exit:ips`/`leader:tor_exit_download`, and the Python-only Phase 32/53/54/58/82 sections); documented previously-undocumented Go-proxy runtime keys (`ratelimit:ip|ja4|ip_ja4`, `dns:fcrdns:{ip}`, `abuseipdb:{ip}`, `audit:last_score:{ip}`, `proxy:heartbeat:{hostname}`, `geoip:blocked_cidrs`, `config:dial:sig`, `ja4proxy:dc:{dc}:sync:out`); added a Pub/Sub channel registry; and recorded two code/schema discrepancies (the dead-code `MultiCheck` bare-key mismatch and the live `config.reload` vs `config:reload` channel-name mismatch) as follow-up work.
- **Runbook staleness sweep + GDPR erasure fix (Phase 309 R4)**: Audited all 48 operational runbooks against the Go-only codebase and reconciled 12 of them. Removed dead Python-proxy references (`proxy.py` config-import check, `src/security/*.py`/`src.config.loader`/`src.tap.tap_sensor` paths, aioredis), corrected stale Redis keys/commands to what the Go proxy actually uses (`ja4proxy:dial`→`config:dial`, `ja4proxy:ban:*`→`ban:*`, `visitor:{ip}`→`return_visitor:{ip}`, `ja4proxy:config_reload`→`config:dial:change`, the non-existent `ja4proxy:dial:last_change_source`→`management:audit_log`, the non-existent `ja4proxy:asn:*` lookups→RDAP cache / event stream, `KEYS`→`--scan`), updated the TAP quick-start to the `ja4-tap` Go binary, and added a deprecation banner to `ti_feed_health.md` (it documents the deleted Python in-proxy secondary-TI-feed + ConfidenceManager subsystem; points operators to the live Phase 85 feed runbooks). Also fixed a real GDPR-completeness bug in `scripts/gdpr_delete.py`: the erasure catalogue targeted deleted-Python key forms and missed live Go-proxy keys, so erasure silently left `session:{ip}`, `return_visitor:{ip}`, `dns:fcrdns:{ip}`, and `audit:last_score:{ip}` behind — corrected the catalogue, fixed the `behavioural`→`behavioral` ZSET spelling, and added `tests/unit/test_gdpr_delete.py` to pin it.
- **Config-reload pub/sub fix + MultiCheck dead-code removal (Phase 309 R5)**: Fixed a live control-plane bug found in the R3 audit — the management API's `POST /api/v1/config/reload` published to `config.reload` (dot) while the Go proxy subscribes to `config:reload` (colon), so UI-triggered config reloads never reached the proxy. `config_ops.py` now publishes to `config:reload`, and a new `management/api/pubsub_signing.py` HMAC-signs the message (matching the proxy's `verifyPubSubHMAC` `{type, value, signature}` envelope and `${VAR:-default}` env-expansion byte-for-byte) when `redis.pubsub_hmac_secret` is configured. Added `management/tests/test_pubsub_signing.py` (replicating the Go verifier to prove cross-language compatibility) and tightened `test_config_ops.py` to pin the colon channel. Also removed the dead `MultiCheck()` method (`internal/redis/client.go` + `RedisReader` interface + 7 inert mock methods) — it read bare `whitelist`/`blacklist` keys nothing writes and had no caller. (Related still-open item: `POST /api/v1/nodes/{host}/reload` publishes to the unsubscribed `proxy:reload` channel.)
- **Throwaway single-host test VM (`scripts/dev/spin-test-vm.sh`)**: one-command rebuild of the disposable Ubuntu VM used to validate phase-231b native single-host deployment, with no host `sudo`. Runs a KVM-accelerated QEMU guest inside a Docker container (only Docker-group membership + `/dev/kvm` required); QEMU and the cloud-init NoCloud `seed.iso` tooling run in throwaway Alpine containers so nothing is installed on the host. Subcommands: `up`, `ssh`, `push` (rsync the repo in), `status`, `down`, `destroy`. Pairs with `scripts/validate-single-host.sh`. Documented in `docs/developer/test-vm.md`.
- **Docs information-architecture, index-first pass (Phase 309 WP-10)**: addressed the "docs are all over the place" problem without the risk of physically moving ~39 files (which would break ~244 internal links). Three changes: (1) **normalized the `audience:` frontmatter** on all 37 applicable top-level `docs/*.md` to a single 5-bucket vocabulary — `product` · `security` · `operator` · `developer` · `reference` — replacing the prior free-form/inconsistent values (`Developers`, `architects`, `operator`, `Operators, DevOps`, …); (2) **rebuilt `docs/README.md` into a complete role-organized index** that lists every top-level document exactly once under its owning audience (previously only ~19 of 39 were linked), plus a subsystem table pointing at `architecture/`, `decisions/`, `runbooks/`, `compliance/`, `security/`, `performance/`, `developer/`, `api/`, and `phases/`; (3) **de-duplicated the two MITRE ATT&CK documents** — `ATTACK_MAPPING.md` remains the single authoritative, CI-gated technique mapping, and `OPERATIONS_MAPPING.md` was refocused to its unique operational content (SecOps triage & remediation playbooks) with a pointer to the authoritative mapping, removing the divergent duplicate technique tables; the `OPERATIONS_GUIDE.md` reference links were repointed accordingly. No files were relocated, so all existing links still resolve (`check_doc_frontmatter.py`, `test_attack_mapping.py`, and the link checker stay green); the physical move into per-audience subdirectories remains a separately-signed-off follow-up. See `docs/README.md`.
- **Docs information-architecture, physical move (Phase 309 WP-10, PR2)**: completed the relocation the index-first pass (PR1) deferred. All 38 top-level `docs/*.md` now physically live in per-audience subdirectories matching their `audience:` frontmatter — new `docs/product/` (5), `docs/operations/` (6), `docs/reference/` (8), with the audience-facing security (9) and developer (10) docs merged into the existing `docs/security/` and `docs/developer/` trees. The top level of `docs/` now holds only `README.md` (the authoritative index) plus the subsystem subdirectories. A link-aware migration rewrote every relative inter-doc link to its new location and the literal `docs/<name>.md` references across the repo (CLAUDE.md, AGENTS.md, scripts, tests, CI workflow); a broken-target diff confirmed **zero new broken links** introduced by the move (pre-existing rot left untouched). Generators and gates were repointed: `scripts/sync-roadmap.py` writes `docs/reference/PROJECT_STATUS.md`, `scripts/traceability.py` writes `docs/reference/TRACEABILITY.md`, and `.gitignore` / the CI roadmap-artifact path / `tests/test_attack_mapping.py` / the doc-structure tests follow the new paths. `check_doc_frontmatter.py`, `traceability.py --check`, and the doc-structure tests stay green. See `docs/README.md`.
- **Go TAP/SPAN sensor — capture & reassembly foundation (Phase 316a)**: new `internal/tap` package and standalone `cmd/ja4-tap` binary that read mirrored traffic (live AF_PACKET or offline `--pcap-file`), reassemble both directions of each TCP connection, and emit the exact ClientHello/ServerHello bytes of every TLS handshake as a `HandshakeEvent`. Pure-Go capture stack (`github.com/gopacket/gopacket` fork: `afpacket`, `pcapgo`, `reassembly`, zero-alloc `DecodingLayerParser`) — no cgo. Per-direction 16 KB reassembly cap plus global page ceiling bound memory under flood. No fingerprints, no Redis writes yet (that is 316b). See `docs/decisions/ADR-316a.md` and `docs/phases/PHASE_316a.md`.
- **Kernel BPF filter (`--bpf-ports`) [316a inc. 2]**: replaces the placeholder `--bpf-filter` expression flag with a port-list flag (`--bpf-ports=443,8443`) that compiles a minimal BPF filter using `golang.org/x/net/bpf` — drops non-TCP, non-IPv4, and non-matching-dst-port packets before they reach userspace. Pure-Go, no libpcap/cgo dependency.
- **Privilege dropping & seccomp check [316a inc. 2]**: `DropCapabilities()` switches to UID/GID 65534 (nobody) with explicit `PR_SET_KEEPCAPS=0` via `golang.org/x/sys/unix`. `LoadSeccomp()` reads `/proc/self/status` and reports the current seccomp mode (0=disabled, 2=filter). Both are called after socket bind but before capture begins.
- **Go TAP sensor — passive OS-mismatch MVP (Phase 316b)**: the `cmd/ja4-tap` sensor now computes a conservative passive OS classification from each connection's SYN (TTL, window, MSS, TCP option order) and writes it to `fp:os:ip:{ip}`, closing the loop on the inline proxy's previously-dormant `tap_os_mismatch` signal. Introduces `internal/fingerprint.OSClass` — a single canonical OS-class vocabulary (`windows`/`macos`/`linux`/`ios` + `unknown`) shared by both the sensor writer and the `tap_consumer` reader, fixing the writer/reader vocabulary-drift bug the design review found (the consumer compared bare `linux` against the old writer's `linux_5x_default`, so the signal could never fire). The classifier is deliberately conservative: only exact, high-confidence stack signatures yield a concrete class (Windows/Linux); ambiguous, NAT/middlebox-normalised, Apple/Darwin, or SYN-less traffic is left `unknown` and **never written**, so a real browser is never mislabelled (zero-FP corpus test). The signal is **advisory-only** — a mismatch is scored under the dial (default 0 = monitor), never an automatic block. Also: 316a's `HandshakeEvent` extended to carry SYN/IP-stack features; `scripts/gdpr_delete.py` now erases `fp:os:ip`/`fp:ip` keys; new `ja4proxy_tap_fingerprints_written_total{result}` metric. See `docs/phases/PHASE_316b.md` and `docs/runbooks/tap_mode.md`.
- **Go TAP sensor — passive JA4T fingerprint + advisory blocklist signal (Phase 316c)**: the `cmd/ja4-tap` sensor now computes the canonical FoxIO **JA4T** TCP fingerprint (`{SYN window}_{TCP option kinds}_{MSS}_{window scale}`) from each connection's SYN — reusing the SYN `StackFeatures` 316b already captures — and writes it to `fp:ja4t:ip:{ip}` (24h TTL). A new inline proxy consumer (`ja4t_consumer`) reads that key on the hot path and emits an advisory `tap_ja4t_blocklist` RiskSignal when the observed JA4T is on an operator-configured blocklist. The blocklist is **empty by default**, so the signal is silent until an operator opts in — it cannot produce a false positive on its own — and like every TAP signal it is scored under the dial and never hard-blocks. JA4T is written only when a client SYN was observed (mid-stream captures write nothing). This phase deliberately scopes the original "full JA4 family" outline down to what is physically computable from a passive TLS TAP: a design review established that JA4H/JA4H2/JA4SSH require plaintext application data that is encrypted under TLS (dropped from the roadmap), JA4X needs the TLS Certificate message which is encrypted in TLS 1.3 (deferred, ≤TLS1.2-only), and QUIC needs UDP capture the TCP reassembler does not do (deferred). New metrics: `ja4proxy_tap_ja4t_written_total{result}` (sensor), `ja4proxy_tap_ja4t_lookups_total{result}` and `ja4proxy_tap_ja4t_signal_total{action}` (proxy); `scripts/gdpr_delete.py` now also erases `fp:ja4t:ip`. See `docs/phases/PHASE_316c.md` and `docs/runbooks/tap_mode.md`.
- **Go TAP sensor — out-of-band enforcement bridge, advisory by default (Phase 316d)**: the `cmd/ja4-tap` sensor can now *act* on a client whose passively-observed JA4T is on an operator-defined enforcement blocklist (`--ja4t-blocklist`), out of band — it is never inline. By **default** a match is recorded only to an advisory watchlist key `fp:ban_intent:ip:{ip}` (provenance value, 1h TTL); **nothing is blocked**, and an empty blocklist (the default) can never fire — a passive misclassification cannot produce a ban by construction. When the operator *consciously arms* enforcement (`--enforce` **and** a widened Redis ACL `~ban:*`), a match also writes a short-TTL `ban:{ip}` (default 5m, provenance value `tap_enforce:ja4t=…`) — the **same** canonical operator-ban key the inline proxy already hard-blocks on (Phase 231a) — so the inline proxy refuses the client's *next* connection (passive "one-strike"). A critical review re-scoped the original outline away from the archived Python design: the proposed `ja4proxy:bans` pub/sub has no Go consumer (dropped), and the iptables/ipset/BGP/HMAC-webhook blockers would expand the sensor far past its least-privilege design (deferred to 316e); CIDR auto-expansion is out of scope (single-IP only). Fail-open in every branch — an unparsable IP, an unreachable Redis, or a failed watchlist write all count and stop, and a failed watchlist write never escalates to a ban. Armed startup emits a loud WARN and sets `ja4proxy_tap_enforcement_armed=1`. New metrics: `ja4proxy_tap_enforcement_actions_total{result=skipped|watchlist|banned|error}` and gauge `ja4proxy_tap_enforcement_armed`; `scripts/gdpr_delete.py` now also erases `fp:ban_intent:ip`. See `docs/phases/PHASE_316d.md`, `docs/decisions/ADR-316d.md`, and `docs/runbooks/tap_mode.md`.
- **TAP intelligence export — pull-based EDL feed (Phase 316e)**: firewalls can now consume JA4proxy's active bans as a plaintext **External Dynamic List** over HTTP — `GET /api/v1/edl/{banned_ips|banned_cidrs|combined}` on the management API returns one IP/CIDR per line (IPv4 + IPv6), sorted, with an `ETag` (→ `304` on `If-None-Match`), `Cache-Control`, and `X-EDL-Count` headers. F5 BIG-IP and Palo Alto NGFW both natively poll an EDL URL, so this single endpoint replaces the per-vendor push clients the original outline proposed. The feed is **read-only** over ban state (`ban:{ip}` from operator/TAP bans, `ban_cidr:{cidr}` from RDAP block-expansion) and writes no new intelligence. **Auth** reuses the existing management-API token store (`mgmt:token:*`): mint a token with `POST /api/v1/tokens` and present it as `X-API-Key`, `Authorization: Bearer`, or `?token=` — revocation and expiry come for free, and no secret lives in `proxy.yml`. **Fail-open:** a Redis error serves an *empty* feed (HTTP 200), never a 5xx that would break the firewall's poller (an empty blocklist under-blocks, which is the recoverable error per the core asymmetry). Includes a per-token sliding-window rate limit (also fail-open) and a `max_entries` cap with logged truncation. Conservative default **off** (`edl.enabled: false` → `404` when disabled). A critical review re-scoped the original seven-exporter outline (EDL/F5/Palo Alto/Kafka/Syslog/TAXII/MISP, ported from the archived Python sensor) down to this one feed: putting outbound egress in the least-privilege capture sensor was the same anti-pattern rejected for 316d's external blockers, and most of the seven were redundant or niche for an inbound bot-protection proxy. Kafka, Syslog/CEF, TAXII-server, MISP, and the now-obviated F5/Palo Alto push clients are deferred until there is concrete demand. New config: `edl:` section in `config/proxy.yml`. New Redis key: `edl:ratelimit:{identity}` (transient, 60s). See `docs/phases/PHASE_316e.md`, `docs/decisions/ADR-316e.md`, and `docs/runbooks/edl_export.md`.
- **Repair `make sync` (Phase 331)**: fixed a mis-indented epic `phases:` list in `docs/phases/manifest.yaml` that YAML folded into a single bogus scalar (`102 - 106 - 161 - 204 - 329`), breaking `make sync` (and the documented close-phase regeneration of `TODO.md`/`PROJECT_STATUS.md`) with an opaque `KeyError`. Hardened `scripts/sync-roadmap.py` with `_validate_epic_phase_refs()` so any epic referencing an undefined phase id now fails loudly — naming the epic and the offending id — instead of dying deep in the table loop. Added regression tests. See `docs/phases/complete/PHASE_331.md`.
- **Merge-race reduction & CI shift-left (Phase 332)**: removed the recurring merge-conflict churn parallel phase PRs hit. The auto-generated roadmap docs (`docs/phases/TODO.md`, `docs/reference/PROJECT_STATUS.md`) are no longer committed — they are pure functions of `manifest.yaml`, regenerated by `make sync` and published by CI as the `roadmap-docs` artifact, so they can no longer conflict. Added a `make preflight` target (`lint → scan → test`) with an AGENTS.md mandate to run it green before opening any PR, trimmed the required-check set (Full Lint and Security Scan demoted to advisory — they still run via `make preflight`, on push-to-`main`, and nightly), and set `strict=false` on `main` to drop the rebase-on-base-advance loop. A GitHub merge queue was attempted but is unavailable (GitHub restricts it to organization-owned repos; this repo is personal-account-owned); the `merge_group` CI wiring is left in place for a possible future org move. Manifest `manifest.d/` fragments were deferred as low marginal benefit after the generated-doc fix. See `docs/phases/PHASE_332.md`.
- **Bootstrap Go-migration & 231b close-out (Phase 333)**: `bootstrap.sh` now
  calls `ja4p init` (Go wizard) instead of the deprecated Python
  `setup_wizard.py`; Python wizard archived with deprecation notice; LaTeX
  install chapter updated for Go-native wizard; Phase 231b marked COMPLETE.
# Phase 336 – Security Hardening

- **Capabilities** – Drop privilege to UID/GID 65534 after opening the AF_PACKET socket.
- **Seccomp** – Load a seccomp profile (placeholder) that restricts syscalls.
- **Poll Timeout** – `OptPollTimeout(100ms)` to avoid a shutdown hang.
- **Metrics** – Optional Prometheus server started by `--metrics-addr`.
- **Panic Recovery** – `tap.Recover` called from the sensor goroutine.
- **Makefile** – `tap-build` target for the standalone binary.
- ADR status validation (WP-R5, Phase 340): added ADR-204, ADR-205, ADR-206 to INDEX.md; updated Last Reviewed dates for all six post-Phase-309 ADRs; added Data Lifecycle & Resilience and TAP Sensor Architecture decision categories.
- Closed 4 remaining OPEN security findings (Phase 341): TAP reassembly buffer logging (F-0060), stale MaxConnectionLimit (F-0062), webhook URL validation TOCTOU (F-0066), Redis password exposed on CLI in PoC compose (F-0079).
- **Emergency Dashboard Access (Phase 511)**: Adds management HTTPS sidecar (Caddy, port 8444, self-signed cert), `make traffic-on`/`traffic-off` (iptables redirect for instant traffic insertion and rollback), rewritten `EMERGENCY_DEPLOY.md` (remote-first, pre-built images, 8-step procedure), and new `docs/runbooks/dashboard_access.md` covering SSH tunnel patterns, corporate web proxy bypass, two-datacentre access, and emergency change record template. Fixes `localhost:8090` references throughout.
- **PDF documentation sync, Phase 512 (synced to Phase 511 — SecOps Emergency Dashboard Access)**: all three offline PDFs updated to reflect the operational changes shipped in Phase 511. User-guide ch07 (Incident Response) gains a new *Accessing the Dashboard Remotely* section covering the SSH port-forward pattern (`ssh -J bastion dmz-host -L 8090:127.0.0.1:8090 -L 8444:127.0.0.1:8444 -N`), an *Emergency Deploy* section documenting `docker compose pull && docker compose up -d` with GHCR pre-built images (no build tools needed on the host), and a *Traffic Insertion* section documenting `make traffic-on` / `make traffic-off` (iptables PREROUTING redirect with instant rollback). Emergency fingerprint blocking is rewritten to use `./scripts/ja4-admin.sh block-ja4 <fingerprint>` as the primary path, with a safety-guarantee callout ("real browsers cannot be blocked") for use on incident calls. Ch02 (Installation) port table gains rows for 8443 (proxy TLS entry point) and 8444 (Caddy HTTPS sidecar), documents the GHCR image names, and fixes the health-check URL to `http://127.0.0.1:8090/api/v1/health`. Ch05 (Operations) `kill -HUP` pattern updated to `docker compose kill -s HUP ja4proxy`. Ch06 (Monitoring) all `localhost` URLs changed to `127.0.0.1` (corporate web proxies intercept the hostname form). Reference-manual ch08 (Deployment Reference) services table updated: `ja4proxy` image is now `ghcr.io/seanpor/ja4proxy-go:main` on port 8443; `management` image is `ghcr.io/seanpor/ja4proxy-management:main`; new `management-tls` (Caddy) row added; Caddy named volumes added to volume table. New subsections document pre-built GHCR images and the iptables traffic-insertion pattern. All three PDFs rebuild with zero LaTeX errors.
- **Fix (security): decision cache leaked per-IP decisions across clients (Phase 515, JA4PROXY-2026-0087, HIGH)**: the Go proxy's in-process `DecisionCache` was keyed on the JA4 fingerprint alone, cached IP-derived decisions, and had no TTL. Because a JA4 is shared by every client on the same TLS stack, a block/ban derived from one IP was served to every other client sharing that fingerprint (a permanent false positive that blocked real browsers) and an allow warmed by one client let an attacker with the same ClientHello bypass all per-IP controls including `ban:{ip}`. The cache is now keyed per client (`clientIP|JA4`) with asymmetric ALLOW/BLOCK TTLs enforced on read, per ADR-003. New `decision_cache:` config block (`allow_ttl_seconds` default 1800, `block_ttl_seconds` default 30, `max_entries` default 10000), hot-reloadable. See `docs/phases/PHASE_515.md`.
- **Fix (concurrency): data race on config hot reload (Phase 515, JA4PROXY-2026-0088, MEDIUM)**: `ReplaceConfig` swapped `p.cfg` and every signal-module pointer under `p.mu` on SIGHUP / pub-sub reload, but the async scoring path and the beaconing worker read them unlocked — memory-unsafe in Go. `processInternal` now snapshots the config and all swappable modules under a single read lock; `beaconingWorker` reads its detector under the lock. Clean under `go test -race`.
- **Fix (resource leak): beaconing/audit workers leaked per Pipeline (Phase 515, JA4PROXY-2026-0090, MEDIUM)**: `NewPipeline` started the beaconing and audit workers at construction with no stop path — they blocked forever on never-closed channels, each pinning the whole `Pipeline`, leaking two goroutines for every pipeline built and discarded (the `ja4p` CLI, every unit test). Their startup moved into `StartBackgroundWorkers(ctx)` and they now exit on `ctx` cancellation; construction starts zero background goroutines.
- **Hardening: nil-Ranger crash class in `BlocklistManager` (Phase 515, JA4PROXY-2026-0091, LOW)**: added a read-side guard in `Check()` so a feed whose trie is a nil `Ranger` interface is skipped rather than panicking. The write-side guard in `ReplaceFeed` was already present; this closes the class defensively.
- **Docs: decision cache reference sync (Phase 516)**: documented the new `decision_cache` config block (`allow_ttl_seconds`, `block_ttl_seconds`, `max_entries`) in the reference-manual config chapter with its per-client (IP + JA4) keying and asymmetric ALLOW/BLOCK TTL semantics (ADR-003), added a `decision_cache` row to the hot-reload support table, and tightened the glossary "warm/cold cache" entries to state the cache is keyed on the client IP together with its JA4 fingerprint (not the IP alone). Rebuilt `reference-manual.pdf` (zero LaTeX errors). See `docs/phases/PHASE_516.md`.
- **CI: Go race-detector gate (Phase 518)**: added a `test-race` Makefile target (`go test -race ./...`) and a `race` CI job that runs it on every PR, so the concurrency regression tests (config hot-reload snapshot `JA4PROXY-2026-0088`, worker lifecycle `-0090`, `forward()` config capture `-0068`) are actually enforced — the required `make test` gate runs without `-race` and so could not catch a revert of those fixes. Also fixed two pre-existing `cmd/ja4pd` **test** races that kept the full `-race` run red: `TestClientHelloFragmentation` shared a `bytes.Buffer` between the handler goroutine (logrus writer) and the test goroutine (reader) — now a mutex-guarded buffer; and `TestForward_ConfigLocalCapture` hung under `-race` load (net.Pipe timer starvation + a reload-vs-capture ordering flaw) — now uses a real TCP socket pair and captures the config before mutating it. No production code changed. See `docs/phases/PHASE_518.md`.
- **Fix (security): SNI/ALPN cross-connection data bleed in the async scorer (Phase 519, JA4PROXY-2026-0092, MEDIUM)**: `tls.ParseClientHello` returns SNI/ALPN as zero-copy strings that alias the `sync.Pool` read buffer, and `handleConn` handed `connCtx` (carrying them) to the default async scorer via `workChan` before returning the buffer to the pool. A later connection reusing the buffer could corrupt the SNI/ALPN the scoring/beaconing workers read — scoring on another connection's bytes, bleeding one connection's SNI hostname into another's logs, or (worst case) a corrupted ALPN missing the h2/h1 browser bypass and blocking a real browser. Fixed by cloning SNI/ALPN (`strings.Clone`) at a single choke point (`populateTLSFingerprints`) so `connCtx` owns them before it escapes; the parser keeps its zero-copy fast path for synchronous callers. Found during a remote-exploitability bug hunt (Phase 519) in which all Go fuzz targets — ClientHello parser (10.7M execs), fragmentation, PROXY v1/v2, smuggling — ran to convergence with zero crashers. See `docs/phases/PHASE_519.md`.
- **Security bug hunt — proxy + infrastructure (Phases 520/521)**: aggressive red-team pass documenting two junior-implementable findings (not yet fixed). `JA4PROXY-2026-0094` (MEDIUM, proxy): the operator manual ban (`ban:{ip}`) and Spamhaus blocklist are hard blocks evaluated only on the async scoring path, so when `workChan` saturates under flood the proxy forwards a banned/blocklisted IP without checking them — fix is to move those checks into the synchronous `checkHardBlocks`. `JA4PROXY-2026-0093` (HIGH, management API): `_is_production()` (3 copies) only recognises `ENVIRONMENT` == `production`/`prod`, so every test-mode escape hatch (hardcoded JWT secret, OIDC-signature skip, CSRF disable, SAML strict-off) and the startup guard fail **open** on a DMZ/unset environment — fix is a single fail-**closed** helper. Both phase docs (`docs/phases/PHASE_520.md`, `PHASE_521.md`) are written for a junior engineer with exact repro, fix steps, acceptance tests, and a critical self-review. See the phase docs.
- **Fix (security): manual ban and Spamhaus blocklist bypassed under scoring-queue saturation (Phase 520, JA4PROXY-2026-0094, MEDIUM)**: `Pipeline.Process` checked the operator manual ban (`ban:{ip}`) and the Spamhaus DROP/EDROP blocklist only inside `processInternal`, reached via the async `workChan`. When the queue saturated under flood, the `select` fell through to `default` and `Process` returned `allow` without ever reaching those checks, so a banned or blocklisted IP was forwarded to the backend. Both checks now run synchronously in `Process`, before the async enqueue, so they take effect regardless of queue state; `BlocklistManager.Check` is still called exactly once per connection (result cached on `ConnectionContext` and reused by `processInternal`) to avoid reintroducing the `JA4PROXY-2026-0037` TOCTOU. Fail-open for scoring is unchanged — ordinary traffic still gets `allow` under saturation. See `docs/phases/PHASE_520.md`.
- **Fix (security): management API test-mode escape hatches failed open for unset/unrecognised ENVIRONMENT (Phase 521, JA4PROXY-2026-0093, HIGH)**: `_is_production()` — duplicated four times across `auth.py`, `main.py`, and `middleware/csrf.py` — returned True only for `ENVIRONMENT` in `{production, prod}`, so every test-mode escape hatch (hardcoded JWT signing secret, CSRF disable, SAML strict-off) and the startup guard meant to catch them armed all failed open for an unset, misspelled, or merely unrecognised `ENVIRONMENT` (e.g. `dmz`, `staging`) — exactly the kind of value a DMZ security-appliance deployment plausibly has. A shared `management/api/environment.py` (`is_explicit_nonproduction()` / `is_production()`) now inverts the default: only an explicit dev/test allowlist (`dev`/`development`/`test`/`testing`/`local`/`ci`) enables the hatches; everything else — including unset — fails closed as production. See `docs/phases/PHASE_521.md`.
- **Security bug hunt — management auth & wiring (Phase 522)**: worked the Phase 521 backlog. RBAC, login-lockout (fails closed), OIDC/SAML, and Redis exposure held up. Two junior-implementable findings documented (OPEN, not fixed): `JA4PROXY-2026-0095` (MEDIUM) — insecure role defaults inconsistent with the `JA4PROXY-2026-0034` least-privilege posture (bearer-token and token-rotate default to `operator`, `_create_access_token` defaults to `admin`, malformed token expiry treated as non-expiring); fix is to fail closed to `auditor`. `JA4PROXY-2026-0096` (MEDIUM) — the quickstart `docker-compose.yml` ships a committed known-value `MANAGEMENT_JWT_SECRET` with no boot guard, so a non-overridden deployment signs admin JWTs with a public key; fix is a startup guard gated on the `0093` fail-closed environment helper. `docs/phases/PHASE_522.md` has exact repro, fix steps, acceptance tests, a critical self-review, and a Phase 523 continuation backlog (OIDC aud/iss binding, WebAuthn origin, analytics input validation, tarpit bounds, inter-container pub/sub HMAC).
- **Fix (security): insecure role defaults on the bearer/rotate/create paths (Phase 522, JA4PROXY-2026-0095, MEDIUM)**: `management/api/auth.py`'s `get_bearer_user` defaulted a bearer token with a missing/invalid `role` field to `operator` (write access) instead of the least-privileged `auditor`; `_create_access_token` defaulted its `role` parameter to `admin`; `routes/tokens.py`'s rotate handler defaulted a role-less old token to `operator`; and a malformed token `expires_at` was silently ignored, treating the token as non-expiring. All four now fail closed to `auditor` / reject the token, matching the rule `JA4PROXY-2026-0034` already established for the cookie-JWT path. `_create_access_token`'s `role` argument is now required — no caller can silently mint an admin token by omission.
- **Fix (security): quickstart compose ships a known-value JWT secret / admin password with no boot guard (Phase 522, JA4PROXY-2026-0096, MEDIUM)**: `docker-compose.yml` defaults `MANAGEMENT_JWT_SECRET` to a literal committed in this repository and `MANAGEMENT_ADMIN_PASSWORD` to `changeme`, so a deployment that forgot to override them signed admin JWTs with a public key. `management.api.main._enforce_strong_secrets()` now refuses to boot on the unset/default/short secret or the default password, unless `ENVIRONMENT` is an explicit dev/test value (reuses the `JA4PROXY-2026-0093` fail-closed helper) — the quickstart itself (`ENVIRONMENT=dev`) keeps booting unchanged. See `docs/phases/PHASE_522.md`.
- **Docs: consistency audit + SecOps form-abuse use case (Phase 524)**: junior-implementable review of the user-facing docs against themselves and the code. Documents four fixes (docs only): D1 (MAJOR) — the README and `CLAUDE.md` claim real-browser (h2/h1 ALPN) traffic "can never be blocked" as an "architectural guarantee," but the shipped default is `alpn_browser_bypass: false` (`JA4PROXY-2026-0004`, since a bot can spoof `ALPN=h2`), so browser-looking traffic is actually scored by default — the safety model must be reframed around monitor-mode + fail-open + the JA4 whitelist; D2 (MAJOR) — `PERFORMANCE_BENCHMARK.md`/README quote "~210 conn/s / single Python asyncio event loop," but the Python proxy was deleted in the Go rewrite (relabel historical + re-measure via `make bench-all`); D3 (MINOR) — inconsistent default-credential and `localhost` vs `127.0.0.1` guidance; D4 — write the "bots are filling my forms" use case honestly (catches non-browser and ALPN-spoofing bots out of the box; real-browser-driven bots share a genuine JA4 and need rate-limit/beaconing/ASN/AbuseIPDB signals, not JA4 alone; it is not a CAPTCHA). See `docs/phases/PHASE_524.md`.
- **Code Health Loop (Phase 800)**: deterministic gate-runner `scripts/phase-800-code-health.sh` (full tier `make lint/scan/test`, `--fast` tier for iteration; exit codes 0=CLEAN 1=RESIDUAL 2=STUCK 64=REFUSED; refuses `main` and dirty all-gates runs; enforced ≤33×170 report; logs under `.local/code-health/`) plus the `/code-health` fixing skill (`.claude/skills/code-health/SKILL.md`). Replaces the original Phase 800 auto-fix script, which live verification showed fabricating fix counts and auto-committing unreviewed files. See `docs/phases/PHASE_800.md`.
- **Dependency CVE triage (Phase 800)**: `click` 8.1.8 (PYSEC-2026-2132) and `protobuf` 4.25.9 (PYSEC-2026-1805) acknowledged in the lint gate with dated comments — both are walled off by semgrep (it pins `click~=8.1.8`; reaching protobuf 5.x needs semgrep≥1.137 whose `mcp==1.23.3` pin would reintroduce CVE-2025-66416). Removal condition: a semgrep release with OTEL≥1.37 and mcp≥1.28. Also raised the `google-cloud-storage` floor 2.0→3.0 to stop pip `resolution-too-deep` backtracking.
- **Lint fixes (Phase 800)**: ruff import-order fixes across 12 management/test files and a `TYPE_CHECKING` import fixing 3 `F821 httpx` errors in `tests/unit/management/conftest.py`.
- **Go toolchain 1.26.4 → 1.26.5 (Phase 800)**: remediates stdlib CVE-2026-39822 (os.Root symlink following, HIGH — flagged by Trivy in the ja4proxy/mockbackend images) and GO-2026-5856 (crypto/tls Encrypted Client Hello privacy leak — flagged by govulncheck on reachable paths). Bumped in `go.mod` ×2, six CI `go-version` pins, and the four digest-pinned `golang:*-alpine` builder images. Time-windowed `.trivyignore` entry (exp 2026-08-01) for CVE-2026-0994 (protobuf, CI-only test image, semgrep-walled).
- **Security: redact secrets in `ja4p init --dry-run` preview**: the setup wizard's dry-run preview printed the generated `.env` — admin password, Redis password, JWT/signing keys, Grafana/HAProxy passwords, and threat-intel API keys — to stdout, where it persisted in terminal scrollback and CI logs (CodeQL `go/clear-text-logging`, alert 95). The preview now masks every secret value (`***REDACTED***`); the on-disk chmod-600 `.env` is unchanged. Secret-key list consolidated to a single source of truth in `internal/wizard`.
- **Frontend Asset Vendoring & Static Compilation (Phase 232a)**: Secures the Management Console UI against CDN supply-chain risks and enables offline/air-gapped operations. Vendors all third-party JavaScript dependencies (`htmx.min.js`, `htmx-sse.js`, `alpinejs.min.js`, `chart.umd.min.js`) into `management/static/vendor/`, compiles and minifies static CSS via Tailwind CLI to `management/static/vendor/tailwind.css`, adds CSP script-src `'self'` enforcement, and cleans up redundant legacy static files from the repository. Updates `docs/OPERATIONS_GUIDE.md`. See `docs/phases/complete/PHASE_232a.md`.
- **First-party image base hardening + first-party HIGH gate (Phase 317)**: closes the
  deferred first-party HIGH-CVE gate from Phase 314 by **removing** the CVEs rather than
  waiving them. The four CVE-bearing first-party Python images — `analytics`, `tarpit`,
  `test`, `trafficgen` — are re-based onto a single digest-pinned
  `python:3.14.6-alpine3.24` base; `test`/`trafficgen` move off Debian `python:3.14-slim`
  (whose no-fix distro HIGH could only be cleared by changing the base), and the alpine
  pair is refreshed to a current openssl. `Dockerfile.test` drops its dead `proxy.py`
  reference (archived in Phase 128) and switches coverage to `--cov=src`. `scan-first-party`
  now gates on **HIGH+CRITICAL** and actually builds the profile-gated `test`/`trafficgen`
  images so they are scanned (previously a vacuous pass); `test_ci_flow` asserts the gate.
  All six first-party images verified scanning **0 HIGH/CRITICAL**. `admin`/`management`
  (Debian slim FastAPI services) stay out of the first-party gate with their no-fix distro
  CVEs waiver-tracked. No image was excluded to green the gate. See
  `docs/phases/complete/PHASE_317.md`.
- **Interface & Container Architecture Review & Consolidation Planning (Phase 230 & 231)**: Completed a thorough architectural audit of all containers and user-facing interfaces. Documented 11 security and operational findings, proposed a target container inventory (eliminating the duplicate `admin-api` service and switching to a plain Alpine Redis base), and established the 7-phase master implementation plan for the Container & Interface Consolidation programme (Phases 232–238). See `docs/phases/complete/PHASE_230.md` and `docs/phases/complete/PHASE_231.md`.
- **Go Redis restore — selective & GDPR-aware (Phase 315b)**: `ja4p restore` loads
  a 315a artifact back into Redis with the guard-rails that make restore safe. **By
  default it can never re-block a real user**: block-state (`ban:*`, `ban_cidr:*`,
  `ip:blacklist`, `ja4:blacklist`, `config:dial`) is skipped unless `--include-blocks`
  is passed. **It never resurrects a GDPR-erased subject**: before writing any per-IP
  key it consults a tombstone set built from the live `management:gdpr_erasure_log`
  (read **before** any `--force` `FLUSHDB` destroys it) merged with an optional
  `--tombstone-file`, with IPv4/IPv6-canonical subject extraction. Integrity is
  verified before any write (tamper/truncation/wrong-key fail closed); a non-empty
  target needs `--force`; `--dry-run` is side-effect-free; TTLs are re-applied from
  the artifact; a newer-schema artifact is refused (downgrade-block); every restore
  is audited to `management:policy_audit` + `backup:last_restore`/`backup:restored_from`.
  Registers the three `ja4proxy_restore_*` series (+`…_skipped_total{reason}`),
  completing the `backup.rules.yml` alert set 315a started. Reuses 315a's
  `DecryptPayload`/artifact format/lock and the CLI's passphrase+redis plumbing.
  Tested (classification incl. IPv6, block-gating, GDPR skip via file **and** live
  log, dry-run, non-empty/force, tamper, schema-block, audit, metrics; real-Redis
  round-trip + GDPR-not-resurrected behind `-tags integration`). See **ADR-206**.
  Deferred (non-safety): full schema-migrator, `--prefix-map`, post-restore smoke.
- **Go Redis backup engine (Phase 315a)**: the Go production runtime can now
  produce an encrypted, restorable snapshot of its durable Redis security state
  via `ja4p backup` (and `ja4p backup inspect` for offline metadata). It uses
  logical per-key `DUMP`/`PTTL` (every Redis type, TTLs preserved), gzip +
  **AES-256-GCM** with a PBKDF2-SHA256-derived key (random salt + nonce per
  artifact, GCM-authenticated header so tampering/truncation fails closed), an
  atomic `0600` write in a `0700` dir, count/age retention pruning, a
  `backup:operation_lock` (`SET NX EX 600`) against concurrent runs, and paced
  pipelined `SCAN` to spare the Redis thread. A conservative default scope backs
  up security-state prefixes and **excludes** credential/session/MFA keys
  (`mgmt:totp`/`webauthn`/`saml`/`oidc`/`session`) and ephemeral counters. This
  revives the four previously-dead `ja4proxy_backup_*` alerts in
  `backup.rules.yml` by finally emitting their metrics (via the process registry
  and an optional node-exporter textfile); the alert series was renamed
  `…_last_success_timestamp` → `…_last_success_seconds` per OBSERVABILITY_STANDARDS.
  Grounding correction vs the plan: the subcommand lives in the cobra CLI `ja4p`,
  not the `ja4pd` daemon. Restore is the sister phase **315b**. See **ADR-205** and
  `docs/runbooks/backup_restore.md`. Unit-tested (crypto round-trip / wrong-key /
  tamper, scope+exclude, TTL capture, retention, metrics toggle, lock); the
  every-type + IPv6 real-Redis round-trip is a `-tags integration` test (miniredis
  only DUMPs strings).

### Security
- **Third-party image HIGH-CVE remediation — differentiated gating (Phase 314)**:
  A fresh authoritative Trivy scan (2026-06-13) showed only 2 of 9 pinned
  third-party images were bump-fixable; the rest are already on their newest
  stable tag with brand-new upstream Go-stdlib/distro HIGH CVEs we cannot fix
  ourselves. Bumped the two that *do* have a fixed tag — `prom/alertmanager`
  `v0.32.1`→`v0.33.0` and `oliver006/redis_exporter` `v1.84.0`→`v1.86.0` (both
  re-scanned HIGH/CRITICAL-clean) — synced across `Makefile` `TRIVY_IMAGES`,
  the monitoring/prod compose files, the `redis-secure` Ansible default, and
  `docs/DOCKER_IMAGES.md`. Adopted a **differentiated gate**: hard HIGH+CRITICAL
  on Dockerfiles and our own Go toolchain; third-party images stay CRITICAL-gated
  with HIGH **reported and tracked** in a new dated waiver register
  (`docs/security/THIRD_PARTY_CVE_WAIVERS.md`) — never silently ignored — rather
  than a blanket HIGH gate that would flap the required CI gate red on un-fixable
  upstream CVEs. Reconciled the long-drifted `docs/DOCKER_IMAGES.md` third-party
  inventory to the actually-pinned tags. The full HIGH gate-flip (first-party
  base-image rework + upstream rebuilds) is deferred to a follow-up; the Phase 313
  deferred HIGH-gate box stays open, annotated with the decision.

### Added
- **Branch hygiene and stale branch cleanup (Phase 329)**: Introduced automated Git branch hygiene guidelines and a Python script (`scripts/branch_hygiene.py`) to safely audit, classify, and delete stale/merged remote and local branches. Developed unit tests and a permanent developer runbook (`docs/developer/BRANCH_HYGIENE.md`).
- **Go blocklist feed downloader (Phase 309 WP-6)**: the Go proxy now downloads
  Spamhaus DROP/EDROP (and any configured CIDR feed) on a per-feed timer and
  atomically swaps the parsed trie into the live `BlocklistManager`. Previously
  the Go `BlocklistManager` only loaded from a local file that nothing ever
  populated, so Spamhaus hard-blocking was inert. The downloader uses
  `ETag`/`If-None-Match` conditional requests (a `304` counts as a successful
  refresh), a bounded 64 MiB body, a lock-free `atomic.Pointer` trie swap, and a
  warm-restart disk cache (default `/var/lib/ja4proxy/blocklists/<name>.txt`,
  overridable per feed via `path:`). **Fail safe**: any error — transport,
  non-2xx, parse, or a 0-entry body — increments
  `ja4proxy_blocklist_download_errors_total{feed}` and keeps the last-good trie.
  No leader election by design (see **ADR-204**). New per-feed metrics
  `ja4proxy_blocklist_download_errors_total` and
  `ja4proxy_blocklist_last_refresh_success_seconds`.

### Removed
- **Orphaned Python-prototype tests (Phase 309 tidyup)**: deleted 35 test files
  that imported modules removed when the Python prototype was archived
  (`5afeba26`) — they errored on collection and could never run, so `pytest
  tests/` aborted with 27 collection errors. `pytest tests/ --co` now collects
  2034 tests with **0 errors**. Each file either tested a subsystem already
  ported to Go (covered by Go tests) or a feature intentionally removed with the
  prototype (TAP sensor, Python backup, the `GDPRStorage` retention abstraction,
  per-provider TI lookups). Retained `tests/fp_corpus/data/` (reusable FP corpus)
  and `tests/fuzz/README.md`. Full audit + the residual Go coverage gaps worth
  porting (notably **quantitative FP-rate thresholds** per CLAUDE.md, and a dead
  `backup.rules.yml` alert set) are catalogued in
  `docs/reports/python-prototype-test-removal-audit.md`.

### Fixed
- **Resolve security scan vulnerability failures (Phase 330)**: Aligned the production proxy image version tag to `ja4proxy:2.0.0` (matching the Go rewrite release) in `deploy/docker/docker-compose.prod.yml` and the `Makefile` first-party image list. This ensures vulnerability scans run against the clean Go/Alpine-based production image instead of the stale Python-based `ja4proxy:1.0.0` image, and resolves `check-image-versions` warnings about version drift.
- **Four dead security alerts now fire on real signals (Phase 309 WP-6)**: the
  metrics behind `AbuseIPDBQuotaExhausted`, `SpamhausDownloadFailed`,
  `SpamhausListStale`, and `BeaconingDetected` were emitted only by the Python
  prototypes that were deleted after the Go port, so the alerts could never
  fire. Added the missing Go emitters: AbuseIPDB detects HTTP 429 /
  `X-RateLimit-Remaining: 0` and flips `ja4proxy_abuseipdb_quota_exhausted`
  (self-clearing on the next lookup with quota); the beaconing detector records
  each flagged `(IP, JA4)` on the `beacon:suspects` ZSET and publishes its size
  as `ja4proxy_beaconing_suspects`; the new feed downloader emits the two
  blocklist metrics. `SpamhausListStale`'s threshold was raised 2h → ~25h to sit
  above the 12h refresh interval. Also fixed the blocklist line parser, which
  never handled Spamhaus DROP annotations (`1.2.3.0/24 ; SBL123`) — only bare
  CIDRs — and now handles `spamhaus`/`cidr`/`ipset` formats.
- **Phase-309 reconciliation — ADR-003 + findings register**: restored **ADR-003**
  (it had been overwritten with a duplicate of ADR-005; its correct subject is the
  cache-TTL asymmetry — ALLOW ~30min / BLOCK ~30s — rewritten from the decision
  log). Repointed **20** stale `docs/security/findings.yaml` `regression_test`
  paths (16 `cmd/proxy/`→`cmd/ja4pd/` + 4 bare Go paths qualified to their real
  `*_test.go`). 12 findings citing deleted Python-prototype tests remain flagged
  for per-finding Go-coverage repointing.

### Added
- **Single-host bootstrap & wizard (Phase 231b, software core)**: `scripts/setup_wizard.py`
  (interactive, generates `.env` secrets — **never echoed** — at chmod 600) and
  `scripts/bootstrap.sh` (zero-compile installer: OS detect, offline-tarball load,
  firewall gating from `.env`, systemd unit, logrotate, daily backup, `--check`/`--uninstall`).
  Defaults to monitor mode; admin ports stay on loopback (real scheme 8090/9090/9091/3000).
- **Single-host core (Phase 231a)**: `ja4pd` can now **write a PROXY protocol
  header (v1/v2) to the backend** so a TLS-passthrough deployment preserves the
  real client IP/port without decrypting — `write_proxy_protocol` (default
  `false`) + `write_proxy_protocol_version` (`1`|`2`, default `1`) in
  `config/proxy.yml`. FP-safe: indeterminate addresses degrade to `PROXY
  UNKNOWN`/v2 LOCAL rather than dropping a valid client. Also enforces **manual
  bans (`ban:{ip}`)** at the top of the pipeline so they block immediately even
  in monitor mode (`dial: 0`), fail-open on a Redis error.

### Fixed
- **Active-bans metric (Phase 231a)**: `CountKeys` queried the wrong prefix
  (`ja4proxy:ban:*`), so the active-bans gauge always read 0; corrected to the
  canonical `ban:*`.
- **CI resilience — `pip-audit` (Phase 311)**: a transient PyPI/OSV outage no
  longer reddens the required Full Lint gate (which also spammed maintainer
  emails and showed public CI failures). `scripts/pip-audit-resilient.sh` retries
  on a service outage and soft-passes with a CI warning if the vulnerability
  service is unreachable, while a **real vulnerability still fails the build**.
  Wired into `make lint` (`lint-static`) and the standalone dependency-audit job.
- **CI resilience — `pip-audit` dual-service fallback (Phase 312)**: when PyPI is
  unreachable the wrapper now falls back to **OSV.dev** before any soft-pass, so
  the warn-and-proceed path requires *both* services down at once (rare) — while
  staying live (no offline/stale DB). A real vulnerability on either path still
  fails the build.
- **Containerise the lint toolchain (Phase 313)**: every linter now runs in a
  container so CI/local share one toolchain and the gate no longer depends on a
  flaky host `pip install`. The Python linters + project Python scripts (ruff,
  mypy, bandit, pip-audit, the doc/meta/phase checks, the ATT&CK pytest) run in a
  pinned `Dockerfile.tools` image via `$(TOOLS_RUN)`; semgrep and ansible-lint
  run from their official images (neither runs on Python 3.14); hadolint,
  shellcheck, trivy, gitleaks, gosec, promtool, amtool, scorecard and lychee stay
  on their own images. `make lint`/`make scan` call `lint-all`/`scan-all`
  directly (the broken `docker-run-tools` Docker-in-Docker wrapper was removed)
  and `scripts/pipeline_summary.py` prints a one-line verdict without recursing into
  `make`. `lint-go` keeps the host Go toolchain (go.mod needs go 1.26); lychee
  link-check, ansible-lint and scorecard are advisory (their gates are the
  dedicated workflows). Verified with a full local `make lint` (exit 0).

### Added
- **Dev lanes + clean load test (Phase 310)**: each git worktree auto-gets a
  collision-free "lane" — its own published host ports + unique compose project
  and docker network — so multiple checkouts run on one host without clashing.
  `make lane` / `make open SVC=…` / `make loadtest` (good/bad traffic mix,
  default 5% good / 95% bad, watch it in the lane's Grafana). The default lane
  runs without HAProxy (single proxy; `WITH_HAPROXY=1` for the multi-proxy test).
- **Management-UI front-end hardening (Phase 230)**: self-hosted + SHA-pinned
  vendored JS (`SHA256SUMS` + `VENDOR.md` + integrity test), a **pre-built purged
  Tailwind CSS** (replacing the 407 KB browser/runtime "Play" build), a
  Content-Security-Policy, and no external CDN/font fetches; plus `make scan-js`
  (retire.js CVE scan of the vendored JS) wired into CI.

### Changed
- **Documentation source-of-truth audit (Phase 309, in progress)**: every doc
  now carries **Version 2.0.0** + a content **"last reviewed"** date (not the
  build date); author name corrected to **Seán Ó Ríordáin**; the user guide,
  `SCALING_GUIDE`, and `OBSERVABILITY_STANDARDS` rewritten to the Go-native
  architecture; the OBSERVABILITY metric registry regenerated from code; live
  alert rules and the CVD/SLA policy text reconciled; Grafana port docs
  `3001`→`3000`. Supersedes **Phase 221** (PDF refresh) and resolves **Phase 159**
  ("10k Mission" — the ~350 CPS cap was the Docker `docker-proxy` relay;
  host-native sustains ~3,000 CPS).

### Security
- **Code-scanning remediation (Phase 308)**: cleared the 60-alert code-scanning
  backlog (7 CodeQL + 53 Scorecard) left after Phase 302 enabled CodeQL +
  OpenSSF Scorecard. **CodeQL (7)**, each verified against the code: `#77`
  (the local fixture recorder `scripts/capture_server.py` bound `0.0.0.0`) is
  **fixed in code** → `127.0.0.1` (its clients already target loopback) rather
  than dismissed; the two `py/url-redirection` findings were dismissed as
  **false positives** (mitigated by `safe_relative_redirect` at `oidc.py:431` /
  `saml.py:323` — CodeQL can't trace the custom sanitizer); the splunk
  `py/clear-text-logging` was dismissed FP (`api_token` is only used in the
  `Authorization` header, never passed to `_log()`); and the two legacy-TLS
  generators + the Go benchmark's `InsecureSkipVerify`-vs-self-signed-mock were
  dismissed **used-in-tests** (their insecurity is intrinsic to the tool and
  non-production). All per-alert with code-backed justifications in the audit
  trail — **no blanket suppression**. **Scorecard (53)**: these are OpenSSF
  supply-chain *scores*, not vulnerabilities, and aren't meaningfully actionable
  — production Dockerfile base images are already digest-pinned (Phase 229); the
  3 `TokenPermissions` are *required* write (SARIF upload / Dependabot
  auto-merge / metrics auto-commit), already job-scoped with `contents: read` at
  top level; `Vulnerabilities` self-clears now Dependabot is at 0; the rest are
  solo-repo process scores. Removed the `"Upload to code-scanning"` step (and
  the now-unneeded `security-events: write`) from `scorecard.yml` so the noise
  stops drowning real CodeQL findings — Scorecard still runs, still publishes
  the badge (`publish_results`), and still keeps the `results.sarif` artifact;
  only the Security-tab upload is gone (one-step reversible).

### Changed
- **Documentation coherence, setup standardization, and link remediation (Phase 307)**: Established a coherent documentation architecture with clear single sources of truth. Standardized onboarding around the `make init` guided wizard and aligned Go proxy paths (`cmd/ja4pd`, `cmd/ja4p`). Removed obsolete Python proxy references, corrected all broken internal links, and added frontmatter blocks to remote manual testing and evaluation guides to pass `make doc-health`.

### Fixed
- **Test environment stability on `.env` presence**: Fixed test failures caused by `pytest-dotenv` loading the production-mode environment and warning level from `.env` by adding explicit environment overrides at the top of `tests/conftest.py`.

### Performance
- **Go proxy hot-path tuning (Phase 306, from PR #95)**: the bidirectional
  forward loop now reuses 32KB buffers from a `sync.Pool` instead of allocating
  one per connection (removes per-connection GC pressure under load); the Redis
  client pool is pre-warmed (`PoolSize: 100`, `MinIdleConns: 10`) to avoid
  cold-start dial latency; and async risk scoring fans out across a **fixed**
  pool of 32 worker goroutines (was 1) draining a deeper `workChan`
  (10000 → 20000) so accept bursts are absorbed rather than serialised. Also
  fixed the dev/POC/Performance wizard scenarios and the POC health check to use
  the real backend port **8443** (was 443, which is HAProxy's ingress;
  Production, a real HTTPS backend, stays 443), and switched `tarpit-server.py`
  to lazy `%s` logging. These are the legitimate wins from external PR #95,
  re-landed on a clean branch without the regressions it carried (see Security
  and Fixed below).

### Fixed
- **ATT&CK mapping doc + CI gate (Phase 306)**: `docs/ATTACK_MAPPING.md` and its
  CI gate `tests/test_attack_mapping.py` were **both broken on `main`** — the doc
  had been relocated to `docs/` but the test still pointed at
  `docs/for-architects/` (so it failed with `FileNotFoundError`), and the doc
  still listed retired Python-prototype source files (`src/security/*.py`, gone
  since v2.0.0). The retired-prototype rows were removed, the two genuine
  rate-tracker rows repointed to `internal/security/rate_limiter.go`, and the
  test path corrected — the gate now passes for the first time. (External PR #95
  had instead run a blind `*.py → *.go` find-replace that produced
  self-contradictory rows; that approach was discarded in favour of this one.)

### Security
- **Forward-path idle timeout restored (Phase 306)**: PR #95's switch to a
  deadline-free copy in the Go proxy's `forward()` silently removed the per-read
  `SetReadDeadline(read_timeout)` / `SetWriteDeadline(write_timeout)`
  idle-connection reaper. That re-opened a resource-exhaustion vector — a
  slowloris / idle-hold client would pin a goroutine **and** a pooled buffer
  indefinitely, and the operator-configured `read_timeout` / `write_timeout`
  knobs became dead. The reaper is restored **inside** the new pooled-buffer copy
  (the buffer-pool win and the deadlines coexist), guarded by a new Go regression
  test (`TestForward_IdleConnectionIsReaped`) that tears down an idle pair at
  `read_timeout` and would hang/fail if the deadlines are ever removed again. The
  per-connection decision log was kept at **Info** (PR #95 demoted it to Debug)
  to preserve the audit trail.
- **CodeQL code-scanning triage (Phase 305)**: worked through the 14 CodeQL
  Python findings (+1 Go bench) that enabling code scanning (Phase 302)
  surfaced. **Three were genuine, all in the Management-API web layer** and are
  now **fixed with regression tests** (`management/tests/test_codeql_305_regression.py`):
  a **reflected XSS** in `/api/v1/partials/list-table` (the unvalidated `list`
  query param was interpolated raw into HTML — now `html.escape`-d), and
  **error-detail exposure** (`str(exc)` of a Redis failure returned to the
  client) in `/health/deep` and the **unauthenticated** `/ready` (now logged
  server-side, generic reason to the caller). A fourth pair (OIDC/SAML
  `py/url-redirection`) was **hardened rather than dismissed**: the post-login
  redirect target is currently a hardcoded `"/"` (no live bug), but to be
  regression-proof a `safe_relative_redirect` guard now confines both callbacks
  to same-site relative paths (rejects absolute / protocol-relative `//evil` /
  backslash variants) — the textbook "don't dismiss a safe-by-constant FP,
  harden it" case. The two test TLS servers
  (`scripts/mock-backend.py`, `tests/docker/tls_backend.py`) were **hardened**
  with an explicit `TLS 1.2` floor — clearing `py/insecure-protocol`
  *legitimately* rather than by dismissal. The remainder were **verified false
  positives** (`redis_client` logs the *redacted* URL — sanitizer confirmed;
  the OIDC/SAML redirect targets are a hardcoded `"/"`; `auth.py` logs a config
  CIDR, not a secret; the Splunk action never logs its token) or **intentional
  test tooling** (the legacy-TLS *generators* exist to exercise the proxy's
  fingerprint detection; the bind-all capture helper; the bench
  `InsecureSkipVerify` against the self-signed mock) — each dismissed
  per-alert with a code-backed justification in the GitHub audit trail, **no
  blanket rule suppression**. The Go production proxy produced no genuine
  code-scanning bug.
- **Dependency CVE remediation (Phase 304)**: triaged the 118 alerts that
  enabling Dependabot + CodeQL (Phase 302) surfaced — the real, fixable,
  *production* findings are concentrated in the Python Management-API auth stack;
  the **Go production proxy is essentially clean**. The Phase 302 auto-merge had
  already landed `authlib 1.4.0→1.6.12` and `python-multipart 0.0.12→0.0.32`
  (minor/patch). This phase did the three Dependabot correctly held back:
  `cryptography 45.0.0→46.0.5` (a **major** bump — `management/requirements.txt`
  and the root `requirements.txt` floor), `python-jose 3.3.0→3.4.0` (critical
  algorithm-confusion CVE; a `python-jose`→PyJWT migration is flagged as a
  follow-up since jose is effectively unmaintained), and the indirect
  `google.golang.org/grpc 1.76.0→1.79.3` in `deploy/terraform-provider/go.mod`
  (deploy tooling, via `go get` + `go mod tidy`). The management suite passes
  (614) against the upgraded stack. Noise documented, **not** bulk-suppressed:
  the bench-tool `go/disabled-certificate-check` (already `#nosec`, hits the
  self-signed mock) and the OpenSSF Scorecard advisories that appear as
  code-scanning "high" are benign; the 9 CodeQL Python findings are left as a
  case-by-case follow-up.
- **Repository security aids enabled + automated (Phase 302)**: turned on Dependabot **alerts** + **security updates** and **private vulnerability reporting**. To keep these low-effort under branch protection, added a SHA-pinned `dependabot-automerge.yml` that auto-merges Dependabot **patch/minor** PRs once the 10 required checks pass (majors stay manual), and throttled `dependabot.yml` weekly → monthly. Two UI-only toggles documented for the operator (CodeQL "Default setup"; secret-scanning validity checks).
- **Production compose port-exposure hardening (Phase 303)**: `docker-compose.prod.yml` published several "internal only" services on `0.0.0.0` (proxy 8080/9090 as random host ports, analytics, tarpit, loki, prometheus) — only Grafana + HAProxy-stats were correctly loopback-bound. Removed the host `ports:` for purely-internal services (reached over the docker network by service name — verified `prometheus.yml` scrapes by DNS, not host ports) and bound the Prometheus UI to `${AGENT_BIND_IP:-127.0.0.1}`. Only `haproxy 443/80` remain public.

### Fixed
- **`make clean` resilient to an incomplete `.env`**: it aborted with `MANAGEMENT_JWT_SECRET is required` in a fresh worktree because `docker compose down` still evaluates the compose `${VAR:?}` interpolations. Added a `CLEAN_DUMMY_ENV` prefix (values irrelevant for `down`) and made `--env-file` conditional on the file existing.

### Fixed
- **Env template completeness (Phase 301)**: added `HAPROXY_STATS_USER`/`HAPROXY_STATS_PASSWORD` (compose-`required`, previously absent) to `template.env` with generation guidance, so `cp template.env .env` boots the full stack incl. monitoring. Deleted the orphan `.env.example` (unreferenced, shipped weak `changeme` defaults). Added an optional commented threat-intel block. (Audit: Phase 300.)
- **Housekeeping**: fixed the `manifest.yaml` `action_plan` path for Phase 160 (`docs/phases/` → `docs/phases/complete/PHASE_160.md`) — `make lint-phases` is now fully clean (0 violations); repaired literal-`\n` corruption in `scripts/perf-matrix.sh` (the whole script was one line); resolved committed merge-conflict markers left in `PHASE_201/202/203.md` (kept the canonical HEAD content).

### Changed
- **Pinned linter container images (Phase 225 part 2, COMPLETE)**: the lint/scan tools already ran in containers, but several used floating tags. Pinned to the exact in-use versions for reproducibility (zero behaviour change): `hadolint/hadolint:v2.14.0`, `koalaman/shellcheck:v0.11.0`, `zricethezav/gitleaks:v8.30.1`, `lycheeverse/lychee:0.24.2`, and the `lint-types`/`lint-quality` image `python:3.14-slim → python:3.14.0-slim` (`amtool`/`promtool` were already pinned). `codespell`/`markdownlint` were dropped from `make doctor`'s tool list — they are not used by any target.

### Added
- **Remote manual-testing (Phase 220, salvaged from PR #82)**: `scripts/test-bot.py` — a stdlib-only TLS test bot that drives connections through a (remote) proxy and reports ALLOWED/BLOCKED + JA4 per profile — plus `make remote-bot HOST=… [PORT=…]` and `docs/runbooks/REMOTE_TESTING.md`.

### Security
- **Remote testing reuses the existing `AGENT_BIND_IP` model, not a `0.0.0.0` override**: PR #82 proposed a `docker-compose.remote.yml` binding *every* port (incl. Management UI and Grafana) to `0.0.0.0`. That was dropped — the `poc`/`monitoring` compose files already bind every service to `AGENT_BIND_IP` (default `127.0.0.1`) and `start-poc.sh` validates it via `check_bind_address.py` (refuses public/`0.0.0.0`). Remote access = set `AGENT_BIND_IP` to the server's private LAN IP, `make start`, `make remote-bot`.

### Security
- **Docs link-check is now a blocking, required gate**: the lychee docs link-check is added to `main`'s required status checks (broken links block the PR instead of merely emailing). To make a required check safe, its workflow (`docs-link-check.yml`) now runs on **every** PR (the previous `paths:` filter would have left non-docs PRs blocked forever waiting for an unreported check). `test_workflow_pinning.py` now also verifies any external required check exists and is unfiltered.

### Added
- **`make scan-summary` (Phase 228, COMPLETE)**: `scripts/scan_summary.py` (stdlib-only, unit-tested) turns the scan blur into compact tables — a per-image Trivy CVE rollup (CRIT/HIGH/MED, reusing the Phase 227 cache) **and** a gosec HIGH/MED/LOW rollup (from the pinned `security-scan` image). Both are reporting-only with gate-consistent verdicts — `make scan` stays the authoritative gate. (A `misconfig` mode is included for manual use but not auto-run, since a whole-dir scan is broader than the gated file list; a `make lint` rollup was deliberately descoped as `make lint` already prints a clear per-target status.)

### Changed
- **Accurate `make doctor` (Phase 225)**: `doctor` now separates **required** host tools (docker, Go 1.26+, python3 — hard-fail if missing) from **informational** notes, and no longer emits scary "Warning: … some targets will fail" for the local Python 3.10-vs-3.14 gap or for absent host copies of `hadolint`/`trivy`/`gitleaks`/`codespell`/`markdownlint`/`amtool` (those run authoritatively in CI; trivy runs in a pinned container via `make scan`). Full tool containerization is the remaining half of Phase 225.

### Performance
- **Trivy DB caching (Phase 227)**: `make scan` now mounts a shared `TRIVY_CACHE` dir into every trivy container, so the vulnerability DB is downloaded once per run instead of once per image (~13× → 1×); a SHA-pinned `actions/cache` step persists it across CI runs.

### Security
- **Branch protection hardened & made correct**: `main` requires a PR passing **all nine** gating CI checks (was only 4) with `enforce_admins=true` and auto-merge; `scripts/branch_protection.sh` was rewritten to the current job names (it had stale `Go tests`/`Python tests` contexts) and the missing require-PR rule; the `KNOWN_ACTION_SHAS` allowlist was completed (ci.yml + scorecard.yml pins); and `tests/test_workflow_pinning.py` is now run by `make test` so pin/context drift can't silently return.

### Security
- **Perl CVEs eliminated, not ignored (Phase 229)**: analytics & tarpit moved from `python:3.14-slim` (Debian, ships perl-base with no-fix CVEs CVE-2026-42496/-42497/-8376) to a digest-pinned `python:3.14.0-alpine` base. All three time-windowed `.trivyignore` perl exceptions are removed — the scan is green with **zero** active exceptions.

### Changed
- **Base-image consolidation (Phase 229)**: the `security-scan` image was aligned from a drifted, unpinned `golang:1.25.10-alpine` to the single pinned `golang:1.26.4-alpine@sha256:…` used by every other Go image. `test_docker_consistency` now accepts a patch-pinned `python:3.14.0-{slim,alpine}` base.

### Added
- **Makefile integrity guard (Phase 224)**: `make lint-meta` now parses the Makefile and fails if any `make help*`-advertised target is missing, any prerequisite or `$(MAKE)` sub-call is unresolved, `.PHONY` lists a phantom, or a light umbrella (`lint`/`scan`/`test`) pulls in a heavy benchmark. Runs in `make test` via `tests/unit/test_makefile_integrity.py`.
- **Pre-push CI gate (Phase 224)**: shared `.githooks/pre-push` (install with `make install-hooks`) runs `make ci-verify` so Makefile/CI breakage is caught before push, not on GitHub Actions.
- **`bench-all` / `verify-all` (Phase 224)**: one-command heavy-benchmark trigger and a full release gate; `make lint scan test` is documented as the full gate minus heavy benchmarks.
- **`make scan-exceptions` (Phase 226)**: lists `.trivyignore` exceptions with days-to-expiry and justification; fails on expired or undated entries. Documented in `docs/runbooks/security_scan_exceptions.md`.

### Security
- **Honest, green security scan (Phase 226)**: the `make scan` gates were de-suppressed (`scan-container` was a no-op; `scan-images`/`scan-first-party` reported CRITICALs but never failed). Real image CVEs are now patched at build time via `apt-get`/`apk upgrade` (e.g. openssl CVE-2026-31789); grafana bumped 13.0.1→13.0.2 to clear bundled-pgx CVE-2026-33816; mockbackend runs non-root. The 23-CVE blanket `.trivyignore` was replaced with 3 justified, **14-day time-windowed** exceptions for genuinely no-fix perl CVEs (retired by Phase 229).

### Fixed
- **CI green end-to-end (Phase 226)**: fixed a hardcoded `GOROOT=/snap/go/current` that broke `make test`/`make lint` in CI; de-hardcoded a `JA4proxy2` dev path in two integration tests; added `pip-audit` to the CI lint job; created the mock-backend cert + `.env` in the scan job.
- **Makefile newline corruption (Phase 224)**: a prior "deduplicate" pass had written literal `\n` into 21 lines, silently commenting out the `scan`, `scan-all`, `scan-container`, `scan-local`, `check-updates-container`, and `check-updates-local` targets — so `make scan` did nothing while reporting success. All restored.
- **Broken `make lint` (Phase 224)**: created the missing `doc-health`, `lint-semgrep`, `lint-ansible`, `lint-docs`, `link-check`, `lint-phases` targets; `make lint` now resolves end to end.
- **Bare `python` in recipes (Phase 224)**: 9 recipes called `python` (absent on python3-only hosts); switched to `$(PYTHON)`.

## [2.0.0] - 2026-06-04

### Added
- **High-Performance Go Core**: Complete rewrite of the proxy logic in Go, achieving sub-microsecond latency.
- **Advanced CLI (ja4p)**: New operational subcommands:
    - `ja4p config validate`: Validates proxy configuration and security feeds.
    - `ja4p test ip`: Simulates pipeline decisions for specific IP addresses.
- **Zero-Copy Parsing**: Optimized TLS ClientHello and SNI extraction using zero-copy memory patterns.
- **Mesh Drift Detection**: Asynchronous decision auditing across proxy instances via Redis.
- **MITRE ATT&CK Mapping**: Formal mapping of JA4proxy signals to adversary techniques in `docs/OPERATIONS_MAPPING.md`.
- **OpenSSF Scorecard**: Integrated automated security auditing (Achieved 10/10 score).
- **SLSA Level 3**: Build provenance and supply chain hardening.
- **Prometheus Instrumentation**: Per-signal latency histograms for deep observability.
- **Maturity Badges**: Codecov, Go Reference, and Release status badges.

### Changed
- **Production Standard**: Go implementation is now the primary production runtime.
- **Repository Pruning**: Removed 150,000+ lines of legacy Python code and obsolete documentation.
- **Documentation Consolidation**: Centralized operational procedures into `docs/OPERATIONS_GUIDE.md`.
- **Helm Chart v2**: Relocated and upgraded Helm charts for Kubernetes-native scaling.

### Removed
- **Legacy Python Proxy**: Python proxy prototype archived to `legacy-v1` branch.
- **Obsolete Docs**: Hundreds of historical research and dev-heavy documents pruned for clarity.

## [1.x.x] - Historical
- Legacy Python prototype implementation (see `legacy-v1` branch for details).
