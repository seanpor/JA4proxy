<!--
title: JA4proxy — Makefile Targets
audience: reference
last_reviewed: 2026-06-04
phase: v2.0
-->

# Makefile Targets Reference

> **Audience:** Developer, Operator  
> **Last reviewed:** 2026-05-30

Every target in the JA4proxy Makefile, with description, arguments, and prerequisites.

---

## Quick-Start

```bash
make help               # Show top-level help (lists all sub-helps)
make lint-help          # Linting targets
make scan-help          # Container scanning targets
make legacy-help        # Python legacy proxy targets
make dev-help           # Build, test, proxy, bench, docs, agents
```

---

## Dev Lanes & Load Test (phase-310)

Each git worktree auto-gets a collision-free **lane** (its own host ports +
`COMPOSE_PROJECT_NAME` + docker network), so multiple checkouts run on one host
without clashing. `make start-poc` allocates the lane automatically.

| Target | Description | Knobs |
|--------|-------------|-------|
| `lane` | Show this worktree's lane: host ports + Grafana/Management URLs | — |
| `open` | Open a lane service in the browser | `SVC=grafana\|management\|metrics\|prometheus` |
| `loadtest` | Bring up the lane stack + drive a good/bad traffic mix to watch in Grafana (default **5% good / 95% bad**: `GOOD_RATE=10 BAD_RATE=190`) | `GOOD_RATE`, `BAD_RATE`, `DURATION`, `WORKERS`, `DIAL` |

The default lane runs **without HAProxy** (single proxy, reached directly on
`HOST_PORT_DIRECT`); set `WITH_HAPROXY=1` for the multi-proxy LB test.

---

<!-- BEGIN GENERATED: make-targets -->

_193 targets. Generated from the Makefile's own `##` help comments by `make sync` — do not edit this table by hand._

### Aggregate linters

| Target | Description |
|--------|-------------|
| `bench-all` | Run every heavy benchmark (perf, load, go-perf, MTTR) — slow, runs alone |
| `bench-hostnative` | End-to-end throughput, ja4pd host-native (no docker-proxy; ~4.5x the bridge port) |
| `bump-build` | Show build number (derived from git commit count — no file needed) |
| `changelog-assemble` | Fold docs/fragments/*.md into CHANGELOG.md (run at release, not per-phase) |
| `ci-verify` | Fast CI mirror: the deterministic checks GitHub Actions gates on (no Docker/network) |
| `cli-build` | Build the unified ja4p CLI tool |
| `doc-health` | Validate documentation frontmatter |
| `go-build` | Build the Go proxy daemon into bin/ja4pd |
| `go-build-foss` | Build royalty-free Go proxy daemon into bin/ja4pd-foss (-tags no_ja4plus) |
| `init` | Start the guided setup wizard |
| `install-hooks` | Install shared git hooks (pre-push runs `make ci-verify`) |
| `ja4p-validate` | Validate proxy configuration YAML |
| `lane` | Show this worktree's dev lane (collision-free host ports + Grafana URL) |
| `link-check` | Alias for the internal-link checker (test-doc-links) |
| `lint-all` | Run every linter in one shot |
| `lint-ansible` | Lint the Ansible playbooks/roles under deploy/ansible (containerised; advisory) |
| `lint-docs` | Core documentation quality checks |
| `lint-docs-all` | Run all documentation quality checks |
| `lint-go` | Run all Go linters (fmt, vet, golangci-lint, mod verify) |
| `lint-infra` | Run all infrastructure linters |
| `lint-observability` | Run observability linters (promtool, amtool) |
| `lint-phases` | Validate phase docs (frontmatter, numbering, manifest sync) |
| `lint-python` | Run all Python linters (ruff, mypy, bandit, pylint) |
| `lint-sast` | Run cross-language SAST (Semgrep, Checkov) |
| `lint-semgrep` | Run Semgrep SAST using the project ruleset (containerised) |
| `lint-supply-chain` | Run supply-chain linters (Gitleaks, govulncheck) |
| `loadtest` | Lane-isolated good/bad load test -> watch Grafana (knobs: GOOD_RATE BAD_RATE DURATION WORKERS DIAL) |
| `management-down` | Stop the management UI for the current agent |
| `management-logs` | Tail the management UI logs for the current agent |
| `management-shell` | Open a shell in the management UI container for the current agent |
| `management-up` | Start the management UI for the current agent |
| `open` | Open a lane service: make open SVC=grafana|management|metrics|prometheus |
| `scan-js` | Scan the vendored Management-UI JS for known CVEs (retire.js) |
| `setup-build` | Build the ja4p CLI the setup wizard needs |
| `start-poc` | Alias for starting the POC environment |
| `sync` | Sync roadmap from manifest.yaml and generated reference docs |
| `test-component-suites` | Run every component test suite (unit, chaos, adversarial) |
| `test-lint-hierarchy` | Run Phase 92 lint hierarchy structural tests |
| `test-ratio` | Show the test-to-code ratio |
| `tunnel` | Print the SSH local-forward command for an agent stack (NAME=, HOST=) |
| `verify-all` | Full release gate: lint + scan + test + bench-all — slow |

### Benchmarking

| Target | Description |
|--------|-------------|
| `bench` | Run all benchmarks (micro + macro) |
| `bench-macro` | Run end-to-end load test (requires: make start) |
| `bench-micro` | Run Go native micro-benchmarks |
| `ci-local` | Run the same fast checks the CI workflow runs (Go + Python tests) |
| `findings-list` | List open findings (add FINDINGS_ARGS=... to pass flags, e.g. --severity HIGH) |
| `findings-render` | Regenerate docs/security/FINDINGS_REGISTER.md from findings.yaml |
| `lint-alert-urls` | Verify Alertmanager runbook_url values are up to date |
| `lint-meta` | Phase 147 — Verify Makefile and automation script health |
| `load-test` | Run JA4proxy load test |
| `load-test-baseline` | Run baseline load test (localhost:8080, 60s, 1000 rps) |
| `load-test-report` | Show latest load test reports |
| `measure-mttr` | Measure MTTR for DR scenarios |
| `perf-test-basic` | Run basic performance test against a local proxy |
| `quality` | Run all linters + coverage checks in one shot |
| `quick-start` | Start the proxy with default config (builds if needed) |
| `reload` | Reload proxy configuration without restart (SIGHUP) |
| `sbom` | Generate CycloneDX SBOM for Go proxy binary |
| `slo-report` | Show SLO report from live Prometheus |
| `smoke-docker` | Run Docker Compose smoke test |
| `smoke-k8s` | Run Helm + kind smoke test |
| `test-attack-mapping` | Phase 107f.4 — fail if ATT&CK mapping rows lack confidence labels or cite missing source files |
| `test-compliance` | Phase 107h — all regulatory-conformance regression guards |
| `test-compliance-language` | Phase 107h.1 — fail if "certified"/"compliant" appears in self-assessed compliance docs |
| `test-doc-links` | Phase 107w.3 — lychee-check all docs for broken internal links (advisory; gated by docs-link-check.yml) |
| `test-evidence-paths` | Phase 107h.2 — fail if conformance docs cite repo paths that don't exist |
| `test-ip` | Alias for simulating IP decision |
| `test-slo` | SLO validation tests |
| `validate-slo-rules` | Validate SLO recording/alert rules (promtool or YAML) |
| `validation-report` | Generate validation report |
| `verify-findings` | Validate docs/security/findings.yaml schema and referential integrity |
| `verify-findings-green` | Run only the regression tests backing findings.yaml entries (fast signal) |
| `verify-manifest-closeout` | Manifest close-out gate — validate register, required docs, ADRs, manifest |

### Build

| Target | Description |
|--------|-------------|
| `bandit-image` | Build containerized bandit SAST image (Dockerfile.bandit) |
| `build` | Build all Docker images (Go compiled inside Docker — no local Go required) |
| `build-native` | Build host-native Go binaries (requires local Go 1.26+) |
| `check-image-versions` | Detect `:latest` tags and version drift across compose files |
| `check-manifest` | Verify manifest.yaml / TODO.md / CHANGELOG.md stay consistent |
| `clean` | Stop + remove all containers and volumes |
| `compose-validate` | Validate docker-compose files and required env vars (fast, no image build) |
| `deploy-enterprise` | Deploy enterprise environment (sudo) |
| `deploy-poc` | Deploy PoC environment |
| `env-sync` | Add any newly-required vars to an existing .env (idempotent, never overwrites) |
| `flush-redis` | Reset bans/blocks/rates (keeps whitelist/blacklist) |
| `health-check` | Run health checks against metrics + Redis |
| `lint` | Phase 146 — Run all linters (Python, Go, Infra, Docs) |
| `lint-alertmanager` | amtool check-config |
| `lint-coverage` | pytest-cov coverage reporting (≥80% gate) |
| `lint-deps` | pip-audit (Python) + govulncheck (Go) CVE scan |
| `lint-docker` | hadolint + `docker compose config --quiet` (all overlays) |
| `lint-go-full` | golangci-lint comprehensive |
| `lint-json` | JSON syntax validation |
| `lint-lua` | luacheck Redis Lua scripts |
| `lint-prom` | promtool check rules (alerts + recording) |
| `lint-quality` | flake8 code quality |
| `lint-secrets` | gitleaks scan of git history |
| `lint-security` | bandit SAST (medium/high severity) |
| `lint-shell` | shellcheck all `.sh` scripts (error-level) |
| `lint-static` | mypy + bandit + ruff + pip-audit |
| `lint-types` | Run mypy type checker on src/ |
| `lint-yaml` | yamllint `config/` and `monitoring/` |
| `logs` | Stream proxy container logs |
| `rebuild` | Wipe volumes/images, rebuild from scratch, start fresh |
| `scan-dockerfiles` | Trivy config scan of Dockerfiles + compose files (HIGH/CRITICAL → fail) |
| `scan-exceptions` | List Trivy scan exceptions (.trivyignore) with days-to-expiry |
| `scan-first-party` | Trivy CVE scan of built images (CRITICAL → fail) |
| `scan-images` | Trivy scan of third-party images (HIGH/CRITICAL; fails on CRITICAL) |
| `scan-summary` | Phase 228 — compact CRIT/HIGH/MED rollup of all scans (images + misconfig + gosec; reporting only) |
| `smoke-test` | Quick sanity check |
| `test` | Phase 146 — Run the full test suite |
| `test-adversarial` | Run adversarial/fuzz tests only |
| `test-calibrate` | Benchmark this machine, store worker count |
| `test-chaos` | Run chaos/resilience tests only |
| `test-docker` | Run tests inside Docker (CI env) |
| `test-unit` | Run unit tests only |
| `tools-image` | Build containerized tools image (Dockerfile.tools) |

### Configuration

| Target | Description |
|--------|-------------|
| `dial` | Set blocking dial 0-100 (LEVEL=...) |

### Dev sub-help

| Target | Description |
|--------|-------------|
| `help-dev` | Show developer commands sub-help |

### Docker test harness

| Target | Description |
|--------|-------------|
| `capture-fixtures` | Generate ClientHello `.bin` fixtures (curl + openssl) |
| `go-build-ja4check` | Build `bin/ja4check` utility |
| `test-go` | Build + test all Go (build binaries, generate fixtures, run suite) |
| `test-go-chaos` | Go chaos tests locally |
| `test-go-docker` | Go integration tests inside Docker (self-contained) |
| `test-go-integration` | Go integration tests locally |
| `test-go-perf` | Go performance benchmarks |
| `test-go-redis-tls` | Go Redis TLS smoke test |

### Environment Configuration

| Target | Description |
|--------|-------------|
| `doctor` | Phase 147/225 — Verify environment and toolchain health |

### GeoIP monitoring

| Target | Description |
|--------|-------------|
| `check-geoip` | Check age of current GeoIP database |
| `geoip-monitor` | Auto-block attacking countries (run once) |
| `geoip-report` | Full blocking report |
| `geoip-watch` | Auto-block attacking countries (continuous loop) |
| `update-geoip` | Download latest IP2Location LITE DB (monthly) |

### Incident response shortcuts (wrappers for scripts/ja4-admin.sh)

| Target | Description |
|--------|-------------|
| `attack-status` | Quick security snapshot |
| `block-ip` | Hard-block an IP address for 1 hour (IP=...) |
| `block-ja4` | Blacklist a JA4 fingerprint (FP=...) |
| `perf-test` | Run performance tests with Locust |
| `poc-secrets` | Generate any missing deploy/secrets/*.txt the PoC stack needs |
| `top-attackers` | Top 10 fingerprints by traffic |
| `unblock-ip` | Remove blocks/bans for an IP (IP=...) |

### Individual linters (Phase 92 additions)

| Target | Description |
|--------|-------------|
| `lint-checkov` | Run Checkov IaC security scan (containerised; advisory) |
| `lint-go-mod` | Verify go.mod and go.sum are consistent (go mod verify) |
| `lint-haproxy` | Validate HAProxy configuration syntax (advisory) |
| `lint-helm` | Run helm lint on Helm charts (advisory) |
| `lint-makefiles` | Lint Makefile for common issues (checkmake) |
| `lint-markdown` | Lint Markdown files for formatting issues (advisory) |
| `lint-pylint` | Run pylint errors-only on Python source (advisory) |
| `lint-spelling` | Spell-check documentation (advisory) |
| `lint-toml` | Validate TOML files (pyproject.toml, .gitleaks.toml) using tomllib |

### Legacy (Python) sub-help

| Target | Description |
|--------|-------------|
| `help-legacy` | Show legacy Python proxy sub-help |

### Master help

| Target | Description |
|--------|-------------|
| `help` | Show the essential front-door targets |
| `help-lint` | Show linting commands help |
| `help-ops` | Incident response and threat intelligence help |

### Multi-Agent

| Target | Description |
|--------|-------------|
| `agent-down` | Stop an isolated agent environment (NAME=<agent>) |
| `agent-status` | List all running agent environments |
| `agent-up` | Start an isolated agent environment (NAME=<agent>) |

### Operations

| Target | Description |
|--------|-------------|
| `ssh-tunnels` | Print SSH tunnel command for default stack |

### Phase 245: First-class admin CLI + minimal init

| Target | Description |
|--------|-------------|
| `admin` | Run the ja4-admin incident response CLI (pass ARGS for commands) |
| `init-minimal` | Emergency init: prompt for BACKEND_HOST, generate .env, done |

### Phase 332: pre-PR gate

| Target | Description |
|--------|-------------|
| `check` | Fast gate: compile + env validate + tests (~3 min, no image builds or CVE scans) |
| `preflight` | Full local gate before opening a PR: lint + scan + test (~25 min) |
| `tap-build` | Build standalone TAP sensor binary |

### Phase 511: Emergency traffic insertion / rollback

| Target | Description |
|--------|-------------|
| `traffic-off` | Remove JA4proxy from the traffic path (instant rollback; needs sudo) |
| `traffic-on` | Insert JA4proxy into the traffic path (iptables redirect :443→:8443; needs sudo) |

### Phase 814a: penetration-testing range

| Target | Description |
|--------|-------------|
| `pentest-range` | Bring up the isolated pentest range (zero egress, verified) and print provenance |
| `pentest-range-down` | Tear down the pentest range (evidence is kept) |
| `pentest-range-verify` | Re-run the range isolation assertions without rebuilding |
| `pentest-shell` | Open a shell on the attacker workstation inside the range |
| `test-journeys` | Phase 824 — run customer-journey checks against a live stack |

### Proxy Operations

| Target | Description |
|--------|-------------|
| `check-scores` | Audit Python and Go signal scores against registry |
| `go-lint` | Run `go vet` on Go code |
| `go-test` | Run all Go unit tests |
| `test-race` | Run Go unit tests under the race detector |

### Remote Manual Testing (Phase 220)

| Target | Description |
|--------|-------------|
| `remote-bot` | Run test bot against remote proxy (HOST=... PORT=...) |

### Scan sub-help

| Target | Description |
|--------|-------------|
| `help-scan` | Show security scanning commands help |

### Security Scans

| Target | Description |
|--------|-------------|
| `check-updates` | Check Python/Go/Docker dependency versions |
| `check-updates-container` | Run dependency update checker in container |
| `check-updates-local` | Run dependency update checker locally |
| `scan` | Phase 146 — Run all security and container scans |
| `scan-all` | Run all security scans (container, dockerfiles, 1st-party, images) |
| `scan-container` | Run Go SAST (gosec) in a container — gates on high-severity/high-confidence findings |
| `scan-local` | Run gosec Go SAST scanner locally |
| `scorecard-local` | OpenSSF Scorecard (local, advisory — the gate is scorecard.yml) |

### Startup / Shutdown

| Target | Description |
|--------|-------------|
| `start` | Start full stack (POC + Prometheus/Grafana) |
| `start-monitoring` | Start monitoring stack only |
| `start-scaled` | Start 4-worker scaled config with HAProxy |
| `status` | Show health of all services + security state |
| `stop` | Stop all services (keep Redis data) |
| `stop-clean` | Stop all + wipe volumes (fresh slate) |

### ja4db feed management

| Target | Description |
|--------|-------------|
| `approve-all` | Approve all pending fingerprints |
| `fetch-db` | Fetch new malicious fingerprints from ja4db/FoxIO |
| `list-pending` | Show fingerprints awaiting admin approval |

### phase-826: demo support

| Target | Description |
|--------|-------------|
| `demo-bot` | Send test non-browser TLS connection for demo |
| `demo-check` | Pre-flight health check for demo environment |

<!-- END GENERATED: make-targets -->

---

## ARGS Variable

Many `test-*` targets accept an `ARGS=` variable that is passed directly to the underlying pytest or benchmark script:

```bash
make test ARGS='-k test_ja4_parity -v'
make bench ARGS='--scenarios peak_throughput --duration-long 60'
```

---

## NAME Variable Convention

The `NAME=` variable is used for multi-agent operations and is normalised from `Name=` or `name=`:
- `make agent-up NAME=claude` — start agent
- `make agent-down NAME=claude` — stop agent
- `make tunnel NAME=claude HOST=user@server` — SSH tunnels

After `agent-up`, many targets read `.current-agent` automatically:
`stop`, `stop-clean`, `status`, `logs`, `health-check`, `flush-redis`, `clean`, `rebuild`, `management-up/down/logs/shell`.
