# Contributing to JA4proxy

## Prerequisites

- Python 3.11 (required; tested against 3.11.x)
- Docker and Docker Compose v2
- Redis Stack (for local development without Docker: `docker run -p 6379:6379 redis/redis-stack-server:latest`)
- Node.js 18+ (for Management UI frontend work only)

## Day 1: Get Up and Running

```bash
# Clone the repository
git clone <repo-url>
cd JA4proxy

# Install Python dependencies
pip install -r requirements.txt

# Install dev/test dependencies
pip install -r requirements-dev.txt

# Run the test suite (should pass with 2251 tests, 0 failures)
make test
# Or directly:
python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py
```

If `make test` passes, your environment is correctly configured.

The Docker integration tests (`tests/integration/test_docker_stack.py`) require the
full stack to be running:

```bash
make start          # Starts all containers
make test-docker    # Runs Docker integration tests only
make stop           # Stops containers
```

## Read First

Before writing any code:

1. **`CLAUDE.md`** — architecture overview, phase index, cross-cutting requirements,
   and the core asymmetry principle (the most important thing to understand).
2. **`docs/phases/PHASE_XX.md`** for the phase you are working on — acceptance criteria,
   API design, Redis schema additions, and test requirements.
3. **`docs/STYLE_GUIDE.md`** — config syntax, log format, test format, documentation
   language.

## Project Structure

```
proxy.py                        # Proxy entry point (hot path, connection handler)
src/
  security/
    pipeline.py                 # Pipeline orchestration (all signals → scorer)
    risk_scorer.py              # Phase 1: signal aggregation
    action_decider.py           # Phase 2: dial → action
    tls_enforcer.py             # Phase 3: TLS version/cipher
    sni_analyzer.py             # Phase 4: SNI analysis
    tcp_analyzer.py             # Phase 5: TCP behaviour + mTLS
    mtls.py                     # Phase 5: mTLS bypass
    asn_classifier.py           # Phase 6: ASN/datacenter/GeoIP
    dns_enrichment.py           # Phase 7: FCrDNS enrichment
    blocklists.py               # Phase 8: Spamhaus DROP/EDROP
    beaconing_detector.py       # Phase 9: IAT coefficient of variation
    abuseipdb.py                # Phase 10: AbuseIPDB lookup
    rdap_enrichment.py          # Phase 11: RDAP + block expansion
  cache/
    local_cache.py              # In-process LRU cache (Phase 0)
  config/
    loader.py                   # Hot-reload config loader (Phase 0)
analytics/                      # Phase 12: analytics node (separate container)
# management/                   # Phase 13 deferred; re-implemented after Phase 15
config/
  proxy.yml                     # Main configuration file
  asn_datacenter_list.yml       # Phase 6: datacenter ASN list
  known_bad_orgs.yml            # Phase 11: known-bad org list
tests/
  unit/                         # Per-module unit tests
  integration/                  # Pipeline + Redis integration tests
  chaos/                        # Failure scenario tests
  adversarial/                  # Fuzz and adversarial input tests
  performance/                  # Throughput and latency benchmarks
  mocks/                        # Mock servers for external APIs
docs/
  phases/                       # Per-phase plan files (PHASE_00.md – PHASE_24.md)
  runbooks/                     # Operational runbooks
  decisions/                    # Architecture Decision Records (ADR-*.md)
```

## Running Tests

### Run a single test file

```bash
python3 -m pytest tests/unit/test_risk_scorer.py -v
```

### Run a specific test

```bash
python3 -m pytest tests/unit/test_risk_scorer.py::TestRiskScorer::test_score_aggregation -v
```

### Run all tests (excluding Docker integration)

```bash
make test
# Or:
python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py
```

### Run with coverage

```bash
python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py --cov=src --cov-report=html
```

### Run a specific test category

```bash
python3 -m pytest tests/unit/ -v
python3 -m pytest tests/integration/ --ignore=tests/integration/test_docker_stack.py -v
python3 -m pytest tests/chaos/ -v
python3 -m pytest tests/adversarial/ -v
```

### Calibrate parallel workers for your machine

```bash
make test-calibrate
# Benchmarks your machine and stores optimal worker count in .local/machine.mk
```

## Code Style

- **Type hints on all public functions and class attributes.** No untyped public APIs.
- **Docstrings on all public classes and non-trivial functions.**
- Follow existing patterns in `proxy.py` and `src/security/`. Read before writing.
- `# pragma: no cover` on: ImportError fallback blocks and `if __name__ == "__main__"` guards.
- No `time.sleep()` anywhere — use `asyncio.sleep()`.
- No blocking I/O on the hot path — all external calls via `asyncio.create_task()`.
- See `docs/STYLE_GUIDE.md` for log format, config syntax, and Prometheus naming.

## Test Requirements

Every new feature or change requires:

1. **Unit tests** covering the new logic (positive path, negative path, error path).
2. **Integration test** if the feature touches Redis or the pipeline.
3. **Chaos test** if the feature has a documented failure mode.
4. **FP corpus test** for any new blocking signal (test against Tranco top-10k domains).

See `docs/TEST_ORGANIZATION.md` for which file each test type goes in, and
`docs/TESTING_STRATEGY.md` for the full methodology.

The project maintains approximately a 1.3× test-to-code ratio. Adding new code without
tests is not acceptable.

**Empty test bodies are rejected at collection time.** A test with only `pass` or a
docstring will cause the test suite to exit with code 3.

## Config Changes

Every new feature must be toggleable in `config/proxy.yml` with a sensible default.
New config keys require inline YAML comments explaining purpose and valid values.
Defaults must be conservative (fail open, low false-positive rate).

## Commit Format

Follow the existing commit message style in `git log --oneline`:

```
feat: short description of what was added
fix: short description of what was fixed
docs: documentation changes
test: test additions or fixes
refactor: code restructuring without behaviour change
```

All commits require a Co-Authored-By line:

```
Co-Authored-By: Your Name <your@email.com>
```

## What Not to Do

- **Never skip pre-commit hooks** (`--no-verify`). If a hook fails, fix the underlying issue.
- **Never force-push to main.** Use pull requests.
- **Never commit secrets** (API keys, passwords, certificates). Use environment variables
  or the Docker secrets mechanism described in Phase 14.
- **Never call real external APIs in tests.** All external services have mock servers
  in `tests/mocks/`. Use them.
- **Never block on the hot path.** If in doubt, use `asyncio.create_task()`.
- **Never hard-code Redis key patterns.** They are documented in `docs/REDIS_SCHEMA.md`
  and must match exactly.

## Completing a Phase

When a phase is done, run this checklist **in order** before starting the next one:

1. `make test` — zero failures, zero warnings.
2. Update `CHANGELOG.md` with a standard entry (format: `docs/DOCUMENTATION_STANDARDS.md`).
3. Update `docs/REDIS_SCHEMA.md` for any new Redis keys introduced.
4. Update `docs/phases/manifest.yaml` — set `status: COMPLETE`, remove gaps that were resolved.
5. Run `python3 scripts/sync-roadmap.py` — regenerates `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md`.
6. Commit everything together: code, `CHANGELOG.md`, `manifest.yaml`, `TODO.md`, `PROJECT_STATUS.md`.

> `manifest.yaml` is the single source of truth for phase status. Skipping step 4–5 leaves
> `TODO.md` and `PROJECT_STATUS.md` showing stale state, and breaks the next contributor's
> understanding of what work remains.

## Updating Documentation

When adding a new feature (outside of a phase close-out):

- Update `CHANGELOG.md` (format in `docs/DOCUMENTATION_STANDARDS.md`).
- Update `docs/REDIS_SCHEMA.md` if new Redis keys are introduced.
- Update the relevant runbook in `docs/runbooks/` if the feature has operational
  implications.
- Write an ADR in `docs/decisions/ADR-NNN.md` for non-obvious architectural decisions.

## Getting Help

- Architecture questions: read `CLAUDE.md` in full. Most design decisions are documented
  in the Decision Log at the bottom.
- Phase-specific questions: read `docs/phases/PHASE_XX.md` for the phase in question.
- Operational questions: check `docs/runbooks/`.
- Unclear acceptance criteria: check the phase doc's acceptance criteria section first.
