<!--
title: "TDD and Testing — Team Discipline"
audience: developers
last_reviewed: 2026-04-25
phase: 105
-->

# TDD and Testing

This page is the **human-facing summary** of the TDD discipline used on the
project. The canonical, exhaustive reference is
[`../TESTING_STRATEGY.md`](../TESTING_STRATEGY.md) — read it before writing a
non-trivial test. This page is intentionally short; do not duplicate the
methodology document.

> **Production runtime is the Go proxy.** Tests in `tests/` cover the Python
> prototyping surface; tests under `internal/...` (Go test files) cover the
> production runtime. A new signal generally lands in both.

---

## The loop

The team practises **red → green → refactor**:

1. **Red.** Write the failing test first. The test must fail for the right
   reason (the behaviour is missing), not because of a typo or a missing
   import. Run it once and read the failure.
2. **Green.** Make the smallest change that turns the test green. Resist the
   urge to write the elegant version first — get to green, then refactor.
3. **Refactor.** With the test holding behaviour stable, clean up. Extract
   helpers, rename, dedupe. Re-run the suite after every refactor step.

Every change to production code lands with a corresponding test change. A PR
that adds code but no tests is rejected on review.

### When fixing a bug

Reproduce the bug as a failing test **before** touching the buggy code. The
test becomes the regression guard. If you cannot reproduce the bug as a
test, you do not yet understand the bug — investigate further.

---

## Test-to-code ratio

The project maintains approximately a **1.3× test-to-code ratio** (test
LOC / source LOC). Check the current ratio with:

```bash
make test-ratio
```

A new feature that drops the ratio below 1.3× without justification is a
review blocker. The ratio is a heuristic, not a hard gate, but the trend
must not drift downward. If your change adds a lot of mechanical code (e.g.
generated stubs, large lookup tables), note it in the PR so reviewers can
calibrate.

---

## Test-category matrix

Every change should answer **which categories apply**. The matrix below is
the human-facing summary; the canonical definitions are in
[`../TESTING_STRATEGY.md`](../TESTING_STRATEGY.md) §1 Test Categories.

| Category | Directory | When to write |
|----------|-----------|---------------|
| Unit | `tests/unit/` | Every public function and every branch in security logic. Threshold tests cover at, above, below the boundary. **No Redis, no network.** |
| Integration | `tests/integration/` | Whenever the change touches Redis, the pipeline orchestration, pub/sub, or hot reload. Uses a real (test) Redis. |
| Chaos / Resilience | `tests/chaos/` | Every documented failure mode (Redis unreachable, external API timeout, malformed pub/sub message) needs a chaos test that asserts fail-open behaviour. |
| Adversarial / Fuzz | `tests/adversarial/` | New parsers, new signal extraction, anything that consumes attacker-controlled bytes. Includes the "always fail open on garbage input" assertion. |
| FP corpus | `tests/fp_corpus/` | **Required for every new blocking signal.** Test against the Tranco top-10k browser fingerprints; the new signal must not block any of them. |
| Performance | `tests/performance/` | Hot-path changes; assert no regression beyond the threshold defined per benchmark. |
| E2E | `tests/integration/test_docker_stack.py` and `scripts/smoke/` | Feature changes that touch the deployed shape — Compose lifecycle, health endpoints, Management UI flows. |

If a category does not apply, say so in the PR description ("Pure docs
change, no code paths affected — categories N/A"). Never silently skip.

---

## Mocks: external services are always mocked

Unit tests **must not** reach any external process. No real Redis, no real
HTTP calls, no real cloud SDK, no real DNS. The full reasoning is in
[`../../AGENTS.md`](../../AGENTS.md) §Unit tests must mock every external
service; the operational rule is:

- All external services have mock servers / fakes under `tests/mocks/`. Use
  them. Patch at the import site, e.g.
  `patch("src.security.abuseipdb.aiohttp.ClientSession", ...)`.
- `os.access` mocks match by **bitmask**, not equality:
  `if mode & os.W_OK: return False`. The single-equality form silently
  passes when production uses `os.R_OK | os.W_OK | os.X_OK`.
- `pathlib.Path.mkdir` is patched whenever you also patch `os.stat` — on
  Python 3.14 `mkdir(exist_ok=True)` calls `os.stat` internally.
- Verify each new test passes with **no dev services running** (stop your
  local Redis, disconnect from the network). A test that only passes when
  Redis happens to be on `localhost:6379` will fail in CI.

A real-API call from a unit test is a phase blocker. The phase-completion
gate scans for known-bad patterns and flags them.

---

## Web service phases — two extra mandatory test files

Web service changes require **two** additional test files, learned from
incidents on Phases 13/51/52:

- `test_pages.py` — for every HTML route: GET with auth → 200, HTML
  content-type, landmark string in body. GET without auth → status < 500.
  A 500 means the route crashed before auth ran, which an auth-only
  redirect test would miss.
- `test_container_config.py` — parses the relevant compose file and asserts
  env sections pass connection strings (especially passwords) correctly.
  In-memory fakes do not need passwords; real containers do, and that gap
  is invisible to unit tests.

The patterns and rationale are in
[`../../AGENTS.md`](../../AGENTS.md) §Web service TDD — two mandatory test
categories.

---

## Phase-gate-must-pass

A phase is not COMPLETE until **every section of `make test`** is green:

```
✓ mypy: OK
✓ bandit: OK
✓ ruff: OK
✓ pip-audit: OK
... 2700+ passed, N skipped (all approved), 0 failed
```

`make test` runs four static-analysis tools **before** pytest. Any `✗` or
`[!]` is a blocking failure. Skipping a category, even with a `# pragma`,
requires an entry in `docs/security/EXCEPTIONS.md` and an explicit user
approval; see [`../../AGENTS.md`](../../AGENTS.md) §Approved Exception
Workflow.

The `/close-phase` slash command runs the full gate. Do not close a phase
manually; see [`PHASE_LIFECYCLE.md`](PHASE_LIFECYCLE.md) for the close-out
flow.

---

## Cross-language parity

Whenever a signal lands in both Python and Go, three permanent tools enforce
parity:

- `config/signal_scores.yml` — single source of truth for every signal score.
  `make check-scores` must exit 0.
- `tests/fixtures/clienthello/*.bin` — ground-truth ClientHello bytes for
  JA4 fingerprint computation; both languages assert
  `parse(fixture) == expected_ja4`.
- `make parity-check` — sends synthetic traffic through both proxies and
  compares `(action, score)` pairs.

A phase that touches scoring or pipeline logic includes
`make parity-check` in its close-out. See [`../../AGENTS.md`](../../AGENTS.md)
§Go/Python Proxy Parity for the full procedure.

---

## Cross-references

- Canonical methodology: [`../TESTING_STRATEGY.md`](../TESTING_STRATEGY.md)
- File layout, conftest, fixtures, parametrize:
  [`../TEST_ORGANIZATION.md`](../TEST_ORGANIZATION.md)
- Mock rules and dev-vs-CI divergence guidance:
  [`../../AGENTS.md`](../../AGENTS.md)
- CI gate that runs the full suite:
  [`CI_AND_QUALITY_GATES.md`](CI_AND_QUALITY_GATES.md)
- Branch and PR rules: [`HOW_WE_WORK.md`](HOW_WE_WORK.md)
