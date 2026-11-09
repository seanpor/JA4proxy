# Phase 868 — Go Proxy Deep Code Review (systematic bug-class sweep)

## Goal

Find bug classes in the **internet-exposed Go proxy** that previous review phases
were not looking for.

Phases 500 (static invariant sweep), 501 (concurrency), 814 (resource-exhaustion
code audit + fuzz seed corpus), 839 (parser fuzz + crypto config) and 860
(protocol-correctness pentest) each applied **one lens**, and each found real
findings — 500 produced 43, 501 produced 42, 814 produced 20. That record is
evidence the lenses work; it is not evidence the surface is clean. What no phase
has done is a **structured reading of every parser and state machine on the wire
path**, with an explicit register of *what we believe to be true* rather than
only *what we have proven*. Prior phases proved narrow properties ("the body is
capped at N bytes"); they did not audit the **beliefs those proofs rest on** —
for example that a truncated ClientHello can never reach the JA4 fingerprint
path at all, or that a count read from the wire is never used to size anything.

This phase audits beliefs, not just bounds. Deliverable is a **belief ledger**:
for every untrusted-input handling site, the property we assume, and whether
that property is enforced in code or merely assumed.

## Scope

**In scope** — `cmd/ja4pd/` (entry, config, cert material) and `internal/**`,
**excluding** `internal/tests/` (test harnesses). This is the production
internet-facing process:

```
cmd/ja4pd/            271  entrypoint, cert material, config load, signals
internal/proxy/      4343  ClientHello reassembly, ALPN/JA4, HTTP parsing, dialing
internal/middleware/ 2088  access log, TLS inspector, cert/key validation
internal/auth/       1559  auth + Redis backend
internal/ratelimit/    916  token buckets
internal/trace/        516  trace context
internal/metrics/      496  Prometheus
internal/tlsutils/     369  TLS record / ClientHello parsing helpers
```

**Out of scope** — `management/` and `src/` (Python UI/API/analytics: not this
binary, and covered by their own test TDD rules); `internal/tests/`; config
**governance** (Phase 865, still `IN_PROGRESS`); the scanner-surface work and
scan-surface registration (Phase 866, `IN_PROGRESS`); performance/latency tuning
(Phase 867, `IN_PROGRESS`).

### Bug classes to hunt (each becomes a work package)

1. **Truncated-input belief inversion** — error paths that discard a *complete*
   observation and keep an *incomplete* one.
2. **Parser integer/boundary bugs** — length fields used as allocation sizes or
   loop bounds; off-by-one on record and handshake boundaries.
3. **JA4/TLS fingerprint correctness** — buckets that silently collapse distinct
   inputs into one fingerprint (`SNI`/`ALPN` bucket semantics).
4. **Deadline and context-propagation gaps** — the deadline ladder, with special
   attention to `context.Background()` on request-bound paths (the one pattern
   Phase 501 could not see, because it looked only at `context.Background()` in
   *init* paths).
5. **Lifecycle state machines** — startup, config reload, shutdown, and
   accept-in-flight-then-drain ordering.
6. **HTTP/2 + HPACK + CONNECT tunnel correctness** — flow control, stream
   limits, header-table sizing, the CONNECT path.
7. **Static-invariant re-derivation** — Phase 500's grep gates re-run against
   today's code, with per-invariant evidence captured.

## Implementation plan — work packages

Each is independently committable and has a precise, testable gate. **No package
may be reported PASS without its gate's command output recorded** in
`docs/security/pentest/verify/`.

### WP-1 — Surface map + belief ledger (`verify/belief-ledger.md`)

Inventory every untrusted-input entry point and annotate what we assume about it.

- **G-1.1** A markdown table exists with ≥1 row per `ATTACK_SURFACE.md` surface
  whose `Owner file` is Go, with columns: surface, entry function, untrusted
  fields, property assumed, **enforced-by / assumed-only**.
- **G-1.2** Every `assumed-only` cell gets a decision: `PROVE` (WP-2..WP-9
  settles it) or `ASSUME-ACCEPT` (with a one-line reason).
- **G-1.3** Row count ≥ the count of Go-owned surfaces in `ATTACK_SURFACE.md`
  (currently 32, of 48 total). Verified by counting, not by eye.

### WP-2 — Parser boundary hunt (`internal/tlsutils`, proxy ALPN + reassembly)

Line-by-line read of every length field against its consumer.

- **G-2.1** Every integer read from a wire buffer is listed with the expression
  that consumes it; each is bounded or explicitly justified.
- **G-2.2** New table-driven boundary tests exist for each of: 1-byte record,
  empty extension, extension length > remainder, 0-length ALPN entry,
  0-entry ALPN list, ALPN list spanning a record boundary, 255-entry protocol
  list, 65535-byte SNI.
- **G-2.3** `go test -fuzz` over the seed corpus reaches
  `internal/fuzzing/corpus/tls_clienthello/` and runs ≥60s with no new crasher.

### WP-3 — TLS/JA4 correctness: the "X" bucket question (highest value)

Determine whether malformed ClientHellos collapse into one bucket, and whether
the ALPN/JA4 code path is reachable *by the same input that reaches the proxy
decision*.

- **G-3.1** A test asserts the JA4 string for each of: no-SNI, SNI-only,
  ALPN-only, both, both-malformed — and that at least the documented distinct
  cases produce distinct strings.
- **G-3.2** Evidence, one way or the other, that a ClientHello failing
  `ValidateClientHello` **cannot** affect a proxy routing/ACL decision. If the
  claim is false, a finding is filed.

### WP-4 — Deadline ladder

- **G-4.1** `grep -rn "context.Background\|context.TODO" cmd internal --include=*.go | grep -v _test | grep -v internal/tests`
  exits with every hit classified `INIT` (acceptable) or `REQUEST` (must carry a
  parent ctx). Zero unclassified.
- **G-4.2** A table lists every client-facing wait (hello wait, auth Redis call,
  dial, tunnel copy) against its timeout source; none has an unbounded wait.
- **G-4.3** A test proves an attacker that holds a connection open without
  sending can be dropped by a finite timer.

### WP-5 — Shutdown / reload / lifecycle ordering

- **G-5.1** A test proves a config reload cannot leak goroutines or file
  descriptors (count before/after N reloads, bounded).
- **G-5.2** A test proves in-flight tunnels are drained (or explicitly refused)
  on shutdown, with a recorded bounded time.
- **G-5.3** Signal handling path reviewed against WP-4's table; recorded in the ledger.

### WP-6 — Static-invariant re-derivation (runs first — cheapest gate)

Re-run Phase 500's gates; do **not** re-triage its 50 findings.

- **G-6.1** For each of these, **one command** and its output: body limit
  present; no unbounded read of a client stream; `crypto/tls` config sanity
  (min version, no `InsecureSkipVerify`, no `Renegotiation` override); HTTP
  response body limits; permission check before read; every `select/default`
  drop has a metric counter; no duplicate YAML keys in compose.
- **G-6.2** Each gate's output is saved as a file under `verify/`; the file, not
  the claim, is the proof.
- **G-6.3** Deliberately skipped (recorded, not silently omitted): the
  `thread`/`goroutine`/`go func` greps — Phase 501 recorded 144 findings for 2
  useful.

### WP-7 — State machines & protocol handling

Per-connection state: `pre-hello → hello-parsed → authed → tunneling`.

- **G-7.1** A written state table: every transition, its guard, and its
  timeout; every input that can arrive in each state.
- **G-7.2** A test for each illegitimate transition (e.g. authed without hello,
  tunnel before auth, second hello on one connection).
- **G-7.3** Connection-reuse / keep-alive accounting: a test proving
  `ActiveConnections` cannot drift under an error storm.

### WP-8 — HTTP/2, HPACK, CONNECT tunnel

- **G-8.1** HPACK dynamic-table size and per-stream header size are bounded,
  with a test that a peer declaring a huge table cannot allocate it.
- **G-8.2** CONNECT path: audit of request/target parsing, auth ordering vs.
  dial, and post-2xx raw byte copying; test for each gap found.
- **G-8.3** Per-stream flow-control accounting cannot go negative (test).

### WP-9 — Crypto material, keys, config reload

- **G-9.1** Permission checks precede `os.ReadFile` on key material (Phase 500
  pattern re-checked at every site, sites listed).
- **G-9.2** A test proving a reload with a bad cert/ACL leaves the previous
  config serving (no fail-open to permissive).

### WP-10 — Soak + fuzz gate

- **G-10.1** `go test -race ./... -count=1` green.
- **G-10.2** The fuzz targets in WP-2 run in CI (or a documented local gate) for
  a recorded duration with zero crashers.
- **G-10.3** No new goroutine/FD growth across a recorded soak of the lifecycle
  tests.

### WP-11 — Close-out

- **G-11.1** `python3 scripts/findings_register.py validate` exits 0; every
  finding has `closed_commit` populated post-merge.
- **G-11.2** Manifest `summary` lists every finding ID raised by this phase;
  `make lint-phases` exits 0.
- **G-11.3** `docs/fragments/phase-868-go-proxy-deep-code-review.md` exists
  (never edit `CHANGELOG.md` directly).
- **G-11.4** `make preflight` green; then `gh pr merge --auto --squash --delete-branch`.

## Test strategy

- **Negative + positive pairs.** Every fix gets a test that asserts the
  **fixed** behaviour; if the fix is reverted, the test must fail. No
  "log-and-observe" tests.
- **Mocks stay out of unit tests** that touch Redis — patch the client
  (repo rule for Python unit tests; same discipline applied to Go `miniredis`).
- **Table-driven boundaries** for all parser work (WP-2), driven by the fuzz
  corpus seeds.
- **No new test-only helpers in production packages.**

## Acceptance criteria

- [x] Every WP-1..WP-10 gate has recorded evidence in `docs/security/pentest/verify/`.
- [x] Every finding is registered in `docs/security/findings.yaml` **and** has a
      GitHub issue **before** its fix is committed (bug-hunt workflow).
- [x] Each fix carries a regression test that fails when the fix is reverted.
- [x] Propagation sweep recorded for each HIGH/CRITICAL fix.
- [x] `go test -race ./... -count=1` green; `make preflight` green.
- [x] Manifest entry `COMPLETE`; fragment present; `make lint-phases` exits 0.

## Out of scope

- The 48-surface ownership re-split and scan-surface registration (Phases 865/866 own that).
- `management/` UI security.
- Performance work (Phase 867).
- `go.mod` dependency changes and CI job-graph edits.
