# Phase 316c — Passive JA4T + advisory blocklist signal — notes

## What shipped

The Go TAP sensor now computes the canonical **JA4T** TCP fingerprint from each
connection's SYN and writes it to `fp:ja4t:ip:{ip}` (24h TTL); a new inline proxy
consumer (`ja4t_consumer`) reads it and emits an advisory `tap_ja4t_blocklist`
RiskSignal when the observed JA4T is on an operator-configured blocklist.

Files:
- `internal/tap/ja4t.go` — `ComputeJA4T(StackFeatures) string` (canonical FoxIO format).
- `internal/tap/store.go` — `Store.WriteJA4T`; `internal/tap/metrics.go` — `JA4TWrittenTotal`.
- `cmd/ja4-tap/main.go` — compute+write JA4T alongside the OS class.
- `internal/security/tap_ja4t_consumer.go` — `JA4TConsumer`; wired in `internal/security/pipeline.go`.
- `internal/metrics/metrics.go` — `TapJA4TLookupsTotal`, `TapJA4TSignalTotal`.
- `internal/config/loader.go`, `cmd/ja4pd/main.go`, `config/proxy.yml` — `ja4t_consumer` config.
- Tests: `internal/tap/ja4t_test.go`, `internal/tap/store_ja4t_test.go`,
  `internal/security/tap_ja4t_consumer_test.go`, `internal/tap/roundtrip_ja4t_test.go`.
- Docs: `docs/phases/PHASE_316c.md`, `docs/reference/REDIS_SCHEMA.md`,
  `docs/reference/OBSERVABILITY_STANDARDS.md`, `docs/runbooks/tap_mode.md`,
  `docs/fragments/phase-316c-tap-ja4t.md`; `scripts/gdpr_delete.py`.

## Decisions

1. **Re-scoped from the original "full JA4 family" outline.** A codebase-grounded
   review (see PHASE_316c.md §1) found most of the outlined fingerprints are
   physically impossible for a passive TLS TAP (JA4H/JA4H2/JA4SSH need plaintext
   app/SSH data; JA4X needs the TLS1.3-encrypted Certificate; QUIC needs UDP) and
   that **only `fp:os:ip` had a Go reader** — every other `fp:*` key was unread.
   Per the user's steer ("feasible slice + real consumer"), this slice ships JA4T
   + a consumer; JA4H/JA4H2/JA4SSH are dropped from the roadmap, the rest deferred
   to land with their own consumers.
2. **Canonical FoxIO JA4T**, not the archived Python letter-coded variant — the
   numeric form is what current JA4+ tooling and threat feeds use, so values are
   portable.
3. **Blocklist consumer, empty + disabled by default.** Mirrors the existing JA4
   blacklist pattern and 316b's write-and-light-up shape; cannot produce a false
   positive on its own; advisory-only (scored under the dial, never hard-blocks).
4. **`JA4TWrittenTotal` is a separate counter** from 316b's
   `FingerprintsWrittenTotal` rather than adding a `kind` label, to avoid
   disturbing 316b's metric/tests on the stacked branch.

## Branch / PR

Stacked on `phase-316b-tap-osmismatch` (PR #184, unmerged). The 316c PR is based
on that branch, so its diff is JA4T-only. **When #184 squash-merges, rebase 316c
onto main** (`git rebase --onto main <316b-sha> phase-316c-tap-ja4t`) and retarget
the PR base to `main`.

## Verification

`go build ./...`, `go vet ./...`, and `go test ./internal/tap/...
./internal/security/... ./internal/metrics/... ./internal/config/...` all pass.
