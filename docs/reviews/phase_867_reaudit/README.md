# Phase 867 — evidence bundle

Bundled artefacts behind **`docs/reviews/phase_867_reaudit.md`** (the deep re-audit of
Phase 867, "Deep Review & Architectural Audit of Performance Testing Harnesses",
merged as PR #719 / `fba6f574`). Nothing here is production code: this is the
reproduction kit for the findings ledger, so every claim in that document can be
re-run by a reviewer without a `/tmp` dependency.

## Layout

| File | What it is |
|---|---|
| `source_Phase_867_phase_doc.md` | Snapshot of `docs/phases/complete/PHASE_867.md` @ `fba6f574` — the source of the ten GATE commands the extractor parses |
| `source_Performance_Harness_Review_report.md` | Snapshot of `docs/reports/PERFORMANCE_HARNESS_REVIEW.md` @ `fba6f574` — the audited report |
| `extract_and_run_gates.py` | Extracts the GATE command column from the phase doc **mechanically** and runs it |
| `gates.transcript.txt` | GATE-1,2,3,5,6,7,8,9 transcript — GATE-1 `EXIT=1` (`SyntaxError`), all others green |
| `gates_gate4.transcript.txt` | GATE-4 (`go test -bench`) kept separate because it takes minutes; 36 `ns/op` rows |
| `bench_count1.log`, `bench_count3.log` | `go test -bench=. -run='^$' -benchmem` over the nine GATE-4 packages at `-count=1` and `-count=3` |
| `bench_compare.py`, `bench_compare.out` | Coverage (33 declared vs 26 table rows) + report-vs-re-run `ns/op` deltas + allocation equality |
| `preflight_main.transcript.txt` | `make preflight` at `fba6f574` — 8,705 lines, ends `✓ preflight passed` / `PREFLIGHT_EXIT=0` (closes the GATE-10 evidence gap) |
| `manifest_diff.py`, `manifest_diff.out` | Parsed-key diff of `manifest.yaml` between `origin/main~1` and `origin/main`, plus a node-level duplicate-key scan of both revisions |
| `probes/` | Three purpose-built Go experiments (each `go vet`-clean, `go.mod` included) |

## Prerequisites

- Run from a checkout of `origin/main` **at `fba6f574` or later**: the audited report
  (`docs/reports/PERFORMANCE_HARNESS_REVIEW.md`) does not exist before that commit and
  `extract_and_run_gates.py` refuses to run with a hint otherwise. A scratch copy:
  `git worktree add --detach /tmp/opencode/reaudit-main fba6f574`
- `GOROOT` must be set correctly for the snap-installed Go, or `go run .` fails with
  `package fmt is not in std` (see `AGENTS.md`): `export GOROOT=/snap/go/current`
- `benchstat` is **not** installed here, which is why comparisons use min/median/max
  instead of confidence intervals.
- Python 3 with PyYAML (only for the two analysis scripts).
- Python lint/test tooling follows the repo rule: never on the host — `make lint`,
  `make test`, `make preflight` run in the pinned `ja4proxy-tools` image.

## Regenerating each artefact

Gates (the transcripts are byte-identical to what was committed, because the commands
are read out of the phase doc rather than hand-copied):

```bash
python3 docs/reviews/phase_867_reaudit/extract_and_run_gates.py \
    --repo-root /tmp/opencode/reaudit-main --only 1 2 3 5 6 7 8 9   # -> gates.transcript.txt
python3 docs/reviews/phase_867_reaudit/extract_and_run_gates.py \
    --repo-root /tmp/opencode/reaudit-main --only 4 --timeout 900    # -> gates_gate4.transcript.txt
python3 docs/reviews/phase_867_reaudit/extract_and_run_gates.py --list   # inspect rows, run nothing
```

`--repo-root` exists because these commands only work at a checkout that contains the
audited report; it also makes the snapshot sources and the executed tree independent,
so a moving `main` can never quietly change what a gate means.

Benchmarks, then the comparison:

```bash
cd <repo-at-fba6f574>
export GOROOT=/snap/go/current
go test -bench=. -run='^$' -benchmem ./cmd/ja4pd ./internal/tls ./internal/quic \
    ./internal/server ./internal/security ./internal/cache ./internal/tap \
    ./internal/webhook ./internal/redis > bench_count1.log 2>&1
go test -count=3 -bench=. -run='^$' -benchmem $(same packages) > bench_count3.log 2>&1
python3 docs/reviews/phase_867_reaudit/bench_compare.py --counts bench_count3.log bench_count1.log
```

Manifest analysis (runs against the repo, default revisions `origin/main~1` / `origin/main`):

```bash
python3 docs/reviews/phase_867_reaudit/manifest_diff.py
```

`preflight_main.transcript.txt` is the captured log of `make preflight` in the
`fba6f574` worktree; re-running it takes ~15 minutes and pulls container images, so it
is committed as evidence rather than regenerated per review.

### `probes/rst_close` — does a blocked connection look like an error?

```bash
cd docs/reviews/phase_867_reaudit/probes/rst_close && go run .
```

Prints the `io.Copy` result against a peer that closes with `SO_LINGER 0` (RST):
`read: connection reset by peer` with a nil `syscall.Errno`, i.e. the harness records
it as `allowed=true` (finding F-01).

### `probes/port_ceiling` — ephemeral-port exhaustion, in a netns

Kept in a container network namespace so the host's sysctls are never touched:

```bash
cd docs/reviews/phase_867_reaudit/probes/port_ceiling
for v in 0 2; do
  docker run --rm --sysctl net.ipv4.ip_local_port_range="32768 34768" \
    --sysctl net.ipv4.tcp_tw_reuse=$v -v "$PWD":/src -w /src \
    golang:1.27.3-alpine go run . > netns_tw_reuse_$v.transcript.txt 2>&1
done
docker run --rm --sysctl net.ipv4.ip_local_port_range="32768 34768" \
  --sysctl net.ipv4.tcp_tw_reuse=0 --sysctl net.ipv4.tcp_fin_timeout=5 \
  -v "$PWD":/src -w /src golang:1.27.3-alpine go run . > netns_tw_reuse0_fin5.transcript.txt 2>&1
```

### `probes/dial_loop` — the report's 28-second cliff, on the real host

```bash
cd docs/reviews/phase_867_reaudit/probes/dial_loop && go run .   # 30 s at ~1,000 CPS
```

## Note on the probe transcripts

The transcripts under `probes/` were **re-generated from the sources committed here**,
not copied from the scratch directory the findings were drafted in — so every source and
its output in this bundle are self-consistent. Because they are re-runs, some numbers
differ slightly from the first pass recorded in the findings document (2,007 vs 2,009
successful dials; 28,096 vs 28,637 connections); both values are reported there, and the
conclusion is unchanged.
