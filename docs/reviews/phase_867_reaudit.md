# Re-Audit of the Phase 867 Deliverables (Performance Harness Audit)

**Subject of review:** `docs/reports/PERFORMANCE_HARNESS_REVIEW.md` and `docs/phases/complete/PHASE_867.md`, as landed by PR #719 (merge commit `fba6f574`, `main`, 2026-11-07).
**Reviewed:** 2026-11-08, against `origin/main` @ `fba6f574`.
**Document type:** review-findings record. It is **not** a phase plan and carries **no** manifest entry — a disposition phase still has to be claimed.
**Author:** AI Systems Engineering — adversarial re-audit of a review deliverable.

---

## 0. Why this document exists, and what it is not

Phase 867 audited the performance harnesses. This document audits **Phase 867**. It does not re-open the harness question, and it is not a complaint about tone: the report's headline conclusion — *the macro harnesses measure the load generator and the network stack, not the proxy* — is correct, and I confirm it independently (§11).

The problem is narrower and more serious: **several of the report's stated mechanisms are not true of this codebase, the acceptance gates were written so they could not detect that, and those false mechanisms have already been promoted into the scope of a four-phase roadmap.** The report is the only artefact Phase 867 produced; the roadmap is what will actually be built. Nothing in the manifest tracks phases 868–871 as written, and one of those numbers is already leased by an unrelated phase.

This is cheapest to fix now, while the only reader of the roadmap is a human. It becomes a wasted implementation phase the moment someone codes to §7.

---

## 1. What was executed to verify these findings

Recipes are in Appendix A; every claim below cites the evidence it produced. The
artefacts themselves — gate transcripts, benchmark logs, the manifest analysis and the
three probe programs with their output — are committed alongside this document in
`docs/reviews/phase_867_reaudit/`.

1. A clean `git worktree` at `origin/main` @ `fba6f574` (no local edits). The bundle
snapshots both audited sources (`source_Phase_867_phase_doc.md`,
`source_Performance_Harness_Review_report.md`) so the gate extractor never reads a
moving file.
2. All ten GATE commands **mechanically extracted** from the acceptance table
(`extract_and_run_gates.py`) and executed; transcripts in `gates.transcript.txt` and
`gates_gate4.transcript.txt`. Mechanical extraction beats hand-transcription: the
commands in the transcript are byte-identical to the committed ones.
3. `go test -bench=. -run='^$' -benchmem` across all nine GATE-4 packages on the host
(Go 1.27.3, i9-9900K) at `-count=1` and `-count=3` (`bench_count1.log`,
`bench_count3.log`) — 33 benchmark functions captured, versus the 26 the report tabulates.
4. Three targeted Go experiments written for this review:
   - `RST` close vs `io.Copy` error semantics (does a block look like an error to the harness?);
   - ephemeral-port exhaustion in a network namespace with a 2,001-port range, `tcp_tw_reuse=0` and `=2`;
   - a 30 s @ 1,000 CPS dial loop on the real host.
5. `go test -run 'TestRunProfileHermetic|TestRateLimited' ./internal/test/bench/` (all pass — they lock in current semantics, see F-05).
6. `manifest.yaml` analysis: parsed-key diff between `origin/main~1` and `origin/main`
(`manifest_diff.py`, output in `manifest_diff.out`), a node-level duplicate-key scan
of both revisions, key-type census, and `git diff --numstat` of the merge.

7. `make preflight` at `origin/main` @ `fba6f574`, which **exits 0** across all four
stages (`preflight_main.transcript.txt`) — this closes the GATE-10 evidence gap (F-13).

**Deliberately not run:** the compose integration stack, the 2-hour soak
(`soak_leak_test.go` is `//go:build soak`), and any Docker-image scan beyond what
`make preflight` performs.

---

## 2. Findings ledger

| ID | Severity | Finding | Where | Disposition |
|---|---|---|---|---|
| F-01 | **CRITICAL** | The enforcement path the report describes (HTTP 403/429 written by the proxy) **does not exist**; the load-bearing next-phase spec is built on it | report §1.1-2, §3.4.2, §6 row 2, §7.3 | erratum + rewrite §7 item 3 |
| F-02 | **HIGH** | The `h2`/ALPN "RFC 7540 violation" cannot occur — the proxy never negotiates ALPN and has no HTTP/2 stack | report §1.1-1, §3.4.1, §6 row 4 | erratum; reclassify as product gap |
| F-03 | **HIGH** | Micro-benchmark "full baseline" is a partial table (26/33) with unverified host/image claims and 1.7–2× run-to-run spread on `ns/op` | report §4, GATE-4 | re-run + label honestly |
| F-04 | **HIGH** | GATE-1 fails as committed (`SyntaxError`) and "validated by automated inventory auditor" refers to a script that was never committed | PHASE_867 GATE-1 | fix gate or drop claim |
| F-05 | **HIGH** | 6 of 10 gates are prose token-greps; GATE-2 literally requires the string `403 Forbidden`, mechanically incentivising F-01 | PHASE_867 GATE-2/3/5/7/8 | re-gate audit deliverables |
| F-06 | **MEDIUM** | Inverted `RateLimited` is real but its blast radius is mis-stated: the gate's throughput/latency failures have been advisory-only since Phase 818, and on the nightly path the flag can never flip | report §3.5, §7.70-1 | correct severity + design note |
| F-07 | **MEDIUM** | Inventory claims "24 files", contains 29 rows, and omits 4 benchmark-bearing files (8 benchmark functions) | report §2 | correct + re-verify |
| F-08 | **MEDIUM** | `scripts/perf-matrix.sh` description is fabricated (claims a worker-count sweep; the script hardcodes `--workers 64`, two scenarios) and is classified `ACTIVE` | report §2 | erratum |
| F-09 | **MEDIUM** | `soak_leak_test.go` is described as 1,000 requests; it is 500 (`20 × 25`) | report §6 row 6 | erratum |
| F-10 | **MEDIUM** | Ephemeral-port "proof" is mis-stated (it is a connection budget, not a 28 s clock) and its host precondition is unvalidated — which also **rescues** the `benchmarks.md` numbers the interim review called falsified | report §3.3 | rewrite as measured ceiling |
| F-11 | **MEDIUM** | Two remediation instructions are actively harmful: re-binding `bench-hostnative.sh` to `HOST_PORT_DIRECT`, and PROXY-protocol source-IP rotation to dodge client-side `TIME_WAIT` | report §5.5, §7.1.5 | strike or re-scope |
| F-12 | **LOW** | Roadmap numbers 868–871 collide with the already-claimed phase 868 lease | report §7 | renumber to 869–872 |
| F-13 | **LOW** | GATE-10 (`make preflight`) has no recorded transcript | PHASE_867 GATE-10 | attach result |
| F-14 | **LOW** | `lint-phases.py` (GATE-9's tool) has no duplicate-key or numeric-key-quoting guard; 52 phase keys are unquoted floats and `245.10` would collide with `245.1` | repo tooling | hardening follow-up |
| F-15 | **MEDIUM** | The 867 merge re-serialized the whole manifest: 3,223 insertions / 2,477 deletions for a one-entry change, unmentioned in the phase doc; the round-trip also silently deleted a duplicate `summary:` key that had been live at `main~1` | `git diff --numstat origin/main~1 origin/main` | erratum + scope rule |
| F-16 | **LOW** | The new entry is registered with a **string** key `'867'` and string dependency `'866'` while `866` itself is an **int** key; mixed key typing across 435 entries | manifest `@ fba6f574` | normalise keys |

---

## 3. Corrections to the interim (chat) review

Three claims from the earlier working review are **retracted** — they are reproduced here so the record is clean, and because each one changes a conclusion:

1. **"Phase 867 deleted manifest entry `245.1` / a `245.10` float-collision destroyed a sub-phase."** Retracted. A YAML diff of `manifest.yaml` between `origin/main~1` and `origin/main` shows **434 → 435 keys, one addition (`867`), zero removals, zero changed values** for pre-existing phases. There has never been a `245.1` named "README Banner + Emergency Quickstart"; that step exists only inside `docs/phases/complete/PHASE_245.md:189`. The genuine latent issues are (a) 52 unquoted float-formatted
phase keys (`88.1`…`250.6`) that would collide the moment anyone adds a `x.10`
(**F-14**) and (b) the manifest-wide re-serialization the merge actually performed
(**F-15**).
3. **"The duplicate `summary:` key under `866` is live on `main`."** Retracted with
correction: the duplicate *was* live at `origin/main~1` (two `summary:` keys at
lines 5689-5690; PyYAML keeps the last, so the first was already dead text) and the
867 merge **removed** it as a side effect of re-serializing the file. A node-level
duplicate-key scan (`manifest_diff.py`, bundled) reports `origin/main~1 -> line
5684: key 'summary' x2` and `origin/main -> no duplicate keys`. The tooling gap is
still real — `lint-phases.py` has no duplicate-key rule, so nothing prevents the
next one — but the instance is gone, and 867 deserves the credit it did not claim.
2. **Direction of the `Record()` error-drop.** The interim review asserted that errored-with-`allowed=false` connections are dropped from the good/bad tallies. They are not: `ja4bench.go:66-70` returns early only when `err != nil && allowed`. Errored *disallowed* connections still land in `GoodBlocked`/`BadBlocked`, which is why `TestRunProfileHermetic_F2` passes. The consequence is therefore *worse* than the interim review claimed, and is F-01 below.

Verified-good of the report (so this is not a drive-by): its line citations check out (`ja4bench.go:321`, `:332-338`, `:101-103`, `nightly_benchmark_gate.py:82-86`, `scripts/benchmark.py:106`, `basic_perf_test.sh:46`, `bench-hostnative.sh:28`), and GATE-2, 3, 4, 5, 6, 7, 8 all exit 0 as written.

---

## 4. F-01 — CRITICAL: the enforcement mechanism the report describes does not exist

**What the report asserts** (§1.1-2, §3.4.2): when the proxy blocks an adversarial request it "writes an `HTTP/1.1 403 Forbidden` response and closes the connection cleanly", so the harness's read completes without error and a blocked attacker is tallied as allowed. §6 row 2 repeats it ("treats HTTP 403 as allowed"). §7 (Phase 868 item 3) then specifies the fix: *"Implement strict HTTP status code verification (assert `200 OK` for good traffic, assert `403/429` for blocked traffic)."*

**What the code does.** The decision switch is `internal/server/server.go:545-554`:

```go
switch result.Action {
case "allow", "flag", "rate_limit":
    s.Forward(clientConn, initialData, ...)
case "tarpit":
    s.Tarpit(clientConn, initialData, ...)
case "block", "ban":
    if tcpConn, ok := clientConn.(*net.TCPConn); ok {
        _ = tcpConn.SetLinger(0)          // :552 — abrupt RST, no bytes written
    }
}
```

Evidence:

- `SetLinger(0)` + deferred `Close()` is the *only* enforcement primitive on the TLS port. The behaviour is documented identically in `docs/phases/complete/PHASE_814i.md:42` ("Policy Block/Ban: Immediate TCP RST (`SetLinger(0)`)") and `PHASE_215.md:73`.
- There is no 403/429 origin response anywhere in the proxy hot path: `rg "403|Too Many Requests|WriteHeader|HTTP/1.1 4"` over `internal/server` and `internal/security` returns only `health.go` 503s. Every other `403` on `main` is a management-API client test or a TLS signature-scheme hex constant (`0x0403`).
- `case "allow", "flag", "rate_limit": s.Forward(...)` — **`rate_limit` is an alert-only label; it forwards the connection.** There is no rate-limit enforcement and therefore nothing that could ever emit a 429. The audit did not flag this, and §7.3 specifies a test asserting one.

**Corrected mechanism, measured.** A Go experiment (Appendix A.4) with a peer that does `SetLinger(0)` immediately after accept:

```
RST-close peer: io.Copy bytes=0 err=… read: connection reset by peer
```

So enforcement *is* observable — but only as a transport error. In `runProfile` (`internal/test/bench/ja4bench.go:330-339`) the TLS handshake itself fails, so the `else` branch runs: `res.Record(isGood, false, 0, err)`, which increments `Errors` **and** `GoodBlocked`/`BadBlocked`.

**Consequences, and they are worse than the report's:**

1. `GoodBlocked` is reachable, but it means *"this good connection failed at the transport layer"*. An outage, a `TIME_WAIT` exhaustion, a `ECONNREFUSED`, a handshake regression and a policy block are the same counter. `FalsePositiveRate()` (`ja4bench.go:122-127`) is therefore a measure of harness/host health, not of proxy accuracy — and `Status()` (`:143-158`) fails the run on any of them.
2. Symmetrically, an attacker that **is** blocked lands in `BadBlocked`. The `Status()` gate never inspects `BadBlocked`/detection at all, so *false negatives are invisible, but not because a 403 was read successfully* — because the harness has no notion of "the proxy took an action" versus "the connection broke".
3. The real defect that makes all of this unfixable-as-specified is the one the audit skipped: **a verdict model with three states (forwarded / reset / tarpitted), not an HTTP status model.** The proxy is a TLS-terminating L4 forwarder; there is no HTTP layer to assert on. §7.3 is not a hard test to write — it is unimplementable without first giving the proxy an HTTP origin/response layer, which is a product change and belongs to no phase in this roadmap.

**Remediation.** Erratum for §1.1-2, §3.4.2, §6 row 2. Replace §7 item 3 with: *"assert connection-level verdicts — forwarded vs `RST` vs tarpit-vs-timeout — by instrumenting `ja4p`'s decision output (`server.go` emits a structured `proxy: connection decision` log line and `EmitConnectionEvent`; the harness should consume that, or the metrics counter for each action) rather than HTTP status codes."* Add a finding that `rate_limit` currently forwards (`server.go:546`) and decide whether that is intended behaviour.

---

## 5. F-02 — HIGH: the ALPN/`h2` "wire protocol violation" cannot occur

**What the report asserts** (§1.1-1): the harness "advertises `h2` via ALPN … but unconditionally transmits raw ASCII `HTTP/1.1` request text over the negotiated stream. This violates RFC 7540 / RFC 9113 §3.5 client connection prefaces." §3.4.1 adds: "When the proxy supports HTTP/2, TLS handshake negotiates `h2` … Any RFC-compliant HTTP/2 proxy or backend rejects this immediately with a GOAWAY/PROTOCOL_ERROR."

**Facts:**

1. ALPN is a **server** decision. A client advertising `h2` gets `h2` only if the server's `tls.Config.NextProtos` offers it.
2. The production proxy sets no `NextProtos` anywhere: `git grep "NextProtos" origin/main` matches exactly two files — the harness (`internal/test/bench/ja4bench.go:321`) and its own unit test (`ja4bench_test.go:249`). No `tls.Config` with ALPN exists in `internal/server` or `internal/tls`. Go's server therefore negotiates an empty protocol.
3. There is no HTTP/2 stack to violate: `go.mod` has no `http2`/`x/net/http2` dependency, and there is no HTTP listener on the TLS port (`http.Server` in production code appears only at `internal/server/server.go:271` for health/metrics and `cmd/ja4-tap/main.go:594`).

So no stream is ever "negotiated", no preface is expected, and no GOAWAY can be sent. The proxy is a byte forwarder: writing ASCII into it is *correct* usage for the protocol actually negotiated.

**What is actually true, and worth keeping:**

- `conf.NextProtos = []string{"h2", "http/1.1"}` at `ja4bench.go:321` is dead configuration that implies a capability the product does not have. That is a documentation-honesty defect, not a protocol defect.
- The far more consequential fact the report never states: **the product has no HTTP/2 (or HTTP-layer) path at all.** §6 dimension 4 ("HTTP/2 Multiplexing — target: dedicated H2/H3 multiplexing load generator") is therefore not a harness gap but a product gap; the generator cannot be written before the feature exists.
- `docs/performance/benchmarks.md:96` describes the 3,263 CPS measurement as "browser-like (h2 ALPN)". That phrase is false in exactly this way, and the audit's §1.1-1 contradicts it without ever reconciling the two. A throughput claim published with a mechanism that cannot occur needs its own erratum.

**Remediation.** Erratum for §1.1-1, §3.4.1, §6 row 4; erratum for `benchmarks.md:96`; and if HTTP/2 is genuinely wanted, a product phase, not a test phase.

---

## 6. F-03 — HIGH: the §4 "Full Go Micro-Benchmark Baseline" is neither full nor reproducible

**GATE-4's criterion:** "Execute all micro-benchmarks across all packages in the repository and record **reproducible** baseline metrics."

**Coverage.** `git grep -c '^func Benchmark'` on `main`: **39 declared benchmark functions across 15 files**. The nine GATE-4 packages contain **33**; the §4 table lists **26**. Missing from the table, from packages the gate explicitly ran: `BenchmarkLRUConcurrent`, `BenchmarkLRUGetMiss`, `BenchmarkDeliverEventEndToEnd`, `BenchmarkPubSubHandlerDispatch`, `BenchmarkSignPubSubMessage`, `BenchmarkParseCRYPTOFramesMultiFrag`, `BenchmarkReadVarint`. Six further functions sit in four packages the audit never inventoried at all (F-07): `internal/cli/engine` (`BenchmarkCLIParseAndExecute`), `internal/cli/output` (`BenchmarkRenderJSON`, `BenchmarkRenderTable`), `internal/config` (`BenchmarkConfigLoad`, `BenchmarkConfigValidate`, `BenchmarkExpandEnvVars`), plus `internal/quic/packet_fuzz_test.go`.

**Reproducibility.** §4 states the environment as "Linux x86_64 (`golang:1.27.3-alpine`, Intel Core i7-1185G7 @ 3.00GHz)". Re-running the identical command on this host (Go 1.27.3 native, i9-9900K, `-count=1` and `-count=3`, Appendix A.3) gives:

| measure | result |
|---|---|
| `allocs/op` identical to the report, in every sample | **26 of 26** |
| `B/op` identical to the report, in every sample | **22 of 26** — four are off by 1–2 bytes (`BenchmarkLRUSet` 7→8, `BenchmarkLRUSetWithEviction` 139→141/142, `BenchmarkSNIAnalyzer` 332→333, `BenchmarkVerifyPubSubHMAC` 745→746/747) |
| `ns/op` report-vs-re-run delta (median of 4 samples) | **−50% … +195%**; only 8 of 26 within ±15% |
| `ns/op` spread, **same binary**, within one `-count=3` invocation | 0.2% … **124.3%**, median 7.2% |
| `ns/op` spread, same binary, across the two invocations (minutes apart) | 0.9% … **228.8%**, median 11.3% |
| functions whose report-vs-re-run delta exceeds their **own** same-binary spread | **17 of 26** (`-count=3` view) |

The per-benchmark tables are machine-generated — `bench_compare.py`, with outputs
committed as `bench_compare.out` (both logs pooled) and `bench_compare_count3.out`
(within-invocation noise only) — because hand-transcribing benchmark output is itself a
defect vector. Extremes, report `ns/op` → re-run median:

| Benchmark | Report | Re-run median | Δ |
|---|---|---|---|
| `BenchmarkTCPReassembly` | 177.8 | 88.6 | −50% |
| `BenchmarkServer_AdmitConn` | 1,026 | 583.3 | −43% |
| `BenchmarkLRUSetWithEviction` | 628.1 | 436.4 | −31% |
| `BenchmarkJA4Compute` | 1,318 | 925.1 | −30% |
| `BenchmarkPacketDecode` | 55.76 | 39.69 | −29% |
| `BenchmarkPipelineCheckBypasses` | 3.998 | 4.053 | +1% |
| `BenchmarkComputeJA4Q` | 1,889 | 2,752 | **+46%** |
| `BenchmarkDeriveInitialKey` | 470.2 | 741.2 | **+58%** |
| `BenchmarkComputeHMAC` | 940.6 | 1,645 | **+75%** |
| `BenchmarkTapConsumer_GetSignal_RedisHit` | 1,759 | 3,218 | **+83%** |
| `BenchmarkBuildSignalPayload` | 2,912 | 8,592 | **+195%** |

Two details make the reproducibility claim worse than "different machine":

- `BenchmarkBuildSignalPayload` measured **2,878 ns/op** in the `-count=1` invocation and
  **8,507 / 9,464 / 8,676 ns/op** in the three samples of the `-count=3` invocation —
  same binary, same machine, minutes apart, a stable 3× offset. Its §4 number is not so
  much wrong as *unanchored*: nothing in the harness says which of the two worlds a run
  lands in.
- Inside one `-count=3` run, `BenchmarkServer_AdmitConn` spread **124%**
  (575.1 / 591.5 / 1,290), `BenchmarkRuleEvaluation` **94%** (1,141 / 2,216),
  `BenchmarkLRUSet` **52%** (68.57 / 53.3 / 45.04). A ±10% drift gate (report §7, Phase
  870 item) is arithmetically unreachable for these functions before any code changes.

Identical `allocs/op` everywhere means the *code* is the same; the movement is
measurement environment. The report records no git SHA for the table, no `-count`, no
`benchstat`, and an environment (an alpine container on an i7-1185G7) that this
repository's own documented measurement host (`i9-9900K`, per
`docs/performance/benchmarks.md`) cannot reproduce.

One more coverage artefact from the same comparison: 32 of the 33 in-scope functions
produce a result row, the exception being `BenchmarkReadVarint`, which emits only four
`b.Run` leaves (`/1-Byte`, `/2-Byte`, `/4-Byte`, `/8-Byte`) — so it has no §4 row and its
four measurements are invisible to the table. Separately, `cmd/ja4pd`'s two pipeline
benchmarks print logrus warnings into the benchmark stream, so their numbers land on an
orphan continuation line with no benchmark name attached (`bench_count1.log`, lines
16-23):

```
BenchmarkPipeline_Allow-16   	<4 interleaved logrus lines>
 2388313	       517.9 ns/op	     184 B/op	       3 allocs/op
```

That is the same class of defect as F-06: a line-oriented parser — which is what every
benchmark gate in this repo is — cannot see those two rows at all, and recovering them
required attributing a numbers-only line to the last-seen benchmark name.

The §8 sign-off then quotes this table as proof ("micro-benchmarks confirm `< 900 ns` per decision"), so the conclusion inherits the defect.

**Remediation.** Re-run with `-count=10 | benchstat` — and pin `benchstat` into the tools image, because it is not installed today — print `go version`, CPU model, governor, and the git SHA alongside the table, include all 33 in-scope functions plus their sub-benchmark leaves, silence logrus during benchmarks so the output stays line-parseable, and label the existing table for what it is — a single-host, single-shot partial snapshot. Better: emit the table from a script into `docs/reports/benchmark/` so it cannot drift from a run.

---

## 7. F-04 — HIGH: GATE-1 fails as committed and validates against a script that does not exist

`docs/phases/complete/PHASE_867.md`, GATE-1 criterion: *"…all 24 components… Validated by automated inventory auditor."*

1. **The promised auditor does not exist.** `git ls-tree -r --name-only origin/main | grep audit_harness` → no match. The Step 1 deliverable `scripts/audit_harness_inventory.py` was never committed.
2. **The committed verification command does not run.** Executed verbatim (Appendix A.1):
   ```
   SyntaxError: invalid syntax   (exit 1)
   ```
   cause: `[assert os.path.exists(p), f'Missing {p}' for p in paths]` — `assert` is a statement and cannot appear inside a list comprehension.
3. Even corrected, the command only checks that listed paths exist and that the count is ≥ 24 — it does not audit an inventory, and it is not an "automated inventory auditor". The count assertion is what produced the "24" claim in §2 while the table itself has 29 rows (F-07).

So GATE-1 is red, yet the phase closed as `COMPLETE`. Either the gate was never run, or
it was run and its failure was not noticed. The other nine gates do pass (Appendix A.1),
which makes this one easy to miss. The failure is captured verbatim in
`docs/reviews/phase_867_reaudit/gates.transcript.txt` (GATE-1 `EXIT=1`, summary line
`SUMMARY: 8 gate(s) executed, failing: [1]`), produced by running the command exactly as
the phase doc's own table stores it — no hand-transcription involved.

**Remediation.** Land `scripts/audit_harness_inventory.py` (walk `**/*_test.go` for `func Benchmark`, plus `scripts/*perf*|*bench*`, `.github/workflows/*bench*`, cross-check against the report table, fail on unlisted files), fix the GATE-1 transcription, and paste transcripts of all ten gates into the phase doc. If the phase is closed, do it in the erratum phase instead and annotate GATE-1 in the completed doc.

---

## 8. F-05 — HIGH: six of ten gates are prose token-greps, and one of them *asked for* F-01

| Gate | Command actually asserts |
|---|---|
| GATE-2 | the strings `\lambda`, `Coordinated Omission`, `TIME_WAIT`, `GoodBlocked`, **`403 Forbidden`** occur in the markdown |
| GATE-3 | `ALPN`, `RFC 7540`, `RateLimited`, `nightly_benchmark_gate.py` occur |
| GATE-5 | `proxy.py`, `18082`, `benchmark_comparison.py`, `self.lock` occur |
| GATE-7 | six dimension labels occur |
| GATE-8 | the strings `Phase 868`, `Phase 869`, `Phase 870`, `Phase 871` occur |

GATE-2's *criterion* is "…(4) `GoodBlocked` reachability under TCP RST vs HTTP 403" — and the *command* satisfies it by requiring the literal string `403 Forbidden` to appear in the document. GATE-3 requires `RFC 7540` to appear. A token grep cannot establish reachability, and in practice it **pays an author to invent the mechanism**. F-01 and F-02 are exactly the two findings those two gates were supposed to catch, and both are in the same document that made both gates green.

This is the most transferable defect in Phase 867: for an audit deliverable, a text-presence gate is not an acceptance criterion. GATE-6 (container import check) and GATE-9 (manifest + fragment) are legitimate; GATE-4 and GATE-10 are legitimate in shape but unverified in fact (F-03, F-13).

**Remediation.** For audit/review phases, gate on artefacts: a script that exits 0, a command transcript committed alongside, a numeric assertion (`benchstat` output, ≥N functions), and a claim-vs-source check (every mechanism assertion in the report must name a `file:line` that the checker opens and greps). Add that last one to `scripts/lint-phases.py` or a sibling checker: extract `` `path/file.go:NN` `` citations from review docs and verify the cited line is in range and the surrounding token exists.

---

## 9. F-06 — MEDIUM: the inverted `RateLimited` gate is real, but its stated blast radius is wrong

The report's core observation is correct and I reproduce it:

- `ja4bench.go:101-103`: `RateLimited = ThroughputCPS >= 0.9*OfferedRateCPS` — i.e. "the generator kept up", not "the proxy throttled".
- `scripts/nightly_benchmark_gate.py:82-86`: `if result.get("rate_limited", False): failures.append("benchmark was artificially rate-limited…")`.

Two tests lock the semantics in, so any fix must change them deliberately: `internal/test/bench/ja4bench_test.go:191-216` (asserts `RateLimited == true` at 95/100 offered) and `:300-307` (asserts `rate_limited=true` on a *fast* server path); plus `tests/unit/test_nightly_benchmark_gate.py:106-115`. All pass today.

**But the report overstates the consequence twice:**

1. **"fails CI" / "fails the nightly job".** Since Phase 818 (#395) the regression step in `.github/workflows/nightly-benchmark.yml:166-183` is explicitly **advisory** — it emits `::warning::` and does not `exit 1`. The only blocking check the gate contributes is the error-rate check (`:70-80`, `max_error_rate_percent: 1.0`). So the inverted flag cannot redden anything today.
2. **The paradox never fires on the path that actually runs.** The nightly invocation (`nightly-benchmark.yml:59`) is `./bin/ja4p test benchmark --host 127.0.0.1:$PORT --duration 30 --output json` with **no `--good-rate`**, so `OfferedRateCPS` is the default 1,000 (`ja4bench.go:214`), against the docker-proxy bridge whose baseline is 600 CPS and whose observed CI value is ~96 CPS (`docs/reports/nightly_benchmark_baseline.json`, plus the Phase 818 comment in the workflow). `96 >= 0.9*1000` is false every night: `rate_limited` is permanently false on that job.

The live damage on that path is different and larger than the report says: with a 600 CPS host baseline and a 20% gate, the throughput check fires ~84% of the time purely from the runner/host mismatch — which is exactly why the step had to be made advisory. So the nightly gate is presently a warning generator whose error-rate check is the only thing with teeth, and per F-01 that error-rate check treats every policy block as an error against a 1% budget.

**Design trap for §7 (roadmap Phase 870 item 1).** "Fix" here must not mean "invert the flag": if `rate_limited` means "achieved < 90% of offered", it is **true on every nightly run by construction** (1,000 offered against a ~600 CPS bridge ceiling), so an inverted check would warn every night forever and teach nobody anything. Either make the nightly job offer a rate the measured ceiling can meet, or delete the saturation signal from that job.

**Remediation.** Correct §3.5's severity language ("advisory-only, dormant"); keep the finding; add the two notes above to the roadmap text before anyone implements 870.

---

## 10. F-07, F-08, F-09 — MEDIUM: inventory and script-description defects

**F-07 — the inventory table.** §2 says *"The following 24 performance files … have been audited"*; the table has **29 rows**. The "24" is an artefact of GATE-1's `assert len(paths) >= 24`. Four benchmark-bearing files are absent from the table and therefore from every conclusion drawn from it:

| File | Benchmark functions | Not inventoried |
|---|---|---|
| `internal/cli/engine/engine_fuzz_test.go` | 1 (`BenchmarkCLIParseAndExecute`) | yes |
| `internal/cli/output/output_fuzz_test.go` | 2 (`BenchmarkRenderJSON`, `BenchmarkRenderTable`) | yes |
| `internal/config/config_fuzz_test.go` | 3 (`BenchmarkConfigLoad`, `BenchmarkConfigValidate`, `BenchmarkExpandEnvVars`) | yes |
| `internal/quic/packet_fuzz_test.go` | 2 (`BenchmarkParseCRYPTOFramesMultiFrag`, `BenchmarkReadVarint`) | yes |

Conversely, all 29 listed paths do exist on disk — the table's existence claims are sound; its **completeness** claim is not, and the count in the prose contradicts the table three lines below it.

**F-08 — `scripts/perf-matrix.sh`.** Described as *"Runs parameter sweeps across worker counts (w ∈ {1,4,8,16}) and rates."* The script is 23 lines: `--workers 64` is hardcoded at `scripts/perf-matrix.sh:14`, exactly two scenarios run (`A`: good 2000 / bad 0; `B`: good 1000 / bad 100, `:18` and `:21`), there is no worker sweep, and it embeds `printf "1\nja4perf\n0\n" | $BIN init`, `make start-poc`, `sleep 15`, `make stop`. It also has **zero inbound references** (the only mentions in the tree are `docs/reference/SCRIPTS.md:111`, which lists its Makefile column as `—`, and historical phase docs), and it is **not** the retired `make perf-test` target (`Makefile:1169` is retired; `make perf-test-basic` at `Makefile:1503` exists and the audit never mentions it). Classified `ACTIVE`. The sweep does not exist; classifying a fabricated behaviour as `ACTIVE` is how it stays unfixed.

**F-09 — soak row.** §6 row 6 says `cmd/ja4pd/soak_leak_test.go` covers "1,000 requests". It is `concurrency := 20`, `iterations := 25 // 500 connections total` (`cmd/ja4pd/soak_leak_test.go:45-46`), and the file's own header comment says "abrupt RST termination of 500 TLS connections". The claim overstates coverage 2×. Note also that the file is `//go:build soak` — it never runs in any current gate, which the report does not mention.

**Remediation.** Three-line errata in §2 and §6; make the inventory count generated (F-04's script), not hand-typed.

---

## 11. F-10 — MEDIUM: the ephemeral-port "proof" is directionally right, mis-stated, and its precondition is unvalidated

§3.3 is the report's flagship "mathematical proof": `T_exhaust = N_ports / λ`, "at 1,000 CPS ≈ 28.23 seconds", then `EADDRNOTAVAIL` and a poisoned `FalsePositiveRate`. GATE-2 accepts it by requiring the string `TIME_WAIT`.

**Verified experiment** (`probes/port_ceiling`, container network namespace, `ip_local_port_range = 32768–34768` → 2,001 ports, 8,000 sequential dials at one 4-tuple; transcripts in `probes/port_ceiling/netns_*.transcript.txt`):

| `tcp_tw_reuse` | successful dials before `connect: cannot assign requested address` |
|---|---|
| `0` | **2,009** (first run) / **2,007** (re-run) — first error at n≈2,007-2,009, t≈0.1-0.4 s |
| `2` | **4,831** (first run) / **4,013** (re-run) of 8,000 — first error at n≈2,010 |
| `0` + `tcp_fin_timeout=5` | **2,017** — no effect, see correction below |

On this host (`tcp_tw_reuse=2`, range `32768–60999`, `tcp_fin_timeout=60`), a 30 s @ 1,000 CPS dial loop (`probes/dial_loop`) completed **28,637** (first run) / **28,096** (re-run) connections with **zero errors** — numerically at the report's `N_ports`, but with **no cliff at 28 s**.

**What is right:** the failure mode exists; the error string is exactly as quoted; the closed-loop generator has no port management; and the accounting chain §3.3 describes (`err != nil` → `GoodBlocked` → `FalsePositiveRate > 0` → `Status()` fails) is accurate — which per F-01 means infrastructure failure and policy enforcement are the same counter.

**What is wrong:**

1. **It is a connection budget, not a clock.** Exhaustion occurs at *N* connections, not at *N/λ* seconds. If `λ < N_ports / TIME_WAIT` (≈ 470 CPS for 28,232 ports at 60 s), a loop never exhausts however long it runs. The report's "after 28 seconds of continuous testing" framing is the wrong causal model and is what makes the figure look like a deadline.
2. **The precondition is never measured.** `tcp_tw_reuse` dominates the outcome (2,001-port namespace absorbed 4,831 attempts at `reuse=2`). This host runs `reuse=2`; GitHub runners and the CI default are unmeasured. A proof that changes sign under a single sysctl is a hypothesis with an untested precondition, not a derivation.
3. **It contradicts §7.1.5** (F-11) and it also *rescues* the numbers the interim review called falsified — see below.
4. **The tunables it implicitly relies on are the wrong ones.** A test with `tcp_fin_timeout=5` (`netns_tw_reuse0_fin5.transcript.txt`) changed nothing: 2,017 successes vs 2,007-2,009 at the default. On Linux `tcp_fin_timeout` sets FIN-WAIT-2, not TIME_WAIT; TIME_WAIT is fixed at 2×MSL (60 s) and is not shrinkable by sysctl. The only knobs that move the ceiling are `ip_local_port_range`, `tcp_tw_reuse`, `tcp_timestamps` (tw_reuse only works with timestamps), more local addresses, or keeping connections alive — which is precisely why `ja4bench`'s `Connection: close` + per-connection dial is the real cost, not a footnote.

**Correction to the interim review's "benchmarks.md is falsified" claim — withdrawn.** `docs/performance/benchmarks.md:92,202` reports 3,263 CPS sustained for ~30 s with "0 errors". 3,263 × 30 ≈ 98k dials against a 28,232-port range looks impossible under §3.3's model. My host experiment shows why it is plausible: at `tcp_tw_reuse=2` the effective ceiling rises and degradation is gradual, not a wall. So that row is **not** a contradiction of the physics — what it lacks is provenance (git SHA *is* given for the history table, but sysctls, duration and offered rate are not). The correct demand is measurement provenance, not an accusation of fabrication.

**Remediation.** Rewrite §3.3 as a measured **sustained-CPS ceiling**: `CPS_max ≈ N_ports / W_tw` (≈ 470 CPS at defaults, ≈ 950 CPS observed at `reuse=2`), state the sysctl precondition, and add a concrete harness requirement the report never reached: the macro harness and `bench-hostnative.sh` must **record** `tcp_tw_reuse`, `ip_local_port_range`, `tcp_fin_timeout` and `tcp_timestamps` into the result JSON (or the report header) — without them, every macro number in the repo is uninterpretable across machines. That single change explains more measurement disagreement than any harness bug in the report.

---

## 12. F-11 — MEDIUM: two remediation instructions are harmful as written

**§5 item 5 — "bench-hostnative.sh … defaults to `PROXY_PORT=18080` instead of canonical `HOST_PORT_DIRECT` (8080)"; §7 (roadmap Phase 869 item 3) — "Update `scripts/bench-hostnative.sh` default port binding to `HOST_PORT_DIRECT`."**

`scripts/bench-hostnative.sh` exists precisely to take `docker-proxy` **out** of the inbound path: it launches `ja4pd` on the host at `PROXY_PORT=18080` / `METRICS_PORT=29090` (`:24-28`) while Redis and the backend stay in Docker, and it hard-fails if either port is occupied (`port_busy()` at `:46-48`). `HOST_PORT_DIRECT` is the *container's published bridge port* (`deploy/docker/docker-compose.poc.yml:70`, default **8081** — not 8080 as §5 claims, and §3.6 separately cites the bridge port as `127.0.0.1:8080`). Re-binding the host-native run onto the published bridge port re-introduces the very userland relay the script exists to avoid — and against a running PoC stack the `port_busy` guard refuses to start. The three port numbers in the report (8080 in §5, 8080 in §3.6, 8081 in the compose) are not consistent with each other either.

**§7 item 5 — "Add PROXY protocol v2 header generation with rotating synthetic source IPs to bypass client-side `TIME_WAIT` port exhaustion."** PROXY protocol v2 conveys the original client address **to the upstream server**; it cannot change the client's own ephemeral port. Rotating *local* bind addresses to multiply the 4-tuple space is a real technique, but it needs multiple loopback addresses and explicit `Dialer.LocalAddr` plumbing (0.0.0.0/8 is pre-configured local on Linux, so it is feasible) — none of which the report specifies. As written this item is unimplementable and would burn implementation time before someone discovers why.

**Remediation.** Strike §5 item 5 and §7-869.3 (or restate as: document why 18080/29090 are deliberate). Rewrite §7-868.5 as: capture host sysctls, and if a higher churn ceiling is needed, bind explicit rotating local addresses on the client side — with an explicit decision about `tcp_tw_reuse` policy for benchmark hosts.

---

## 13. F-12–F-16 — LOW/MEDIUM: roadmap numbering, GATE-10 evidence, manifest health

**F-12 — the roadmap numbers are already taken.** §7 proposes Phases 868–871 and GATE-8 passes on the strings "Phase 868"…"Phase 871". Phase **868 is claimed**: remote branch `phase-868-go-proxy-deep-code-review` (lease commit `3b0346e6`, 2026-11-07, the same day as the 867 merge), whose `docs/phases/PHASE_868.md:45` lists 867 as `IN_PROGRESS` — stale, since 867 merged the same day — and `:212` puts performance-harness work out of its scope. So the collision is real but harmless if caught now: the four performance phases should be renumbered **869–872** and registered in `manifest.yaml` before any of them is claimed. Fixing `PHASE_868.md:45` is the 868 owner's edit, not this erratum's.

**F-13 — GATE-10 evidence gap, now closed by this review.** GATE-10 is `make preflight`; the phase doc records no transcript. Run at `main` @ `fba6f574`: `make preflight` **exits 0** — all four stages (`lint`, `scan`, `test`, `test-race`) passed, ending `✓ preflight passed — safe to open a PR` (log: 8,705 lines). So the *fact* is fine; the *evidence* was simply never recorded, which is the same process hole as F-04: a gate with no transcript is indistinguishable from a gate that was never run.

**F-14 — `scripts/lint-phases.py` is too thin for GATE-9's purpose.** It implements three rules (action_plan exists, H1 stale-number, allowed status values). It does not detect:
- **duplicate keys.** At `origin/main~1` the manifest carried, under `866`, two
`summary:` keys (lines 5689-5690); PyYAML keeps the last, so the first — a
`"COMPLETE 2026-11-07. …"` status-in-summary — was already dead text. The 867 merge
**removed** it (see F-15: the file was re-serialized), so `main` is clean today.
The tooling gap is unfixed either way: `lint-phases.py` cannot see a duplicate key,
so nothing prevents the next one, and GATE-9 ("Manifest & Documentation Health")
passed over it when it was still present.
- **unquoted numeric keys.** Demonstrated hazard: `yaml.safe_load("245.1: {…}\n245.10: {…}")` collapses to `{245.1: <second value>}` — YAML 1.1 float parsing silently destroys a sub-phase entry. The manifest currently has `245.1`–`245.9` unquoted, and `PHASE_245.md:189` documents an eleventh step ("Step 1: `Under Attack` README Banner + Emergency Quickstart") that has **no manifest entry at all**; whoever adds it as `245.10` will overwrite `245.1`.
- **phase docs referenced nowhere / roadmap phases not registered** — which is how §7's 868–871 could exist entirely outside the manifest (F-12).

**Remediation.** Add to `lint-phases.py`: a duplicate-key loader (`yaml.compose` / node-level key scan), a rule that any key matching `^\d+\.\d+$` must be quoted, and a rule warning on H1 `Phase N` references in phase docs that are absent from the manifest. Register 869–872 (or explicitly decline them) in `manifest.yaml`.

**F-15 — the merge was a full re-serialization of the manifest, not an edit.**
`git diff --numstat origin/main~1 origin/main -- docs/phases/manifest.yaml` →
**3,223 insertions, 2,477 deletions** for a change whose content is one phase entry.
The diff shape is diagnostic of a `yaml.safe_load` → `yaml.safe_dump` round trip:
long `summary:` scalars re-wrapped at ~79 columns, `"double quoted"` scalars becoming
plain or `'single quoted'`, flow sequences `dependencies: [865]` becoming block
sequences, and `\u2014` escapes becoming literal em-dashes. Parsed content is
unchanged for every pre-existing key (`manifest_diff.py`: `CHANGED: []`), so nothing
semantic was lost — and the round trip incidentally removed the duplicate `summary:`
key described above, which is a real (unclaimed, unattributed) fix.

The problem is process, not data: (i) `PHASE_867.md` never says the manifest was
rewritten, so the 5,700-line diff has no stated justification; (ii) the phase's own
scope is a documentation audit, and a whole-file re-serialization is a repo-wide
change; (iii) under branch protection with required reviews, a reviewer cannot
review one added entry inside 5,700 changed lines — the actual content of the phase
is invisible in its own PR. (iv) is prospective, not observed: I tested the rebase
cost on the one branch that has to follow this merge — `origin/phase-868-go-proxy-
deep-code-review` (lease commit `3b0346e6`) rebased onto `main` in a scratch worktree
and it applied cleanly, because that commit adds only `docs/phases/PHASE_868.md` and
never touches the manifest. The hazard is for the *next* branch that edits the
manifest: its diff base is a file whose every long line has been re-wrapped, so
legitimate one-line manifest edits will now collide with unrelated re-wrapping.

**Remediation.** Erratum note in `PHASE_867.md` recording what was rewritten and
why; a rule for roadmap files (mirror of the CHANGELOG-fragment rule in AGENTS.md):
edit `manifest.yaml` additively, never re-dump it. If the repo *wants* a canonical
manifest formatting, make it explicit — a `make manifest-format` target plus a CI
check that the file is already formatted, so reformatting is a named commit and not a
side effect.

**F-16 — mixed key typing in the new entry.** `main` registers the phase as the
**string** key `'867'` with the **string** dependency `'866'`, while `866` itself is
an **int** key with an int dependency `[865]`. Census at `main~1` already shows the
manifest is mixed (305 int, 49 float, 80 str keys), so this is not an 867 invention —
but 867 added to the mix rather than following its neighbour. No tool resolves the
cross-reference today (`lint-phases.py` stringifies ids; `sync-roadmap.py` sorts via
`_phase_sort_key`, which tolerates mixed types), so the concrete risk is latent: any
future `phases[867]` lookup by int, or a dependency resolver that matches ids by
identity, will miss. Normalize on strings, and have the linter (F-14) enforce quoting
of every key that is not a bare int.

---

## 14. What Phase 867 got right (confirmed independently)

This is not a repudiation of the audit. These findings reproduce:

| Claim | Confirmation |
|---|---|
| Closed-loop generator, tick drops, coordinated omission | `ja4bench.go:310` `time.NewTicker(1s/ratePerWorker)` inside `select`; `:334` `_, _ = io.Copy(...)` discards the read error; `:336` records latency as `time.Since(startDial)` with no scheduled-issue time. Real. |
| Inverted `RateLimited` semantics | `ja4bench.go:101-103` vs `nightly_benchmark_gate.py:82-86` (severity corrected in F-06). |
| `basic_perf_test.sh` counts failure as success | `scripts/basic_perf_test.sh:46` `\| grep -q "200\|502\|503"`. A genuine bug the audit surfaced. |
| Zombie Python tooling | `scripts/benchmark_comparison.py` (~2k lines against the deleted `proxy.py`), `tests/performance/benchmark_phase26.py` / `benchmark_parallel_signals.py` importing `src.security.pipeline`, `scripts/tap_benchmark.py` importing `src.tap.capture`. All real; none is collected by `make test` today. |
| `scripts/benchmark.py` sleeps under the lock | `:106` confirmed. |
| Bridge-path measurement is dominated by `docker-proxy` | Corroborated independently by `.github/workflows/nightly-benchmark.yml:166-183` (Phase 818: host baseline 600 CPS / 290 ms vs CI ~96 CPS / 17 ms) and `docs/performance/benchmarks.md:92`. |
| Soak/long-duration coverage is missing | True, and under-stated (F-09). |
| No bulk data-plane benchmark | True — the harness sends a 40-byte `GET /health` and discards the body. |

The audit's *direction* is sound; its mechanisms and its acceptance gates are not.

---

## 15. Disposition

### 15.1 One MEDIUM erratum phase (items F-01, F-02, F-06…F-11, F-13)

Documentation-only, no code. Scope:

1. Errata in `docs/reports/PERFORMANCE_HARNESS_REVIEW.md` §1.1-1, §1.1-2, §3.3, §3.4, §3.5, §3.6, §5 item 5, §6 rows 2/4/6, §2 prose, §7 items 868.3, 868.5, 869.3, 870.1 — with the corrected mechanism text in this document as the source.
2. Companion erratum in `docs/performance/benchmarks.md` (the "h2 ALPN" phrase at `:96`) and add host-sysctl provenance to its measurement tables.
3. Register the follow-up phases in `manifest.yaml` as **869–872** and stop referring to 868 as a performance phase.
4. Attach the gate transcripts (all ten, with GATE-1's corrected command) and the `make preflight` result to `docs/phases/complete/PHASE_867.md`.
5. Record in `PHASE_867.md` that the merge re-serialized `manifest.yaml` (F-15) and add the additive-edit rule for roadmap files to AGENTS.md — a manifest-wide `safe_dump` must be a named commit, never a side effect.
6. News fragment under `docs/fragments/` (never edit `CHANGELOG.md` directly).

### 15.2 Separate phases (do not fold into the erratum)

- **Benchmark baseline re-run** (F-03): `-count=10` piped through `benchstat` (pin
  `golang.org/x/perf/cmd/benchstat` into the tools image — it is not installed today),
  all 33 in-scope functions plus their `b.Run` leaves (39 repo-wide if the scope is
  widened, F-07), SHA/CPU/governor/`go version` tagged, logrus silenced during benchmarks
  so output stays line-parseable, generated into `docs/reports/benchmark/`. MEDIUM,
  code-adjacent (a generator script).
- **Harness verdict model** (F-01): replace "assert 403/429" with connection-level
  verdicts (forwarded / RST / tarpit) sourced from the proxy's own decision output or
  per-action metric counters; fix `Record()`/`Status()` so a transport error is never
  tallied as a policy verdict; update `ja4bench_test.go:191-216,300-307` and
  `tests/unit/test_nightly_benchmark_gate.py:106-115` in the same change. This is the
  phase the roadmap's "868" was trying to be — and it needs the erratum landed first, or
  it will be built on a fiction.
- **`lint-phases.py` hardening** (F-14, F-16): node-level duplicate-key detection, a rule
  that any key matching `^\d+\.\d+$` must be quoted, key-type normalisation for new
  entries, and a warning on `Phase N` references in phase docs that are absent from the
  manifest. SMALL.

### 15.3 Sequencing and collision note

Renumbering must happen **before** anything claims 869+ and before the 868 owner writes their phase doc's dependency section. If the erratum phase is claimed as its own number, it should slot between 868 and 869 rather than being folded into 869 — otherwise the fix for the roadmap arrives after the roadmap is built.

---

## 16. Open questions for the user

1. Is the fictional 403/429 mechanism merely a drafting artefact, or did its author believe the proxy has an HTTP-block response path? If the latter, is there a *product* intent to add one (which would change F-01 from "erratum" to "unregistered feature request")?
2. Is `rate_limit` forwarding the connection (`server.go:546`) intended behaviour, or a gap worth its own finding ID?
3. Should `scripts/perf-matrix.sh` be deleted (23 unreferenced lines, hardcoded flags, embedded `make start-poc`) or fixed into the sweep the report claims it runs?
4. Which is authoritative for macro baselines — the host-native path (`bench-hostnative.sh`, 18080) or the CI bridge path (`nightly-benchmark.yml`)? The report treats both as "the" benchmark and the baseline file uses the bridge number.
5. Do you want this document converted into a claimed phase (`PHASE_8XX`) now, or kept as an unclaimed findings record until the 868 owner's PR lands?

---

## Appendix A — reproduction recipes

Everything needed to re-run these recipes is in `docs/reviews/phase_867_reaudit/`
(start with its `README.md`). Prerequisite for A.1–A.3: a checkout at `origin/main` @
`fba6f574` or later, because the audited report does not exist before that commit —
`git worktree add --detach /tmp/opencode/reaudit-main fba6f574`. Export
`GOROOT=/snap/go/current` first, or `go` fails with `package fmt is not in std`.

**A.1 GATE commands.** Ten commands, read out of the acceptance table by
`extract_and_run_gates.py` (mechanical, so the commands executed are byte-identical to
the committed ones) and run at `main` @ `fba6f574`:

```bash
python3 docs/reviews/phase_867_reaudit/extract_and_run_gates.py \
    --repo-root /tmp/opencode/reaudit-main --only 1 2 3 5 6 7 8 9
python3 docs/reviews/phase_867_reaudit/extract_and_run_gates.py \
    --repo-root /tmp/opencode/reaudit-main --only 4 --timeout 900
```

Results in `gates.transcript.txt` and `gates_gate4.transcript.txt`: **GATE-1 → exit 1**
(`SyntaxError`); GATE-2, 3, 4, 5, 6, 7, 8, 9 → exit 0; GATE-10 → exit 0 (A.5). The
phase doc itself is snapshotted as `source_Phase_867_phase_doc.md`, so the extractor's
input cannot drift.

**A.2 Manifest diff.**

```bash
python3 docs/reviews/phase_867_reaudit/manifest_diff.py        # -> manifest_diff.out
git diff --numstat origin/main~1 origin/main -- docs/phases/manifest.yaml
```

Expected: `434 435 added ['867'] removed [] changed []`; node-level duplicate scan
reports `origin/main~1 -> line 5684: key 'summary' x2` and `origin/main -> no duplicate
keys`; `git diff --numstat` → `3223 2477`.

**A.3 Benchmark re-run and comparison.**

```bash
go test -bench=. -run='^$' -benchmem ./cmd/ja4pd ./internal/tls ./internal/quic \
    ./internal/server ./internal/security ./internal/cache ./internal/tap \
    ./internal/webhook ./internal/redis > bench_count1.log 2>&1
go test -count=3 -bench=. -run='^$' -benchmem $(same packages) > bench_count3.log 2>&1
python3 docs/reviews/phase_867_reaudit/bench_compare.py --counts bench_count3.log bench_count1.log
```

33 functions declared in scope, 26 rows in the §4 table, 32 functions observed, 4
`b.Run` leaves. `benchstat` is not installed on this host, which is why F-03's evidence
uses min/median/max over `-count=3` rather than a confidence interval.

**A.4 Ephemeral-port and verdict probes.** Sources are committed under
`docs/reviews/phase_867_reaudit/probes/`, each with its transcript:

- `probes/rst_close` — `go run .` → `read: connection reset by peer`, nil `Errno`,
  recorded `allowed=true` (F-01).
- `probes/port_ceiling` — runs in a container netns so host sysctls are untouched:
  `docker run --rm --sysctl net.ipv4.ip_local_port_range="32768 34768" --sysctl
  net.ipv4.tcp_tw_reuse=0 -v "$PWD":/src -w /src golang:1.27.3-alpine go run .`
  → `ok=2007 … connect: cannot assign requested address`; `tcp_tw_reuse=2` → `ok=4013`;
  adding `tcp_fin_timeout=5` → `ok=2017` (no effect).
- `probes/dial_loop` — `go run .` on the host, 30 s @ 1,000 CPS → `ok=28096 fail=0`
  (no cliff).

**A.5 Preflight.**

```bash
cd /tmp/opencode/reaudit-main && GOROOT=/snap/go/current make preflight
```

Observed: exit 0, `✓ preflight passed — safe to open a PR`, stages 1/4 lint, 2/4 scan,
3/4 test, 4/4 test-race; the full 8,705-line log is committed as
`preflight_main.transcript.txt`. Redis "connection refused" lines inside the race stage
are expected negative-path noise, not failures.

---

## Appendix B — files this document names

| File | Role here |
|---|---|
| `docs/reports/PERFORMANCE_HARNESS_REVIEW.md` | the audited deliverable (erratum target) |
| `docs/phases/complete/PHASE_867.md` | the ten gates (GATE-1 broken; transcripts absent) |
| `internal/test/bench/ja4bench.go` | `:101-103` `RateLimited`; `:122-127` FP rate; `:143-158` `Status()`; `:214-217` flag defaults; `:310` ticker; `:321` `NextProtos`; `:330-339` verdict collapse |
| `internal/server/server.go` | `:545-554` action switch; `:552` `SetLinger(0)`; `:546` `rate_limit` forwards |
| `scripts/nightly_benchmark_gate.py` | `:45-57` throughput floor; `:70-80` error-rate; `:82-86` inverted flag |
| `.github/workflows/nightly-benchmark.yml` | `:59` nightly invocation; `:166-183` advisory-only step |
| `docs/reports/nightly_benchmark_baseline.json` | 600 CPS bridge baseline, 1% error budget |
| `docs/performance/benchmarks.md` | `:92`,`:202` 3,263 CPS rows; `:96` false "h2 ALPN" phrase |
| `scripts/bench-hostnative.sh` | `:24-28` deliberate 18080/29090; `:46-48` `port_busy` guard |
| `scripts/perf-matrix.sh` | 23 lines, `:14` `--workers 64`, `:18`,`:21` two scenarios |
| `scripts/basic_perf_test.sh` | `:46` 502/503 counted as success |
| `cmd/ja4pd/soak_leak_test.go` | `:45-46` 500 connections; `//go:build soak` |
| `scripts/lint-phases.py` | three rules only (F-14) |
| `docs/phases/manifest.yaml` | re-serialized by the 867 merge (F-15); `'867'` str key vs int `866` (F-16); 52 unquoted float keys (F-14) |
| `docs/reviews/phase_867_reaudit/` | this document's evidence bundle: gate extractor + transcripts, bench logs and comparison, manifest analysis, the three probes, and snapshots of both audited sources |
| `docs/reviews/phase_200_security_review.md` | naming/format precedent for a review record under `docs/reviews/` |
