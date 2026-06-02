This is a review by claude Opus 4.8 Extended of the 
The rest of the associated documents are in archive/claude_ja4proxy_security_analysis.zip

# JA4proxy — Security Hardening Guide (for Claude Code)

**Audience:** Claude Code (agentic coding tool) and the engineers reviewing its
changes. **Goal:** improve the security posture of the **Go proxy** in this
repository by working through the prioritized findings below, fixing each with a
regression test that proves the fix.

This guide is self-contained: it carries the context you need without access to
the original review conversation. It is the synthesis of a multi-round whitebox
penetration test. Findings are labelled with their verification status — some
were reproduced against the real code, others are static-analysis ("by
inspection") and must be confirmed before relying on the triage.

> **Scope.** This guide covers the **Go** code in this repo (`cmd/`, `internal/`).
> The Python *proxy* is deprecated, but the Python **management/reporting API**
> is retained and authoritative for posture — it is out of *this repo's* scope
> but is flagged where it matters (M4, M5). Do not attempt to fix Python here;
> instead make the Go side defend itself against an untrusted control plane.

---

## 0. How to use this guide

1. Read Section 1 (operating constraints) **before changing any code**. Several
   "obvious" fixes are wrong for this codebase if they break passthrough or
   re-introduce a fail-open path.
2. Run Section 2 (verification baseline) first, to establish current state and
   catch anything the static review could not see (dependency CVEs especially).
3. Work the findings in Section 3 **in the order given** (priority-ordered).
   For each: make the change, then write and run the regression test that proves
   it. Use red→green TDD — write the test so it *fails* against current code
   (proving the bug is real), then patch until it passes.
4. Section 4 is cross-cutting work (a shared fix, a detection rule).
5. Sections 5–7 are out-of-scope flags, areas needing a fresh look, and what
   genuinely needs a live environment.
6. Section 8 is the "definition of done" checklist per finding.

Do not batch unrelated findings into one change. One finding → one focused
change → one test → one commit, so each can be reviewed and reverted
independently.

---

## 1. Operating constraints for THIS codebase (read first)

These are not style preferences; violating them creates security regressions.

- **It is a passthrough proxy. Never break byte-for-byte forwarding.** The proxy
  forwards the raw ClientHello to the backend unchanged; it does **not** rewrite
  SNI or any handshake bytes. Any "sanitize the input" fix protects the proxy's
  *own* downstream (logs, Redis, reporting) — it does **not** clean what the
  backend receives. So a fix that merely normalizes a malicious value must still
  allow that value to drive a **block decision**; cleaning is not protection for
  the backend.

- **Fail-open is the current design, and that is the problem, not the contract.**
  When the parser cannot understand input, the connection is currently scored
  *without* a fingerprint and usually forwarded. Do not add code that widens this.
  When you fix a parser gap, the fallback for "well-formed-looking TLS that still
  can't be fingerprinted" should be a **scored signal or a configurable
  fail-closed**, never a silent zero-JA4 pass.

- **Keep it memory-safe Go.** No `unsafe`, no cgo, no new `exec` of external
  binaries, no interpreter on untrusted input. The parser must never panic on
  malformed input (it currently meets this — keep it that way). Out-of-bounds
  must be impossible, not merely recovered.

- **The FoxIO JA4 specification is the oracle for F2.** Do not invent expected
  JA4 values. Validate against the published spec
  (`technical_details/JA4.md` in FoxIO's `ja4` repo) and its reference vectors.
  After fixing F2, any internally-collected JA4 blocklists must be **re-baselined**
  because stored values will change.

- **Respect repo conventions.** Security regression tests are named
  `pentest_<topic>_regression_test.go` next to the code. Reuse existing helpers
  rather than reinventing: `buildTLSClientHello()` (in
  `cmd/proxy/lifecycle_test.go`), `recordingBackend()` (in the existing evasion
  test), and the JA4 corpus at `fixtures/ti_feeds/ja4_fp_corpus.txt`.

- **Do not add dependencies casually.** The network-facing parse path is
  deliberately hand-rolled (no third-party library parses raw ClientHello bytes).
  Keep it that way; new deps expand the supply-chain attack surface.

- **Do not weaken what already works.** Section 3 of the full assessment lists
  controls that are already solid (PROXY-protocol handling, goroutine caps,
  metrics auth, Redis TLS, syncagent mTLS+ed25519, seccomp default-deny). Do not
  refactor these away. If a change touches them, preserve the guard IDs
  (`JA4PROXY-2026-NNNN`) and their tests.

---

## 2. Verification baseline (run before and after changes)

Establish current state and surface anything source review cannot. These need
normal repo access (the original review sandbox could not fetch dependencies, so
these are **not yet done**):

```sh
go build ./...                       # must build clean
go vet ./...                         # correctness/suspicious constructs
go test -race -count=1 ./...         # the whole suite under the race detector
govulncheck ./...                    # dependency CVEs — HIGH PRIORITY, can reveal
                                     #   an RCE in a dep that source review cannot
gosec ./...                          # security-focused static analysis
```

Treat any `govulncheck` hit on a network-facing path (go-redis, maxminddb, the
outbound HTTP clients) as urgent — that is the one place a real remote-code-exec
could hide that none of the findings below would catch. Re-run this whole block
after each finding is fixed, and keep `-race` and `govulncheck` in CI.

---

## 3. Findings, prioritized (fix in this order)

Each finding: **what's wrong**, **where**, **fix direction**, **the test that
proves it**, **status**.

### Priority 1 — defeats or bypasses the core control

#### F1 — ClientHello fragmented across TLS records bypasses JA4 + SNI controls
- **Status:** HIGH. **Verified live** (reproduced against the real parser).
- **Where:** `internal/tls/parser.go` (`ParseClientHello`), `cmd/proxy/main.go`
  (`reassembleClientHello`, `handleConn`), `internal/security/pipeline.go` (the
  `JA4 != ""` gate, ~line 338).
- **What's wrong:** the parser handles a ClientHello inside a *single* TLS
  record; `reassembleClientHello` only stitches TCP segments of *one* record. A
  ClientHello split across *multiple TLS records* (which the record layer permits
  and the backend reassembles) returns `ErrTruncated` → the proxy fails open with
  empty JA4/SNI → every JA4 check is skipped. The first record still starts with
  `0x16`, so protocol-lockdown does not stop it.
- **Fix direction:** reassemble on the **handshake-message length** (the uint24
  in the handshake header) spanning records, up to a tight byte/time ceiling. If
  a well-formed-looking handshake still cannot be assembled, make that a scored
  signal or a configurable fail-closed — not a silent pass.
- **Test:** `pentest_tls_record_fragmentation_regression_test.go`. Build one
  ClientHello with `buildTLSClientHello()`, wrap `hello[:k]` and `hello[k:]` in
  two separate `0x16` records, write record 1 / flush / pause / write record 2.
  Assert a blocklisted JA4 is **blocked** (backend receives nothing) and a benign
  one still passes through byte-for-byte. (Contrast the existing `0003` test,
  which splits within a single record.)

#### F2 — JA4 output deviates from the FoxIO spec (external blocklists silently never match)
- **Status:** HIGH. (a) and (c) **verified live**; (b) real but needs a corrected
  test; (d) minor.
- **Where:** `internal/tls/ja4.go` (`ComputeJA4`, `hashExtensions`).
- **What's wrong, per the spec:**
  - **(a)** ALPN (`0x0010`) is **not excluded** from the JA4_c extension hash
    (only SNI `0x0000` is). The spec excludes both.
  - **(b)** signature algorithms are **never folded into JA4_c**. The parser
    populates `SignatureAlgorithms` but `ComputeJA4` ignores them. The spec
    defines `JA4_c = sha256(sorted_exts "_" sorted_sigalgs)`.
  - **(c)** cipher/extension counts are **not capped at 99**; `%02d` overflows
    the fixed 2-char field (120 ciphers → an 11-char JA4_a). Also an evasion: pad
    past 99 to shift your own fingerprint.
  - **(d, minor)** the version digit only special-cases TLS 1.3; same root cause
    as F7.
- **Fix direction:** match the spec — exclude `0x0010` from the hash, append
  sorted sigalgs to JA4_c with the `_` separator, cap both counts at 99. Then
  **re-baseline internally-stored JA4 lists**.
- **Test:** `internal/tls/ja4_spec_test.go`, property tests + a reference vector:
  - **(a)** two hellos differing only by an added ALPN extension must produce the
    **same** JA4_c.
  - **(b)** *Caution:* a naive "add sigalgs ext → JA4_c changes" test gives a
    false pass, because adding the extension *type* `0x000d` changes the
    type-only hash regardless of values. The correct test holds the extension set
    constant and varies only the sigalg **values**, asserting JA4_c changes.
  - **(c)** 120 ciphers → assert the cipher-count field is `"99"` and JA4_a is 10
    chars.
  - **Reference vector:** take one real ClientHello from FoxIO's published test
    pcaps with its expected JA4 string; assert `ComputeJA4(parse(bytes))` equals
    it. Do not hand-roll both the bytes and the expected hash.

#### F7 — TLS version read from `legacy_version`, not the effective version
- **Status:** HIGH. Wiring verified.
- **Where:** `cmd/proxy/main.go:558` (`connCtx.TLSVersion = int(hello.LegacyVersion)`),
  consumed at `internal/security/pipeline.go:331` (`tlsEnforcer.Check`) and `:339`
  (`CheckJA4TLSMismatch`).
- **What's wrong:** in TLS 1.3 `legacy_version` is always `0x0303`, so (1) every
  genuine 1.3 client trips `ja4_tls_mismatch (+35)` — false positives at scale;
  (2) a client sending `legacy_version=0x0303` + `supported_versions=[0x0301]` is
  seen as 1.2 (no block) while the backend negotiates TLS 1.0 — a `BlockTLS10`
  bypass.
- **Fix direction:** add `EffectiveTLSVersion(hello)` = highest non-GREASE
  `supported_versions` entry if present, else `legacy_version`; set
  `connCtx.TLSVersion` from it. Re-evaluate whether `CheckJA4TLSMismatch` is
  meaningful in passthrough mode at all (it compares two derivations of the same
  ClientHello).
- **Test:** `internal/tls/version_test.go` + a pipeline test: a genuine 1.3 hello
  → assert **no** `ja4_tls_mismatch`; a `0x0303`+`[0x0301]` hello with
  `BlockTLS10` on → assert hard block.

#### PE-6 — the dial is replicated fleet-wide via the sync mesh, and the signing key fails open
- **Status:** HIGH. New finding; logic verified in isolation. **Tests already
  drafted** (`pe6_sync_regression_test.go`).
- **Where:** `cmd/syncagent/agent.go` (~line 290 inbound allow-list includes
  `config:dial`; ~line 583 empty `IntegrityKeyFile` → ephemeral key, no error).
- **What's wrong:** the sync channel may carry `config:dial` (the global
  enforcement level) between datacentres, bypassing the management API's
  four-eyes approval; and a node with no integrity key configured silently
  invents a throwaway key and joins the mesh instead of refusing to start.
  Together: a foothold on one node's sync trust can push `config:dial = 0` to the
  whole fleet through an unaudited channel.
- **Fix direction:** (1) remove `config:dial` from the sync allow-list — posture
  changes flow only through the audited management path; (2) make an empty
  `IntegrityKeyFile` return an error (fail closed).
- **Test:** `pe6_sync_regression_test.go` (provided). Requires a small,
  behaviour-preserving refactor first: extract the inline allow-list into
  `isReplicableKey(key string) bool` and the inline key-load into
  `loadIntegrityKey(keyFile string) (ed25519.PrivateKey, error)`. Both tests fail
  against current code and pass after the fix.

#### M1 — Redis is the real posture authority; the proxy can write its own dial
- **Status:** HIGH. Confirmed concretely.
- **Where:** the example Redis ACL at `config/proxy.yml:55` grants the proxy
  `~config:*` with `+SET +DEL`; the proxy reads the dial at `main.go:1193`.
- **What's wrong:** the management API's four-eyes approval protects the API
  path, but the *state* in Redis has only ACLs in front of it. The shipped proxy
  ACL lets a stolen proxy credential `SET config:dial 0` directly, bypassing the
  API and approval entirely.
- **Fix direction (Go side):** (1) **sign the dial value** — reuse the existing
  `0019` HMAC "critical channel" secret; the proxy rejects any dial it cannot
  attribute to the management API's key. (2) Document/ship a corrected ACL: split
  `config:*` to a separate admin ACL user the proxy does **not** hold; the proxy
  gets at most `+GET` on `config:dial` (it never writes its own dial).
- **Test:** the proxy rejects a `config:dial` written without the valid HMAC; an
  ACL conformance test asserts the proxy user is denied `SET config:dial`.

### Priority 2 — high-value hardening and confirmed real issues

#### F3 — canonicalize SNI at source (also fixes F9a, M3, and the first hop of chain C-B)
- **Status:** MEDIUM, but **highest-leverage single fix** — see Section 4, it has
  its own design.
- **Where:** `internal/tls/parser.go` (`parseSNI`), all SNI consumers
  (`cmd/proxy/main.go` decision log ~600 and Redis event ~631,
  `internal/security/sni_analyzer.go` `ExpectedHostnames[sni]` ~99).
- **What's wrong:** SNI is stored/logged/streamed raw (control chars → log
  injection; up to ~16 KB → bloat), and different consumers see different forms
  (case, trailing dot) so they disagree (F9a).
- **Fix:** see Section 4.

#### F6 — data race on `p.cfg` between `handleConn` and `reload()`
- **Status:** MEDIUM. `go test -race` will confirm deterministically.
- **Where:** `reload()` swaps `p.cfg` under `p.mu.Lock()`; `handleConn` reads
  `p.cfg` fields (`BufferSize`, `ReadTimeout`, `ProxyProtocol`,
  `ProtocolLockdownEnabled()`) **without** the lock, while `forward()`/`tarpit()`
  do take `RLock()`.
- **Fix direction:** snapshot `cfg := p.cfg` once under `RLock()` at the top of
  `handleConn` and read fields off the local, as `forward()` already does.
- **Test:** `pentest_config_reload_race_regression_test.go` run with `-race`:
  hammer `reload()` in a goroutine while many short connections enter
  `handleConn`. Fails (DATA RACE) before, passes after. Keep `-race` in CI for
  this package.

#### PE-1 — NTP monitor shells out by bare name (untrusted search path, CWE-426)
- **Status:** MEDIUM. Verified.
- **Where:** `internal/metrics/ntp.go` — `exec.Command("chronyc", ...)` /
  `exec.Command("ntpstat")` by bare name, on a timer in the proxy process.
- **What's wrong:** bare-name exec resolves via `$PATH`; anyone who can plant a
  file of that name on a writable PATH dir gets code-exec as the proxy user.
  Mitigated in prod by the read-only rootfs, but it is the cheap amplifier that
  turns any future write primitive into code-exec.
- **Fix direction:** use absolute paths (`/usr/sbin/chronyc`), or drop the
  shell-out for a local-socket / pure-Go NTP query.
- **Test:** assert the resolved command path is absolute.

#### M2 — `GetDial` does not clamp the dial range read from Redis
- **Status:** MEDIUM. Verified.
- **Where:** `internal/redis/client.go:291` — `fmt.Sscanf("%d", &dial)` returns
  the integer unbounded on a successful parse; range validation lives only in the
  CLI writer.
- **Fix direction:** clamp on read — `if dial < 0 || dial > 100 { log; return 0 }`
  — so the proxy never acts on out-of-range posture even from its own store.
  Combined with M1, this bounds dial-poisoning to at worst a monitor-mode flip.
- **Test:** `GetDial` with `"99999"`, `"-1"`, `"2147483648"` all → `0` + warn.

#### C-DNS — FCrDNS forward-resolves an attacker-controlled PTR against the internal resolver
- **Status:** MEDIUM. Confirmed on shipped defaults.
- **Where:** `internal/security/dns_enrichment.go:96` (`net.LookupHost(hostname)`
  on the attacker's PTR name); `config/proxy.yml:506` ships
  `resolver_nameservers: []` = system (internal) resolver.
- **What's wrong:** an attacker who controls the reverse DNS of their own source
  IP can make the proxy resolve any name (e.g. `db-prod.internal.corp`) against
  the internal resolver — an internal-name-existence oracle plus cache seeding.
- **Fix direction:** send enrichment DNS to a dedicated external/non-recursive
  resolver (the `resolver_nameservers` knob already exists — wire the code to use
  it and ship a non-internal default). Never forward-resolve an attacker-supplied
  name against the internal resolver.
- **Test:** mock resolver; set PTR → attacker name; assert internal names are not
  forward-resolved against the internal resolver.

#### PE-2 — webhook dispatcher SSRF (no host filter, follows redirects)
- **Status:** LOW→MEDIUM (becomes Medium if the management plane can author
  webhook URLs — chain C-B).
- **Where:** `internal/webhook/delivery.go` (`doHTTPPost`).
- **Fix direction:** parse the URL; reject `IsLoopback`/`IsLinkLocalUnicast`/
  `IsPrivate` and `169.254.169.254`; set a `CheckRedirect` that re-applies the
  filter (or disables redirects); require `https`.
- **Test:** a 302 → `169.254.169.254` and a direct `127.0.0.1` are both refused;
  table-drive `[::1]`, `10.x`, `metadata.*`.

#### F8 — tarpit overflow `allow` fails open to the backend
- **Status:** MEDIUM (config-dependent).
- **Where:** `tarpit()` — at saturation with `OverflowAction: "allow"`, overflow
  calls `p.forward(...)`, sending tarpit-classified traffic to the backend.
- **Fix direction:** ensure the shipped internet-facing default is not `allow`;
  prefer block/ban under saturation.
- **Test:** assert the shipped internet profile has `OverflowAction != "allow"`.

### Priority 3 — defense-in-depth and cleanup

#### C-A — RDAP auto-CIDR-ban (DOWNGRADED to Medium, well-mitigated)
- **Status:** MEDIUM, well-mitigated. Confirmed `config/proxy.yml:727` ships four
  guards: `min_trigger_score: 75`, `require_no_browser_traffic: true`,
  `require_known_bad_org: true`, `expansion_ban_duration: 3600` (1 hour),
  `max_expansions_per_hour: 10`.
- **Fix direction (defense-in-depth):** keep `require_known_bad_org: true` locked
  for internet-facing deploys; require multi-distinct-IP corroboration before
  expanding (one IP should never ban a subnet); maintain an allow-list of shared
  CDN/cloud egress ranges that are never auto-expanded.
- **Test:** single high-score IP → no `ban_cidr`; N corroborating IPs → ban;
  allow-listed CDN range never expands.

#### C-AMP — enrichment/webhook fan-out amplification
- **Where:** per-connection fan-out (DNS, AbuseIPDB, RDAP, webhook×M). Per-IP
  caches are bypassed by distinct attacker IPs (a botnet).
- **Fix direction:** global outbound rate limits on enrichment independent of
  inbound; negative-result caching; a per-connection enrichment budget.
- **Test:** distinct-IP flood → outbound enrichment capped; negative results
  cached.

#### M6 — metrics/health posture disclosure
- **Where:** `/metrics/summary`, `/health/deep`. Auth-wrapped, loopback-default
  (good). Residual = deployment drift.
- **Fix direction:** add a startup guard that refuses to bind these to a
  non-loopback interface without auth (mirror the `0008` treatment).
- **Test:** start with summary bound `0.0.0.0` and no auth → process refuses to
  start.

#### PE-7 — config field named `DownloadURL` is read as a file path
- **Where:** `cmd/proxy/main.go:1480` passes
  `cfg.ASNClassifier.TorExitList.DownloadURL` into `TorExitListPath`;
  `internal/security/asn_classifier.go:97` does `os.ReadFile` on it.
- **What's wrong:** harmless today (read fails, list empty, no downloader exists)
  but a trap — if someone later makes it fetch the URL and the URL is
  operator-settable, it becomes a fetch-then-parse path.
- **Fix direction:** separate the config into distinct `*_path` (read from disk)
  and `*_url` (fetched) fields; never feed a URL-typed value to a file reader.
- **Test:** a `*_path` field containing `https://...` is rejected at config load.

#### PE-3 — secrets handling / unauth escape hatches
- **Fix direction:** file-based secrets only in prod (never env); refuse to start
  if `JA4PROXY_ALLOW_UNAUTH_REDIS`/`_METRICS` is set while
  `ENVIRONMENT=production`.
- **Test:** `ENVIRONMENT=production` + `ALLOW_UNAUTH_REDIS=1` → startup fails.

#### F4 / F5 / F9b — small hardening
- **F5 (Info):** `ParseClientHello` accepts `recordLen` up to 65535; RFC 8446
  caps a record at 16384. Reject `recordLen > 16384`. **Verified.** Test: a
  record of declared length 16385 is rejected.
- **F4 (Low):** `info.Raw = data` aliases the whole read buffer for the
  connection lifetime. Copy only the parsed record (or drop `Raw` if unused).
- **F9b (Low):** metrics rate-limiter does an O(n) scan to evict when full. Use a
  ring/heap or random eviction.

---

## 4. Cross-cutting work

### The F3 SNI canonicalizer (do this once, centrally)

This single fix closes F3, F9a, M3, and severs the first hop of chain C-B. Model
it on the Perl taint/untaint idiom: extract a clean value via an **allowlist**
regex (define good; treat everything else as suspect), and grade the *kind of
difference* between raw and canonical as a risk signal.

**Go specifics that make this safe:** Go's `regexp` is RE2 (linear time, no
ReDoS), and its default `$` anchors at end-of-text, so `^[a-z0-9.-]+$` will not
match `"evil.com\n"`. **Never** add the `(?m)` flag, and check control chars
explicitly anyway (the value must be safe for non-regex consumers too).

**Do not use a single "any difference → bump" threshold** — legitimate clients
differ from canonical constantly. Normalize first (lowercase, strip one trailing
dot, accept `xn--` punycode), then grade:

| Tier | Examples | Weight |
|------|----------|--------|
| none | already canonical; absent SNI (ECH) | 0 |
| normalized | mixed-case, trailing dot, valid punycode | 0 (silent) |
| note | raw UTF-8 instead of punycode; long-but-legal (≤253) | small |
| suspicious | chars outside DNS allowlist; IP literal; length > 253 | moderate |
| malicious | CR, LF, NUL, other control bytes | heavy / **block** |

Place `CanonicalizeSNI(raw) (canonical string, sig)` in `internal/tls/`, call it
once right after `parseSNI`, store the **canonical** value into `connCtx.SNI` so
the decision log, the Redis event, and the `ExpectedHostnames` lookup all see the
same string, and feed the graded signal into the pipeline. **Remember the
passthrough constraint:** the backend still gets the raw bytes, so the
`malicious` tier must be able to drive a block, not merely normalize.

Generalizes to ALPN (also a raw attacker string). JA4 and the cipher/extension
lists do not need it (proxy-computed, fixed alphabet / numeric).

**Test:** table-driven `internal/tls/sni_canonicalize_test.go` — `example.com`
(none), `Example.COM`/`example.com.` (normalized), `xn--…` (none),
`example.com\r\nHost: evil` and `ex\x00ample.com` (malicious, canonical empty),
254-char name (suspicious), `192.0.2.1` (suspicious). Assert the canonical value
never contains `\x00\r\n`. Add an integration assertion that a CRLF SNI produces
a decision-log line with no embedded newline.

### Detection rule (build and test it regardless of code fixes)

The control-plane bypass (M1/PE-6) is best caught at runtime: **alert whenever
`config:dial` changes in Redis with no matching management-API audit entry.**
Implement via Redis keyspace notifications or an audit cross-check, ship the
alert to the SIEM, and write a test that simulates a direct `SET config:dial`
(no API event) and asserts the alert fires.

---

## 5. Out of scope for this repo, but flagged (do not fix here)

- **M5 — the management API server is not in this repo** (retained Python). It is
  the authoritative writer of `config:dial`, bans, and (per C-B) webhook URLs.
  Its authN/authZ, RBAC, CSRF posture, and input handling are unreviewed. The Go
  fixes M1 (sign the dial) and M2 (clamp on read) exist precisely so the proxy
  defends itself regardless of that service's quality — make sure they land.
- **M4 — compliance CSV export injection** lives in the Python API
  (`internal/compliance/` here is only a classifier + API client). SNI/JA4 values
  beginning with `= + - @` become live formulas in spreadsheet software. Flag for
  the Python review; the F3 canonicalizer removes the control-char vector at
  source, which helps.
- **The web UI** (stored-XSS landing point for chain C-B) — output-encode SNI/JA4
  there. Out of this repo.
- **SOAR connectors** (`deploy/integrations/xsoar`, `splunk_soar`) — verify they
  do not auto-act on attacker-influenced payload fields (the proxy populates
  these from SNI/JA4). Out of this repo's Go code.
- **Supply/deploy plane** (CI/CD, registry, base-image provenance, artifact
  signing) — separate review.

---

## 6. Areas that warrant a fresh look (not yet examined in depth)

- **Prometheus label cardinality.** If SNI/JA4/client-IP are ever used as metric
  *label values*, unbounded cardinality is a memory-exhaustion DoS. Audit the
  metrics package for attacker-controlled label values; if present, bucket or
  drop them.
- **NetBox integration** (`internal/config/netbox.go` makes outbound HTTP) —
  apply the same SSRF/trust checks as the webhook client (PE-2).
- **Crypto-correctness pass.** Confirm all secret comparisons (bearer tokens,
  HMAC) are constant-time; confirm the ed25519 signed payload in the syncagent
  covers **every** security-relevant field (M8) so a valid-but-low-trust peer
  cannot tamper an unsigned field.

---

## 7. What needs a live environment (cannot be fully done in code)

- Dynamic confirmation of F1/F2/F7 and the chains against a running proxy + Redis
  + a real dial config and JA4 blocklist (stand up the stack; fire the fragmented
  ClientHello; confirm the auto-ban writes a `ban_cidr`; watch sync propagation).
- The runtime confinement drift guard: a CI smoke test on the built image
  asserting UID 1000, read-only `/`, the exact cap list (`NET_BIND_SERVICE`
  only), and `no-new-privileges` — re-run against the real Kubernetes Pod
  `securityContext` if deployed there (that, not the Dockerfile, is what binds).
- A seccomp allow-list audit: `strace` the real workload, diff against the
  profile, strip unused syscalls (especially confirm `clone` cannot pass
  namespace flags, and that `unshare` stays absent).
- `govulncheck`/`gosec`/full `-race` (Section 2) — code-adjacent but needs deps.

---

## 8. Definition of done (per finding)

A finding is closed when **all** of:

1. The fix is in, and respects every constraint in Section 1 (especially: did not
   break passthrough, did not widen any fail-open path).
2. A regression test exists that **failed before the fix and passes after**
   (red→green), in the repo convention, and is wired into CI.
3. `go build`, `go vet`, `go test -race ./...`, `govulncheck`, and `gosec` are
   all clean (Section 2).
4. For F2: validated against a FoxIO reference vector, and internal JA4 lists
   re-baselined.
5. For control-plane fixes (M1/M2/PE-6): the proxy demonstrably refuses to act on
   posture it cannot attribute to a trusted writer / that is out of range / that
   arrived via the wrong channel.

---

### Companion documents (full detail, if available alongside this guide)

- `ja4proxy-security-assessment-consolidated.md` — full findings + the tooling
  verification round.
- `ja4proxy-privesc-assessment.md` — privilege escalation, including the deeper
  pass (PE-6/PE-7) and the documented dead ends.
- `ja4proxy-management-plane-attack-paths.md` — the control-plane trust model,
  boundary diagram, and every non-proxy input to the backend.
- `pentest_findings_regression_test.go` — runnable PoC tests for F1/F2/F5.
- `pe6_sync_regression_test.go` — the PE-6 tests.

> All findings are static-analysis + isolated-reproduction results except where
> marked "verified live." Confirm the inspection-only items against a running
> system before relying on the triage, and treat `govulncheck` as the priority
> action that could reveal something this source review structurally cannot see.

