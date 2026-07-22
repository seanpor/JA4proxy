# PHASE 316b — TAP OS-Mismatch MVP (first end-to-end value)

> **STATUS: APPROVED (post-review) — implementation in progress.**
> Sub-phase 2 of the TAP series. **Depends on 316a** (handshake events).
> This is the smallest slice that produces a *working, useful* sensor: it makes
> the existing OS-mismatch signal actually fire.
>
> **Revised after a critical design review (2026-06-16).** The first draft assumed
> 316a's `HandshakeEvent` already carried TCP/IP-stack features — it does not (it
> carries only handshake bytes + the 5-tuple). The revision adds an explicit
> **Step 0** to extend the 316a capture path, descopes a speculative middlebox
> signature DB (former D5), drops the dead `android`/`other` enum values, and adds
> the security/PII items the review surfaced. See §3 and §10.

---

## 1. Goal (plain language)

The inline proxy already has a dormant detector for a classic evasion: a
connection whose **TLS fingerprint** claims one operating system while its
**network stack** looks like another (e.g. a TLS fingerprint that says
"Chrome-on-Windows" arriving from a TCP/IP stack that looks like Linux — typical
of a spoofing tool or middlebox). That detector lives in
`internal/security/tap_consumer.go` and reads a Redis key `fp:os:ip:{ip}` that is
supposed to hold **the OS the passive sensor actually observed**. Nothing writes
that key today, so the detector never fires.

This phase makes the 316a sensor compute a **passive OS classification** from the
packets it captures and write it to `fp:os:ip:{ip}`, so the existing detector
lights up — end to end, test-proven. It deliberately does the *minimum*
fingerprinting needed for this one signal; the full JA4 fingerprint family is
316c.

## 2. Background — what 316a actually gives us (read this; the first draft got it wrong)

316a emits, per TLS connection, a `HandshakeEvent` containing **only**:

```go
ClientIP, ServerIP string
ClientPort, ServerPort uint16
ClientHello, ServerHello []byte   // handshake-record-defragmented TLS messages
FirstSeen time.Time
```

There are **no TCP options, no TTL, no window, no MSS** in the event, and there
is no TCP-option parsing anywhere in 316a. Passive OS classification needs those
SYN/IP-stack features. Where they live in the 316a pipeline:

- **SYN TCP window + options + MSS + window-scale** — available in
  `streamFactory.New(netFlow, tcpFlow, tcp *layers.TCP, ac)`: that `tcp` layer is
  the connection's first observed packet (the SYN on a complete capture). 316a
  currently ignores it.
- **IP TTL** — lives in the IP layer, which `reassembly` does **not** pass to any
  stream callback. It must be plumbed: `decode()` already decodes `ip4`/`ip6`;
  carry the observed TTL into `assemblerCtx` (today it holds only `ci`) so `New`
  can read it off the context.
- **No SYN observed** (capture started mid-connection on a SPAN port) → we have
  no stack features → classify `Unknown` → **write nothing**. This is the common,
  correct conservative path.

The consumer (`tap_consumer.go`) reads `fp:os:ip:{ip}` (a plain string) and
compares it for **exact equality** to the OS implied by the live JA4 string
(`ja4OSClass()`).

## 3. Decisions (post-review)

| # | Decision | Why |
|---|---|---|
| D1 | **One canonical OS-class type** — `windows`, `macos`, `linux`, `ios`, plus a distinct zero-value `Unknown` — defined once in `internal/fingerprint/osclass.go` and used by **both** the sensor writer **and** the consumer. | One source of truth; writer and reader can never drift again. The clean short form (`linux`) wins, per the "good code, not a faithful port" directive. |
| D2 | `fp:os:ip:{ip}` stores **exactly** the bare class string (e.g. `linux`), TTL **24h** (matching the value `tap_consumer.go` already documents). `Unknown` is **never written**. Update `docs/reference/REDIS_SCHEMA.md` to pin the value domain and TTL. | Removes the encoding ambiguity that caused the original silent-no-op bug; matches the consumer's freshness assumption. |
| D3 | Refactor the consumer's `ja4OSClass()` to return the shared `OSClass` (behaviour unchanged; unknown JA4 prefix → `Unknown` → no signal, fail-open preserved). Add the **closed-loop round-trip test**: write via the new sensor store, assert `TapConsumer.GetSignal` returns a signal on mismatch and nothing on agreement. | Proves the loop is closed — the test the original code never had. |
| D4 | The passive OS class is derived from **SYN/IP-stack features** (initial-TTL guess, SYN window, MSS, option presence/order — the inputs JA4T uses), mapped to a canonical class with a **conservative `Unknown` default**: anything that does not match a clean, high-confidence OS profile → `Unknown` → no write. | We must not emit a confident wrong class — that creates false mismatches (false positives), the expensive error. **When unsure, write nothing.** |
| D5 | **No separate middlebox-signature classifier (descoped from the first draft).** Middlebox/NAT-normalized stacks (rewritten TTL, normalized option arrays) simply fail to match any clean OS profile and fall through to `Unknown` → no write. An explicit F5/AWS-ALB signature table is deferred to a later phase. | A speculative signature DB is more work than the classifier, has no fixed public reference, and adds its own FP/maintenance risk. The conservative default already covers the case safely. |
| D6 | **`android` and a generic `other` class are NOT in the MVP vocabulary.** | Android is passively indistinguishable from Linux (it *is* Linux) and has no `ja4OSClass` mapping — a dead value that can only manufacture false mismatches. `other` is replaced by the precise `Unknown` (never written, never compared). |

## 4. Safety: advisory-only, monitor-first (the core asymmetry)

This phase **does not block anyone.** The sensor only *writes a fingerprint*; the
inline pipeline turns a mismatch into a normal `RiskSignal` scored under the
**dial** (default 0 = monitor only). An OS-mismatch is, by default,
observed-and-scored, never an automatic block. Active enforcement from TAP is a
later, opt-in phase (316d). Stated explicitly in the runbook.

Two inherent false-positive sources this phase must own (both reinforce
advisory-only + the conservative default + the zero-FP gate):

1. **Imprecise passive fingerprinting.** TTL is observed post-hop; window/MSS are
   perturbed by window-scaling, VPNs, and tunnels. → conservative `Unknown`
   default (D4).
2. **CGNAT / shared-IP last-writer-wins.** `fp:os:ip:{ip}` is keyed by client IP;
   many users behind one CGNAT/mobile IP can flap the stored OS, so a Linux box
   could stamp `linux` onto an IP a Windows user then connects from → a false
   mismatch. This is pre-existing design debt (Phase 20/203) that 316b *activates*;
   it is documented in the runbook as a known limitation and a reason the signal
   stays advisory.

## 5. Design / flow

```
SYN packet (first packet of connection)
  └─ 316a streamFactory.New captures: SYN window, MSS, window-scale,
     TCP option presence/order; assemblerCtx carries IP TTL
        │
ClientHello/ServerHello reassembled (316a, unchanged)
        │
HandshakeEvent (316a, EXTENDED in Step 0 to carry StackFeatures)
        │
  ├─ classify StackFeatures → OSClass         (internal/tap/osfingerprint.go)
  │     conservative: no SYN / ambiguous / normalized → Unknown
  ├─ if OSClass == Unknown:  write nothing     (fire-and-forget, no key)
  └─ else: SET fp:os:ip:{client_ip} = "<class>"  TTL 24h  (v4 & v6 canonical)
                                                 (internal/tap/store.go)

(unchanged, already in production)
inline proxy → tap_consumer.GetSignal():
     observed = fp:os:ip:{ip}            (what the sensor saw)
     claimed  = ja4OSClass(live JA4)     (what the TLS fingerprint implies)
     both concrete AND observed != claimed → RiskSignal "tap_os_mismatch"
```

Writes run off the capture goroutine and are **fire-and-forget / fail-open**: a
Redis error drops the fingerprint and increments an error counter — it never
blocks capture and never produces a ban. A full event channel already drops in
316a, so a slow Redis degrades to dropped fingerprints, never to stalled capture.

## 6. Implementation plan (in order)

**Step 0 — extend the 316a capture path (the prerequisite the first draft missed):**

0a. `internal/tap/events.go` — add a `StackFeatures` struct to `HandshakeEvent`:
    `{ TTL uint8; SYNWindow uint16; MSS uint16; WindowScale uint8; OptionOrder []layers.TCPOptionKind; HasSYN bool }`. `HasSYN=false` when the SYN was not observed.
0b. `internal/tap/decode.go` / `sensor.go` — capture the IP TTL in `decode()` and
    carry it on `assemblerCtx` so it is available when the stream is created.
0c. `internal/tap/reassembler.go` — in `streamFactory.New`, parse the SYN's TCP
    options (MSS, window scale, SACK-permitted, timestamps, NOP order) and window
    from the `*layers.TCP`, plus TTL from the context; store on `tlsStream` and copy
    into the emitted `HandshakeEvent`. Only the **first** packet's features are
    used (the SYN); ignore later packets. Never panic on malformed options.

**Step 1 — the signal:**

1. `internal/fingerprint/osclass.go` — canonical `OSClass` type (`Unknown` zero
   value + `Windows/macOS/Linux/iOS`), `Parse`/`String`, and the
   JA4-prefix→class table (moved verbatim from `tap_consumer.go`). Thoroughly tested.
2. Refactor `tap_consumer.go` to use it: `ja4OSClass` returns `OSClass`; comparison
   only fires when **both** observed and claimed are concrete (neither `Unknown`).
3. `internal/tap/osfingerprint.go` — `Classify(StackFeatures) OSClass`: high-confidence
   profiles only (e.g. TTL≈64 + Linux-typical window/MSS/option order → `Linux`;
   TTL≈128 + Windows-typical → `Windows`; TTL≈64 + macOS/iOS option order → `macOS`/`iOS`),
   everything else → `Unknown`. No middlebox signature DB (D5).
4. `internal/tap/store.go` — `WriteOSClass(ctx, ip, class)`: canonical v4/v6 IP,
   `SET fp:os:ip:{ip} <class> EX 86400`, fire-and-forget, error counter on failure.
   Skips entirely when class is `Unknown`.
5. `cmd/ja4-tap/main.go` — wire the event loop to `Classify → WriteOSClass` (behind a
   `--redis-url` flag; absent → classify-and-log only, no writes, so offline pcap
   replay still works without Redis).
6. `scripts/gdpr_delete.py` — extend `_IP_KEY_PATTERNS` with `fp:os:ip:*` and
   `fp:ip:*` so erasure reaches fingerprint PII.
7. Metric `ja4proxy_tap_fingerprints_written_total{result}` (`written|skipped_unknown|error`)
   on the sensor's own registry (`internal/tap/metrics.go`), + observability doc.
8. Docs: REDIS_SCHEMA (`fp:os:ip` value domain + 24h TTL), runbook (advisory-only,
   the two FP sources, least-priv Redis ACL), CHANGELOG fragment, manifest `316b`.

## 7. Test plan

- **Step 0 capture tests** — a synthetic SYN with known TTL/window/MSS/options flows
  through the sensor and the emitted `HandshakeEvent.StackFeatures` reflects them;
  capture-without-SYN (mid-stream) yields `HasSYN=false`; malformed options never panic.
- **OS-class unit tests** — canonical mapping per class; conservative `Unknown` default;
  `Parse`↔`String` round-trips; `Unknown` is never written.
- **Classifier tests** — clean Linux/Windows/macOS/iOS SYN profiles classify correctly;
  ambiguous / normalized / TTL-rewritten profiles → `Unknown` (this is the
  former-D5 middlebox case, now covered by the conservative default).
- **Consumer round-trip (the key test, D3)** — write `fp:os:ip` via the sensor store
  with a class that *disagrees* with a crafted JA4 → assert `TapConsumer.GetSignal`
  returns the mismatch; write an *agreeing* class → assert no signal; write `Unknown`
  → assert nothing written and no signal.
- **FP-rate against a Tranco-style browser corpus (mandatory, CLAUDE.md)** — replay
  legitimate browser handshakes and assert the sensor produces **zero** false
  OS-mismatches. A sensor that drives scoring must prove it doesn't mislabel real
  browsers. Conservative classifier → expect many `Unknown` (no write); that is a pass.
- **IPv6** — `fp:os:ip:{v6}` stored canonical; mismatch fires for v6.
- **Chaos** — Redis down → fingerprint dropped, error counter up, no panic, capture
  continues; `Unknown` traffic → no key written; slow Redis → dropped fingerprints,
  capture never stalls.

## 8. Acceptance criteria

- 316a's capture path is extended to carry SYN/IP-stack features (Step 0), test-proven.
- The sensor writes `fp:os:ip:{ip}` as a canonical bare OS class (v4 & v6), 24h TTL,
  and **never** writes `Unknown`.
- A genuine OS mismatch makes `tap_consumer.GetSignal` fire **(round-trip test)**;
  agreement and `Unknown` produce no signal.
- FP rate against the browser corpus is 0.
- No enforcement: a mismatch is scored under the dial, never an automatic block.
- `gdpr_delete.py` erases `fp:os:ip`/`fp:ip` keys.
- Tests pass; coverage ≥ 80%; REDIS_SCHEMA / runbook / observability / CHANGELOG
  fragment / manifest updated.

## Files to Modify

| File | Change |
|------|--------|
| `internal/tap/events.go` | **Step 0** — add `StackFeatures` to `HandshakeEvent` |
| `internal/tap/decode.go` | **Step 0** — expose observed IP TTL |
| `internal/tap/sensor.go` | **Step 0** — carry TTL on `assemblerCtx` |
| `internal/tap/reassembler.go` | **Step 0** — capture SYN window/MSS/options in `New`; copy into event |
| `internal/fingerprint/osclass.go` | New — canonical `OSClass` type + JA4-prefix table |
| `internal/security/tap_consumer.go` | Refactor to the shared `OSClass`; compare only concrete classes |
| `internal/tap/osfingerprint.go` | New — `Classify(StackFeatures) OSClass`, conservative default |
| `internal/tap/store.go` | New — fire-and-forget `fp:os:ip:{ip}` writer (skips `Unknown`) |
| `internal/tap/metrics.go` | New `ja4proxy_tap_fingerprints_written_total{result}` |
| `cmd/ja4-tap/main.go` | Wire classify→store behind `--redis-url` (absent → log-only) |
| `scripts/gdpr_delete.py` | Add `fp:os:ip:*` and `fp:ip:*` to IP patterns |
| `docs/reference/OBSERVABILITY_STANDARDS.md` | Add sensor fingerprint metric |
| `docs/reference/REDIS_SCHEMA.md` | Pin `fp:os:ip:{ip}` value domain + 24h TTL |
| `docs/runbooks/tap_mode.md` | Advisory-only scoring; two FP sources; least-priv Redis ACL |
| `docs/fragments/phase-316b-*.md` | CHANGELOG news fragment |
| `docs/phases/manifest.yaml` | Mark 316b status |

## 9. Out of scope

- The full JA4 fingerprint family (JA4S/JA4T/JA4H/…) and the other `fp:*` keys → 316c.
- An explicit middlebox/NAT signature database (former D5) → later phase.
- TAP-originated bans / iptables / BGP enforcement → 316d. Exporters → 316e.

## 10. Review changelog (what changed from the first draft)

- **Added Step 0**: extend 316a's `HandshakeEvent` + capture path to carry
  SYN/IP-stack features. The first draft assumed these already existed (they do
  not) — without Step 0 the phase is unbuildable.
- **Descoped former D5** (middlebox-signature classifier) to the conservative
  `Unknown` default; explicit signatures deferred.
- **Dropped `android` and generic `other`** from the enum; added a precise
  `Unknown` zero value that is never written and never compared.
- **Pinned the key TTL to 24h** to match the consumer's documented assumption.
- **Added** the CGNAT/shared-IP FP limitation and the least-priv Redis ACL
  (the tap binary now needs `fp:*` write access) to the safety/runbook scope.
