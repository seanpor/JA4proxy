# PHASE 316b — TAP OS-Mismatch MVP (first end-to-end value)

> **STATUS: PROPOSED — plan for review. No code until approved.**
> Sub-phase 2 of the TAP series. **Depends on 316a** (handshake events).
> This is the smallest slice that produces a *working, useful* sensor: it makes
> the existing OS-mismatch signal actually fire. Read §3 — it fixes a real
> contract bug the design review caught.

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
packets it already captures and write it to `fp:os:ip:{ip}`, so the existing
detector lights up — end to end, test-proven. It deliberately does the *minimum*
fingerprinting needed for this one signal; the full JA4 fingerprint family is
316c.

## 2. Background

- 316a hands us `HandshakeEvent{client_ip, …, tcp_options, …}` per flow.
- The consumer (`tap_consumer.go`) reads `fp:os:ip:{ip}` (a plain string) and
  compares it for **exact equality** to the OS implied by the live JA4 string
  (`ja4OSClass()` → `"windows" | "macos" | "linux" | "ios"`).

## 3. The contract bug this phase fixes (important)

The design review found that the **archived Python writer** stored values like
`"linux_5x_default"`, but the **Go consumer** compares against bare classes like
`"linux"` — so `"linux" == "linux_5x_default"` is never true and a faithful port
would write a key the consumer can never match: **a silent no-op sensor.**

We are explicitly **not** doing a faithful port. **Decision: one canonical OS-class
vocabulary, shared by both sides.**

| # | Decision | Why |
|---|---|---|
| D1 | Define a single canonical OS-class type — `windows`, `macos`, `linux`, `ios`, `android`, `other` — in one place (`internal/fingerprint/osclass.go`), and have **both** the sensor writer **and** the consumer use it. | One source of truth; the writer and reader can never drift again. The clean short form (`linux`) wins, per the "good code, not a faithful port" directive. |
| D2 | `fp:os:ip:{ip}` stores **exactly** that bare class string (e.g. `linux`). Update `docs/REDIS_SCHEMA.md` to state the value domain precisely. | Removes the encoding ambiguity that caused the bug. |
| D3 | Refactor the consumer's `ja4OSClass()` to return the shared type (behaviour unchanged, just typed). Add a round-trip test that **writes via the new sensor path and asserts `TapConsumer.GetSignal` actually returns a signal on a mismatch.** | Proves the loop is closed — the test the original code never had. |
| D4 | The sensor's passive OS class comes from the **SYN / IP-stack features** in the handshake event (TTL, TCP window, MSS, option ordering — the same inputs JA4T uses), mapped to a canonical class with a **conservative "other"/no-write default**. | We must not emit a confident wrong class for traffic we can't classify — that would create false mismatches (false positives). When unsure, write nothing. |
| D5 | **TCP Option Normalization Profile Classifier (NAT/Middlebox Evasion).** | NAT gateways and security middleboxes (e.g. F5, AWS ALB) rewrite TTLs and normalize TCP Options. To prevent false-positive mismatch alerts, detect normalized option list patterns (standardized option arrays) and classify the OS as `other` (unknown), suppressing downstream alerts. |

## 4. Safety: advisory-only, monitor-first (the core asymmetry)

This phase **does not block anyone.** The sensor only *writes a fingerprint*; the
inline pipeline turns a mismatch into a normal `RiskSignal` that is scored under
the **dial** (default 0 = monitor only). So an OS-mismatch is, by default,
observed-and-scored, never an automatic block. Active enforcement from TAP is a
later, opt-in phase (316d). State this explicitly in the runbook.

This is also why D4 insists on a conservative classifier: a false "mismatch" on a
real browser is a false positive, and false positives are the expensive error.

## 5. Design / flow

```
HandshakeEvent (from 316a)
  │
  ├─ check TCP Option ordering against Middlebox Normalization Profiles
  ├─ if normalized signature matched:
  │     └─ OSClass = "other" (unknown / bypass mismatch scoring)
  ├─ else:
  │     └─ classify passive OS from SYN/IP-stack features (TTL, Win Size, Option presence) → OSClass
  ├─ if OSClass != "other":
  │     └─ SET fp:os:ip:{client_ip} = "<OSClass>"  (TTL per schema; v4 & v6 canonical)
  └─ else:
        └─ write nothing (conservative / no confident class)

(unchanged, already in production)
inline proxy → tap_consumer.GetSignal():
     observed = fp:os:ip:{ip}            (what the sensor saw)
     claimed  = ja4OSClass(live JA4)     (what the TLS fingerprint implies)
     observed != claimed  → RiskSignal "tap_os_mismatch" (scored under the dial)
```

Writes are fire-and-forget and fail-open: a Redis error drops the fingerprint and
increments an error counter — it never blocks capture and never produces a ban.

## 6. Implementation plan (in order)

1. `internal/fingerprint/osclass.go` — the canonical `OSClass` type + parse/format
   + the JA4-prefix→class table (moved from `tap_consumer.go`), thoroughly tested.
2. Refactor `tap_consumer.go` to use it (no behaviour change; add the typed return).
3. `internal/tap/osfingerprint.go` — implement Middlebox Normalization profile checks, then classify SYN/IP-stack features → `OSClass` (defaulting to `other` on mismatch or middlebox detection). Reuse 316a's TCP-option parsing.
4. `internal/tap/store.go` — write `fp:os:ip:{ip}` (canonical v4/v6 IP, schema TTL),
   fire-and-forget, error-counter on failure.
5. Replace 316a's stub event-consumer with the classify→store path.
6. `gdpr_delete.py` — extend `_IP_KEY_PATTERNS` to cover `fp:os:ip:{ip}` /
   `fp:ip:{ip}` so erasure reaches fingerprint PII (it currently does not).
7. Metric: `ja4proxy_tap_fingerprints_written_total{result}` (+ registry/doc).
8. Docs: REDIS_SCHEMA (`fp:os:ip` value domain), runbook (advisory-only),
   CHANGELOG, manifest `316b`.

## 7. Test plan

- **OS-class unit tests** — the canonical mapping for each class; the conservative
  unknown default; round-trips parse↔format.
- **Middlebox Evasion Normalization Test** — replay packets with normalized TCP Option arrays (e.g. standard F5/AWS option structures) or rewritten TTLs, and verify they are classified as `other` (unknown), ensuring no false mismatch alerts.
- **Consumer round-trip (the key test)** — write `fp:os:ip` via the sensor store
  with a class that *disagrees* with a crafted JA4 → assert `TapConsumer.GetSignal`
  returns the mismatch signal; write an *agreeing* class → assert no signal. This
  is the proof the loop is closed (D3).
- **FP-rate against Tranco top-10k (mandatory, CLAUDE.md).** Replay legitimate
  browser handshakes for `tests/fp_corpus/data/tranco_top_10k.txt`-style traffic
  and assert the sensor produces **zero** false OS-mismatches (or below an agreed
  threshold). A sensor that drives scoring must prove it doesn't mislabel real
  browsers.
- **IPv6** — `fp:os:ip:{v6}` stored in canonical form; mismatch fires for v6.
- **Chaos** — Redis down → fingerprint dropped, error counter up, no panic, capture
  continues; unknown-OS traffic → no key written.

## 8. Acceptance criteria

- The 316a sensor writes `fp:os:ip:{ip}` as a canonical bare OS class (v4 & v6).
- A genuine OS mismatch makes `tap_consumer.GetSignal` fire **(test-proven)**;
  agreement produces no signal.
- FP rate against the Tranco corpus is 0 (or ≤ agreed threshold).
- No enforcement: a mismatch is scored under the dial, never an automatic block.
- `gdpr_delete.py` erases `fp:os:ip`/`fp:ip` keys.
- Tests pass; coverage ≥ 80%; REDIS_SCHEMA/runbook/CHANGELOG/manifest updated.

## Files to Modify

| File | Change |
|------|--------|
| `internal/fingerprint/osclass.go` | New file — canonical OSClass type and parsing helper |
| `internal/security/tap_consumer.go` | Refactor to use the shared, canonical `OSClass` type |
| `internal/tap/osfingerprint.go` | New file — OS classification from packet TCP options and middlebox checks |
| `internal/tap/store.go` | New file — Redis write layer for `fp:os:ip:{ip}` |
| `internal/tap/sensor.go` | Replace stub consumer with classification and store pipeline |
| `scripts/gdpr_delete.py` | Add `fp:os:ip:*` and `fp:ip:*` to IP patterns for deletion |
| `internal/metrics/metrics.go` | Register sensor fingerprint metrics |
| `docs/OBSERVABILITY_STANDARDS.md` | Add sensor metrics definitions |
| `docs/REDIS_SCHEMA.md` | Document `fp:os:ip:{ip}` values precisely |
| `docs/runbooks/tap_mode.md` | Document advisory-only scoring runbook |
| `CHANGELOG.md` | Add Phase 316b changes |

## 9. Out of scope

- The full JA4 fingerprint family (JA4S/JA4T/JA4H/…) and the other `fp:*` keys → 316c.
- TAP-originated bans / iptables / BGP enforcement → 316d. Exporters → 316e.
