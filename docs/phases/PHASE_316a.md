# PHASE 316a — Go TAP Capture + TCP Reassembly + Handshake Extraction

> **STATUS: PROPOSED — plan for review. No code until approved.**
> Sub-phase 1 of the TAP/SPAN series (316a–316e). This one builds the
> **foundation only**: get TLS handshakes off a mirror feed. No fingerprints, no
> Redis, no enforcement yet — those are later sub-phases.

---

## 1. Goal (plain language)

A **TAP/SPAN feed** is a copy of network traffic that a switch mirrors to a
monitoring port — the sensor sees the packets but never sits in the path, so it
can never drop or delay real traffic. This phase builds the part of a Go sensor
that:

1. reads raw packets from a mirror interface,
2. rebuilds each TCP connection's byte stream (in both directions),
3. pulls out the two interesting pieces of each TLS connection — the **ClientHello**
   (what the client sends) and the **ServerHello** (what the server answers),

and hands those upward as a small in-memory event. **Computing fingerprints from
those bytes is the *next* phase (316b).** We split it here because reliable packet
capture and TCP reassembly is hard, self-contained work that deserves its own
review independent of the fingerprint maths.

## 2. Why a separate phase / background

- The Go proxy today has only the TAP **consumer** (`internal/security/tap_consumer.go`,
  reads fingerprints other code must produce) — there is **no capture/sensor side**.
- The inline proxy's existing TLS parsing (`internal/tls/parser.go`) reads **one
  direction** off an already-terminated socket and **never sees a ServerHello**.
  A passive sensor is a different problem: it must reassemble *both* directions of
  a flow from raw mirrored packets. So this is genuinely new code, not a tweak.
- A Python sensor did this before (archived at
  `git show 5afeba26:archive/python_legacy/src/tap/{capture,reassembler}.py`) — a
  useful reference for the algorithm, **not** something to port line-for-line.

## 3. The decision this phase must make first: the capture library (ADR)

This is load-bearing — it shapes everything downstream — so it is **an ADR
written before any code**, not a runtime choice.

| Option | Pros | Cons |
|---|---|---|
| `gopacket` + libpcap | mature, rich decoders | **cgo** → libpcap link/static-build pain in containers |
| **`gopacket/afpacket` (recommended)** | pure-Go AF_PACKET (TPACKETv3), in-kernel BPF filter, no cgo, good throughput | Linux-only (fine — we ship Linux), fewer batteries than libpcap |
| hand-rolled AF_PACKET syscall | zero deps, full control | we re-implement ring buffers, BPF wiring, decode — most code, most risk |

**Proposed decision:** `gopacket/afpacket` for capture + `gopacket` decoders for
Ethernet/IP/TCP. Pure-Go (no cgo) keeps the static container build simple, and
AF_PACKET gives us a **kernel BPF filter** (essential for §6 data-minimisation).
The ADR records this with the trade-offs.

**Additional Decisions (Performance & Tooling):**
*   **Zero-Copy Decoding via `gopacket.NewDecodingLayerParser`:** Standard gopacket decoding allocates Go structures for every parsed layer. To handle 10,000+ pps with minimal garbage collector pressure, use a pre-allocated parser and pre-allocated layer variables, decoding packet headers in-place (zero-alloc on the hot path).
*   **Offline PCAP Replay Mode:** Support a `--pcap-file <path>` flag. This uses Go's pure-Go PCAP reader, bypassing raw socket bindings entirely. It allows replaying captured traffic for offline analysis, CI/CD verification, and local development without raw interface permissions.

## 4. Design / how it works

```
                       [ Live Mirror NIC ]
                               │ (promiscuous mode)
                               ▼
    [ AF_PACKET Ring Buffer (Kernel BPF Filter: tcp port 443) ] OR [ --pcap-file Reader ]
                               │
                               ▼
    [ Zero-Copy Layer Parser (gopacket.NewDecodingLayerParser) ]
                               │ (pre-allocated struct reuse)
                               ▼
    [ Bounded Bidirectional Flow Table (sync.Pool Buffer Recycler) ]
                               │
            ┌──────────────────┴──────────────────┐
     (Under 16KB & Handshake)             (Exceeds 16KB / Timeout)
            ▼                                     ▼
[ ClientHello / ServerHello bytes ]       [ Evict / Drop Stream ]
            │
            ▼
    [ HandshakeEvent Channel ]
```

1. **Capture.** Open an AF_PACKET socket on the mirror interface in promiscuous mode (or read offline via `--pcap-file`) with a **BPF filter** (e.g. `tcp port 443`) to drop non-handshake packets early in the kernel.
2. **Decode.** Parse Ethernet → IPv4/IPv6 → TCP using a zero-copy decoding layer parser. Extract 5-tuple, sequence, flags, payload, and TCP options.
3. **Reassemble (the hard part).** Track flows in a bounded table. To prevent memory exhaustion under attack, enforce a **16KB reassembly boundary** per stream (sufficient for the TLS handshake). Reassemble client and server streams concurrently, handling retransmissions and segment splits.
4. **Extract & emit.** Emit a `HandshakeEvent` once ClientHello (and ServerHello, if seen before timeout) is parsed, then evict the flow. Buffer structures are pooled using `sync.Pool` to avoid allocations.

## 5. Resource & overload model (must be explicit)

A SPAN port can carry **far more** traffic than the inline proxy sees, so the
sensor must be impossible to OOM or to turn into a Redis-flooder later:

- **Reassembly Depth Limit:** Restrict stream tracking to the first **16KB (16384 bytes)** of payload per direction. Once this boundary is reached without completing the handshake extraction, evict the flow immediately. This mitigates flood and HTTP-large-payload exhaustion.
- **Buffer Pooling via `sync.Pool`:** Allocation on the packet hot path is a major bottleneck. Maintain pools of pre-allocated byte slices (e.g., 64KB buffers) and flow-tracking struct nodes. Reassemblers pull from the pool and return them upon flow eviction.
- **Bounded flow table** with a hard **memory** cap (not just a count) and
  **LRU/idle eviction**; a configurable `max_flows` and `max_flow_buffer_bytes`.
- **Drop-tail under saturation.** If the ring or flow table is full, drop new
  flows and increment `ja4proxy_tap_packets_dropped_total` — never block capture.
- **Idle/timeout eviction** so half-open or never-completed flows can't pile up.
- The drop policy and its numbers are **documented**, and the
  `ja4proxy_tap_ring_buffer_fill_ratio` gauge is wired to the shedding rule.

## 6. Privacy & data-minimisation (a hard requirement)

Promiscuous capture of a mirror feed is, by nature, broad. We constrain it:

- **Kernel BPF filter** restricts capture to the handshake ports we fingerprint —
  not "everything".
- The sensor keeps **only the handshake/header bytes** needed for fingerprinting.
  It **never persists packet payloads** and **never logs raw packet contents**.
- No Redis writes here, but the contract is set now: downstream phases store only
  fingerprints + metadata, and fingerprint keys (`fp:ip:*`) are PII subject to
  `gdpr_delete.py` (316b wires that).

## 7. Security / privileges

- Run as a **non-root** standalone binary with **only `CAP_NET_RAW`** (systemd
  `AmbientCapabilities`/`CapabilityBoundingSet`, or Docker `cap_drop: ALL` +
  `cap_add: NET_RAW`).
- **Post-Socket Privilege Dropping:** Bind the raw AF_PACKET socket at startup under root/CAP_NET_RAW, then immediately drop all capabilities (`syscall.Setreuid` / `syscall.Setregid` to non-root user UID/GID). If capability dropping fails, exit immediately (fail closed).
- **Restrictive Redis User ACL:** The sensor only writes fingerprints and sets TTLs. Secure the Redis access layer by provisioning a custom ACL user policy specifically for the sensor in `users.acl` or `redis.conf`:
  `user tap_sensor on >my_secure_password ~fp:os:ip:* ~fp:ip:* ~fp:conn:* +set +expire -@all`
  This prevents a compromised sensor container from executing read operations, clearing whitelist rules, or modifying proxy configuration.
- Ship and load a seccomp profile (`config/seccomp_tap.json` equivalent).

## 8. Metrics (registry first)

Add to `internal/metrics` **and** `OBSERVABILITY_STANDARDS.md §1d`:
`ja4proxy_tap_packets_received_total`, `ja4proxy_tap_packets_dropped_total`,
`ja4proxy_tap_active_streams` (gauge — note: noun-last name, **not**
`_streams_active`), `ja4proxy_tap_ring_buffer_fill_ratio` (pre-computed gauge),
`ja4proxy_tap_worker_restarts_total`.

## 9. Implementation plan (in order)

1. **ADR** for the capture library (§3) — first, before code.
2. Metrics → registry + `OBSERVABILITY_STANDARDS.md`.
3. `internal/tap/capture.go` — AF_PACKET open, promisc, BPF filter, ring read. Support reading offline via pure-Go pcap library if `--pcap-file` is specified.
4. `internal/tap/decode.go` — zero-copy eth/IPv4/IPv6(+frag)/TCP decode to a normalised segment using `gopacket.NewDecodingLayerParser`.
5. `internal/tap/reassembler.go` — use `github.com/google/gopacket/tcpassembly`. Implement a custom `StreamFactory` wrapping `tcpassembly.Stream` that tracks byte length. Restrict stream tracking to 16KB per direction, evicting the flow/stream on overflow, and pool connection/stream allocations via `sync.Pool` to avoid heap allocations. Do not write a TCP reassembler from scratch.
6. `internal/tap/sensor.go` — wires capture→decode→reassemble→`HandshakeEvent` chan;
   a stub consumer that just counts/logs (replaced in 316b).
7. `cmd/ja4-tap/main.go` — standalone binary; parse `--pcap-file` / `--key-file` / `--key`, execute cap-drop + change UID/GID, and load seccomp at startup.
8. `internal/tap/watchdog.go` — per-worker restart with rapid-crash detection.
9. `config/proxy.yml` `tap:` block — **disabled by default**; document that
   interface/promisc/BPF are **restart-only** (cannot hot-reload, like the listen
   port).
10. Docs: ADR(s), `docs/runbooks/tap_mode.md` (append a Go section — don't clobber
    the existing Python TAP content), CHANGELOG, manifest `316a`, `/health`
    component entry for the sensor.

## 10. Test plan

- **Synthetic packet builder** (port the Python `SyntheticPacketBuilder`):
  helpers to emit `syn/synack/ack/clienthello/serverhello/data/fin/rst`. This is
  the backbone of every test.
- **Reassembly & Stream Limits** — in-order, **out-of-order**, retransmit/overlap, a ClientHello
  **split across several TCP segments**, IPv4 fragmentation, IPv6, and a
  server-direction ServerHello. Assert the extracted bytes are exact. Verify that stream tracking is aborted and memory freed the moment stream payload size exceeds 16KB.
- **Offline PCAP Replay Verification** — run the sensor over checked-in PCAP fixtures, asserting exact ClientHello/ServerHello byte extraction.
- **Memory Optimization Benchmark** — run the parser/reassembler benchmarks with allocation profile metrics to assert zero heap allocations on the packet-processing hot path.
- **Overload** — exceed `max_flows` / buffer cap → oldest evicted, drop metric
  increments, no OOM, no panic.
- **Privacy** — assert no payload bytes beyond the handshake are retained and the
  BPF filter rejects non-handshake ports.
- **Security** — the binary refuses to run if cap-drop fails; runs with only
  `CAP_NET_RAW`.
- **Performance** — a pps/throughput benchmark (this is a hot capture path);
  document the budget.

## 11. Acceptance criteria

- Given a synthetic (and a real `.pcap`) mirror feed, the sensor emits exact
  ClientHello and ServerHello bytes per flow, both IPv4 and IPv6, including
  segment-split and out-of-order cases.
- Bounded memory under flood (drop-tail + metrics), no OOM/panic.
- Runs non-root, `CAP_NET_RAW`-only, seccomp loaded, BPF-filtered.
- No payloads persisted/logged.
- Tests (incl. performance) pass; coverage ≥ 80%; ADR/runbook/CHANGELOG/manifest done.

## Files to Modify

| File | Change |
|------|--------|
| `docs/decisions/ADR-316a.md` | New file — capture library assessment and selection |
| `internal/metrics/metrics.go` | Register TAP metrics |
| `docs/OBSERVABILITY_STANDARDS.md` | Add TAP metrics definitions |
| `internal/tap/capture.go` | New file — AF_PACKET and PCAP read loops |
| `internal/tap/decode.go` | New file — zero-copy Ethernet/IP/TCP decoding |
| `internal/tap/reassembler.go` | New file — TCP stream reassembly and pooling using `gopacket/tcpassembly` |
| `internal/tap/sensor.go` | New file — pipeline orchestration |
| `cmd/ja4-tap/main.go` | New file — standalone sniffer entry point, privilege drop, seccomp |
| `internal/tap/watchdog.go` | New file — health watchdog |
| `config/proxy.yml` | Add `tap:` config section |
| `docs/runbooks/tap_mode.md` | Update sniffer runbook |
| `CHANGELOG.md` | Add Phase 316a changes |

## 12. Out of scope (these are later sub-phases)

- **Any fingerprint computation** (JA4 family) → 316b (OS-mismatch MVP) and 316c.
- **Any Redis write** → 316b.
- **Enforcement** (bans/iptables/BGP) → 316d. **Exporters** → 316e.

## 13. Glossary

- **SPAN/TAP/mirror** — a switch feature (or physical tap) that copies traffic to
  a monitoring port; passive, out-of-band.
- **AF_PACKET** — a Linux socket family for receiving raw link-layer frames in
  userspace, with an in-kernel ring buffer and optional BPF filter.
- **BPF filter** — a tiny in-kernel program that decides which packets reach
  userspace; lets us capture only the ports we care about.
- **TCP reassembly** — rebuilding the ordered byte stream of a connection from
  individually-arriving, possibly out-of-order, possibly retransmitted packets.
- **ClientHello / ServerHello** — the first messages of a TLS handshake, sent in
  the clear; the raw material for JA4/JA4S fingerprints.
