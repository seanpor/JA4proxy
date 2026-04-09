# Phase 200 — Independent Security Architect Review

**Reviewer:** Cyber-Architect (independent of implementation)
**Date:** 2026-04-09
**Scope:** Go PROXY protocol trust check + v2 parser (P200a–P200c)

---

## Findings Summary

| ID | Severity | Status | Description |
|---|---|---|---|
| A-001 | INFO | Accepted | UDP family families (0x12/0x22) silently rejected |
| A-002 | LOW | Noted | v1 parser accepts UDP4/UDP6 protocol types |

No MEDIUM or above findings. **Implementation approved for production deployment.**

---

## A-001: UDP Family Silently Rejected (INFO — Accepted)

**Observation:** The v2 parser only handles `0x11` (TCP/IPv4) and `0x21` (TCP/IPv6).
UDP families (`0x12`, `0x22`) fall through to `default:` and return `("", false)`.

**Risk assessment:** This is a TLS-aware proxy that only handles TCP connections.
UDP PROXY headers are nonsensical in this context. Silently rejecting them and
falling back to the socket IP is the correct behavior.

**Verdict:** Accepted as correct. No change needed.

---

## A-002: v1 Parser Accepts UDP4/UDP6 (LOW — Noted)

**Observation:** The v1 parser (`ReadProxyProtocol`) does not validate the protocol
type — it accepts `PROXY UDP4 1.2.3.4 ...` and extracts the IP. The v2 parser
explicitly rejects UDP family.

**Risk assessment:** This is a behavioral inconsistency between v1 and v2 parsers,
but it has no security impact. The IP field is in the same position regardless of
protocol type. The trust check gates both parsers identically. Since this is a
TLS proxy on TCP connections, a UDP PROXY header from a trusted upstream would
be an operational misconfiguration, not an attack vector.

**Verdict:** Noted for future cleanup. No immediate change required.

---

## Positive Security Attributes

1. **Fail-open design:** Every error path (nil config, disabled trust, empty CIDRs,
   invalid IP, malformed CIDR, parse failure, trust failure) defaults to using the
   socket IP. This is correct for the core asymmetry (FP >> FN).

2. **Buffer bounds safety:** The v2 parser validates `len(buf) < v2MinHeaderSize`
   before any slice access, and `addrLen > 256 || len(buf) < v2MinHeaderSize+addrLen`
   before reading addresses. No `binary.Read` on untrusted data. No OOB possible.

3. **No panic surface:** Both parsers and the trust check return `("", false)` on
   any malformed input. The fuzz test corpus (adversarial bytes, empty buffers,
   repeated 0xFF) confirms no panic paths.

4. **Trust check on socket IP, not header IP:** The critical security control —
   `IsTrustedProxySource(socketIP, cfg)` — checks the TCP peer's real IP, not the
   IP claimed in the PROXY header. This is the correct enforcement point.

5. **Version gate ordering:** v2 is tried before v1. Since v2's 12-byte signature
   is binary and v1's `PROXY ` prefix is ASCII text, there's no false-positive risk
   of v2 matching on v1 data or vice versa. The ordering is correct (modern HAProxy
   defaults to v2).

6. **LOCAL command handling:** v2 LOCAL command (connection originated on the proxy
   itself) returns `("", false)` — no IP extracted, socket IP used. Correct.

---

## Threat Model Verification

| Threat | Mitigation | Verified |
|---|---|---|
| Attacker sends `PROXY TCP4 8.8.8.8 ...` | Trust check rejects (socket IP not in CIDR) | ✅ A-005 adversarial test |
| Attacker sends v2 header with spoofed IP | Trust check gates before parsing | ✅ `TestAdversarial_SpoofedPROXYFromUntrustedSource` |
| Malformed v2 header causes panic | Length checks before every slice access | ✅ `TestReadProxyProtocolV2_DoesNotPanic` |
| Oversized `addr_len` causes OOB read | `addrLen > 256` guard + buffer length check | ✅ `TestReadProxyProtocolV2_OversizedAddrLen` |
| Empty config trusts all IPs | `enabled: false` → `false`; empty CIDRs → `false` | ✅ `TestIsTrustedProxySource_DefaultConfig` |
| v1 header on TLS ClientHello data | `ReadProxyProtocol` checks `PROXY ` prefix; TLS bytes won't match | ✅ `TestProxyProtocol_NotProxyHeader_ReturnsFalse` |
| v2 signature in random binary data | Full 12-byte signature check + version nibble validation | ✅ `TestReadProxyProtocolV2_WrongSignature` |

---

## Parity with Python

| Aspect | Python (`proxy.py`) | Go (this phase) | Match |
|---|---|---|---|
| Trust check function | `_is_trusted_proxy_source(ip)` | `IsTrustedProxySource(ip, cfg)` | ✅ |
| Config key | `proxy.upstream_trust` | `ProxyConfig.UpstreamTrust` | ✅ |
| enabled check | `if not trust_cfg.get("enabled")` | `if !trust.Enabled` | ✅ |
| Empty CIDRs check | `if not trusted_cidrs` | `if len(trust.TrustedCIDRs) == 0` | ✅ |
| IP parsing | `ipaddress.ip_address(ip)` | `net.ParseIP(ip)` | ✅ |
| CIDR matching | `addr in ipaddress.ip_network(cidr)` | `ipNet.Contains(addr)` | ✅ |
| Malformed CIDR | `except (ValueError, TypeError): pass` | `if err != nil: continue` | ✅ |
| v1 parser | `_parse_proxy_protocol` | `ReadProxyProtocol` | ✅ |
| v2 parser | `_parse_proxy_protocol` v2 branch | `ReadProxyProtocolV2WithLength` | ✅ |

---

## Approval

**Implementation is approved for production.** All success criteria from the phase
mandate are met:

- ✅ `IsTrustedProxySource()` correctly accepts/rejects IPs against configured CIDRs
- ✅ `ReadProxyProtocolV2()` extracts correct client IP for both IPv4 and IPv6
- ✅ `ReadProxyProtocolV2()` safely rejects malformed v2 headers (no panic, no OOB)
- ✅ Untrusted source sending PROXY header is NOT trusted — socket IP used instead
- ✅ Both v1 and v2 parsers gated by the same trust check
- ✅ All unit tests pass (30 in `internal/proxy`, 9 in `cmd/proxy`)
- ✅ Adversarial tests confirm untrusted PROXY spoof is rejected
- ✅ `config/proxy.yml` documents `proxy.upstream_trust` section
- ✅ 29 new tests with comprehensive coverage

**Signed:** Cyber-Architect Review, 2026-04-09
