# Security Signal Implementation Review

**Date:** 2026-04-08  
**Scope:** All signal modules in `src/security/` and `internal/security/`, JA4 fingerprinting, score registry  
**Severity scale:** CRITICAL → HIGH → MEDIUM → LOW

---

## Findings Summary

| # | Severity | Finding | Impact |
|---|----------|---------|--------|
| 1 | CRITICAL | Signal score drift — 5 signals differ between code and registry | Wrong scores, broken parity |
| 2 | CRITICAL | Dead code in `asn_classifier.py` — unreachable return | Code hygiene concern |
| 3 | HIGH | Python/Go DGA detection algorithms fundamentally different | Parity break, evasion possible |
| 4 | HIGH | `ja4_tls_mismatch` missing from Go entirely | Detection gap |
| 5 | HIGH | `tcp_analyzer.py` uses `__import__("random")` for production logic | Non-deterministic, meaningless signals |
| 6 | HIGH | Broad `except Exception` + f-string logging in 8+ files | Standards violation, potential data exposure |
| 7 | MEDIUM | `asn_classifier.py` module-level `RISK_SCORES` diverges from config | Dead code, developer confusion |
| 8 | MEDIUM | `_check_ja4t_mismatch` OS mapping is nonsensical | Signal effectively non-functional |
| 9 | MEDIUM | `return_visitor` signal uses score -1 instead of -20 | Wrong score value |
| 10 | MEDIUM | Go weak cipher suite coverage 13 vs Python's 37+ | Detection gap |
| 11 | MEDIUM | `check-signal-scores.py` regex cannot handle multi-line RiskSignal | Linter blind spot |
| 12 | LOW | VirusTotal quota tracking not multi-instance safe | Undercounting under load |
| 13 | LOW | `blocklists.py` silently drops malformed CIDRs | Silent degradation |
| 14 | LOW | Go `JA4T` implementation is a stub (always returns `""`) | Detection gap |

---

## Finding 1 — CRITICAL: Signal Score Drift

**5 signals** diverge between Go code and `config/signal_scores.yml`:

| Signal | Go Value | Registry Value | File |
|--------|----------|---------------|------|
| `tls_version` | 40 | 10 | `internal/security/tls_enforcer.go:73,87` |
| `weak_cipher` | 20 | 35 | `internal/security/tls_enforcer.go:120` |
| `high_concurrency` | 25 | 40 | `internal/security/tcp_analyzer.go:117` |
| `moderate_concurrency` | 10 | 25 | `internal/security/tcp_analyzer.go:127` |
| `return_visitor` (Python) | -1 | -20 | `src/security/tcp_analyzer.py:340` |

**Impact:** Go proxy produces materially different composite scores than Python for identical traffic. A connection scoring 75 in Python could score 55 in Go, causing different actions (block vs. tarpit). This breaks the parity requirement.

**Remediation:** Update all Go signal scores to match the registry. Run `make check-scores` — must exit 0.

---

## Finding 2 — CRITICAL: Dead Code in `asn_classifier.py`

File: `src/security/asn_classifier.py`, lines 341-342:

```python
return ASNClassification(asn=0, asn_str="AS0", org_name="", category="unknown")

return ASNClassification(asn=0, asn_str="AS0", org_name="", category="unknown")
```

Two consecutive identical return statements — the second is unreachable. Suggests a merge conflict or copy-paste error was not cleaned up.

---

## Finding 3 — HIGH: DGA Algorithm Mismatch (Python vs Go)

The Python `dga_score()` (`src/security/sni_analyzer.py`) and Go `dgaConfidence()` (`internal/security/sni_analyzer.go`) are **not algorithmically equivalent**:

| Heuristic | Python | Go |
|-----------|--------|-----|
| Entropy threshold | `ent >= 3.8` → up to 0.40 | `entropy > 3.5` → 0.35; `> 4.0` → 0.15 |
| Vowel analysis | No vowels = +0.30; ratio > 5:1 = +0.20 | vowel ratio < 0.10 = +0.30 |
| Label length | >= 20 = +0.20; >= 16 = +0.10 | > 15 chars = +0.15 |
| Digit detection | `\d{4,}` consecutive = +0.10 | digit ratio > 30% = +0.20 |
| Consonant runs | Not checked | max consecutive >= 4 = +0.20 |

Additionally, Python's `_get_primary_label()` strips common prefixes (`www`, `api`, `cdn`) before analysis, while Go always uses the leftmost label. A hostname like `www.xjkqwzlmnp.com` is analyzed as `xjkqwzlmnp` in Python (flagged) but as `www` in Go (too short, returns 0.0).

**Remediation:** Port the Python algorithm exactly to Go, or document the divergence as a known parity gap.

---

## Finding 4 — HIGH: `ja4_tls_mismatch` Missing from Go

The Python `tls_enforcer.py` produces a `ja4_tls_mismatch` signal (score 35) when the JA4 fingerprint's declared TLS version doesn't match the actual connection. The Go proxy has **no implementation** of this signal — grep for `ja4_tls_mismatch` in `internal/security/` returns zero results.

**Remediation:** Implement the signal in Go or document as a known gap.

---

## Finding 5 — HIGH: `tcp_analyzer.py` Uses `random()` for Production Logic

File: `src/security/tcp_analyzer.py`, lines 158-161:

```python
is_resumption = (
    "chrome" in ctx.ja4.lower() and __import__("random").random() < 0.9
)
```

And line 192:
```python
lifespan_ms = ctx.connection_lifespan_ms or __import__("random").randint(100, 2000)
```

These are simulation/stub code that reached production. Session resumption is determined by a 90% coin flip based on whether "chrome" appears in the JA4 string, not by inspecting the actual session_ticket extension. Connection lifespan uses a random value when the context lacks one.

**Remediation:** Implement proper session ticket inspection, or disable these signals until they produce real data.

---

## Finding 6 — HIGH: Broad `except Exception` + f-string Logging

AGENTS.md mandates: "Never use broad `except Exception:` blocks" and "Never use f-strings in logging." The following files violate both:

| File | Lines |
|------|-------|
| `src/security/attribution.py` | 166 |
| `src/security/behavioral.py` | 96, 130, 153 |
| `src/security/greynoise.py` | 185, 213 |
| `src/security/virustotal.py` | 204, 214, 241, 361, 376 |
| `src/security/alienvault.py` | 168, 195 |
| `src/security/misp.py` | 180, 207 |
| `src/security/threatfox.py` | 176, 203 |

**Remediation:** Replace broad exception handlers with specific types. Convert f-strings to lazy `%` formatting in logging calls.

---

## Finding 7 — MEDIUM: `asn_classifier.py` Dead `RISK_SCORES` Dict

File: `src/security/asn_classifier.py`, lines 37-43:

```python
RISK_SCORES = {
    "vpn": 10,  # Registry says 25
    ...
}
```

This module-level dict is unused (the `__init__` method reads from config). However, its values differ from the registry, which could mislead developers.

**Remediation:** Remove the dead dict or annotate it clearly as unused reference.

---

## Finding 8 — MEDIUM: JA4T OS Mapping Is Non-Functional

File: `src/security/tcp_analyzer.py`, lines 106-120:

```python
ja4_os_map = {
    "chrome": "windows",
    "firefox": "windows",
    "safari": "macos",
}
```

Chrome and Firefox run on every platform. The TTL-based JA4T OS map checks for `"64_"` and `"128_"` prefixes, which only work for exact TTL values — not the common 63 (Linux through one hop) or 127 variations.

**Remediation:** Either implement a proper OS fingerprinting heuristic or disable this signal.

---

## Finding 9 — MEDIUM: `return_visitor` Score Mismatch

Python: hardcoded `-1` (`src/security/tcp_analyzer.py:340`).  
Go: correctly uses `-20`.  
Registry: declares `-20`.

The Python signal always returns -1 regardless of the `score_reduction_pct` config value (default 20).

**Remediation:** Use the config value or registry value, not a hardcoded constant.

---

## Finding 10 — MEDIUM: Go Weak Cipher Suite Coverage Gap

Go `weakCipherSet` contains **13** suites. Python `WEAK_CIPHERS` contains **37+**, including NULL, EXPORT, DH_anon, ECDH_anon, and non-PFS RSA ciphers. The Go proxy would miss many weak cipher detections.

**Remediation:** Sync the Go cipher suite list with Python's.

---

## Finding 11 — MEDIUM: Score Checker Regex Blind Spot

`check-signal-scores.py` regex: `name=["\']{signal}["\'],\s*score=(-?\d+)`

This requires name and score on the same line. Multi-line RiskSignal construction escapes verification:

```python
RiskSignal(
    name="beaconing",
    score=risk_score,  # variable — cannot be verified
)
```

**Remediation:** Enhance the linter to track `score_cap` variable usage, or require literal scores in the registry-checked signals.

---

## Finding 12 — LOW: VirusTotal Quota Not Multi-Instance Safe

`src/security/virustotal.py`, line 290: `self._quota_used_today += 1` — in-process counter, not atomic across workers.

**Remediation:** Use Redis-based counter like `abuseipdb.py` does.

---

## Finding 13 — LOW: Blocklist Silent CIDR Drops

`src/security/blocklists.py`, lines 108-120: malformed CIDRs are logged as WARNING but silently dropped. No alerting on high drop rates.

**Remediation:** Add a counter/metric for dropped CIDRs and alert on anomalous rates.

---

## Finding 14 — LOW: Go JA4T Is a Stub

`internal/tls/ja4t.go`:

```go
func ComputeJA4T(alertCodes []uint8) string {
    return ""
}
```

Always returns empty string. Python produces actual JA4T fingerprints.

**Remediation:** Implement JA4T in Go or document as a known gap.

---

## Top 3 Priority Actions

1. **Run `make check-scores` and fix all 5 drifts** — this is a close-out checklist requirement currently failing.
2. **Remove `__import__("random")` stubs** from `tcp_analyzer.py` — non-deterministic signals must be fixed or disabled.
3. **Align DGA algorithms** between Python and Go — either port exactly or document as known gap.
