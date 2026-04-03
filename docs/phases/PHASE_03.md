# Phase 3 — TLS Version & Cipher Enforcement

## Goal

Reject connections using obsolete TLS versions and known-weak cipher suites at the
proxy level. Zero false positive risk — no legitimate modern browser uses TLS 1.0/1.1.
Simple, early win, completely standalone.

## 3a. Module: `src/security/tls_enforcer.py`

### 3a. TLS Version Enforcement

Block TLS 1.0 and TLS 1.1 entirely. Emit warning for TLS 1.2 (still valid but
declining). TLS 1.3 is the gold standard.

These are visible in the ClientHello `legacy_version` and `supported_versions`
extension fields — already parsed for JA4, so no additional parsing needed.

```yaml
tls_enforcer:
  block_tls_10: true            # Hard block — no false positive risk
  block_tls_11: true            # Hard block — no false positive risk
  flag_tls_12: false            # Default: false. Set true to add a score contribution for TLS 1.2 connections.
  score: 10
  block_ssl3: true              # SSLv3 — strongly recommended; disable only for legacy investigation
```

### 3b. Weak Cipher Suite Detection

Some cipher suites are known-broken (RC4, NULL, EXPORT, ANON, DES, 3DES) and indicate
either a very old/misconfigured client or active probing.

These are visible in the ClientHello cipher suite list — already parsed for JA4.

```python
WEAK_CIPHERS = {
    0x0000,  # TLS_NULL_WITH_NULL_NULL
    0x0001,  # TLS_RSA_WITH_NULL_MD5
    0x0002,  # TLS_RSA_WITH_NULL_SHA
    # ... RC4, EXPORT, ANON, DES, 3DES suites
}

def has_weak_ciphers(cipher_list: list[int]) -> bool:
    return bool(set(cipher_list) & WEAK_CIPHERS)
```

```yaml
tls_enforcer:
  block_weak_ciphers: false     # Flag by default; block only if explicitly enabled
  score: 20
```

### 3c. JA4 as Evidence

The JA4 fingerprint (already computed) encodes TLS version implicitly. Weak TLS
version and cipher signals feed into the risk scorer as `RiskSignal` objects.

TLS 1.0/1.1 block is a **scorer bypass by default** (controlled by
`security_policy.tls_version_bypass.enabled`). When that bypass is disabled, old TLS
versions produce a `RiskSignal` instead of a hard RST — they can still be blocked by
the dial+scorer if score is high enough.

Weak cipher detection is always a **scored signal** (not a hard block) unless
`block_weak_ciphers: true` is set explicitly.

## Redis Key Schema

Phase 3 adds no new Redis keys. TLS enforcement is in-process only.

## Config

```yaml
tls_enforcer:
  enabled: true
  block_tls_10:       true    # Default: true. Block TLS 1.0 connections.
  block_tls_11:       true    # Default: true. Block TLS 1.1 connections.
  flag_tls_12:        false   # Default: false. Set true to add a score contribution for TLS 1.2.
  score: 10                   # Risk score contribution when flag_tls_12 is true. Default: 10.
  block_ssl3:         true    # Default: true. Block SSLv3 connections.
  block_weak_ciphers: false   # Default: false. Hard-block connections using weak cipher suites.
  weak_cipher_score:  20      # Score contribution when block_weak_ciphers is false. Default: 20.
  weak_ciphers:               # Cipher suite IDs considered weak. Extend as needed.
    - 0x0004  # TLS_RSA_WITH_RC4_128_MD5
    - 0x0005  # TLS_RSA_WITH_RC4_128_SHA
    - 0x000A  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    - 0x0035  # TLS_RSA_WITH_AES_256_CBC_SHA (no PFS)
    - 0x002F  # TLS_RSA_WITH_AES_128_CBC_SHA (no PFS)
```

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| TLS version field missing from ClientHello | Treated as unknown version; no signal; connection passes to scorer |
| Cipher suite list empty | No weak cipher signal; no crash |
| Config reload changes `block_tls_11` during traffic | New value applies to next connection; in-flight TLS 1.1 connection uses old value |

## Acceptance Criteria

### Functional
- [x] `TLSEnforcer.check(tls_version, cipher_list) -> list[RiskSignal] | None`
- [x] Returns `None` for hard-block cases (signals pipeline not called); list otherwise
- [x] TLS 1.0 and 1.1: immediate RST when `security_policy.tls_version_bypass.enabled: true` (default)
- [x] TLS 1.0 and 1.1: `RiskSignal(name="tls_version", score=40)` emitted when bypass disabled
- [x] TLS 1.2: optional `RiskSignal` emitted when `flag_tls_12: true`
- [x] SSLv3: always hard-blocked (no bypass option — protocol is broken by design)
- [x] Weak cipher suite: `RiskSignal(name="weak_cipher")` with configured score
- [x] `block_weak_ciphers: true`: weak cipher → hard block instead of scored signal
- [x] Both checks independently config-toggleable; disabling one does not affect the other

### Configuration
- [x] All score values and block flags loaded from `config/proxy.yml`; hot reload applies
- [x] `block_ssl3`, `block_tls_10`, `block_tls_11`, `flag_tls_12`, `block_weak_ciphers` all tested on reload

### Observability
- [x] Prometheus counter: `ja4proxy_tls_version_total{tls_version,action}` — connections by TLS version and action
- [x] Prometheus counter: `ja4proxy_weak_cipher_total{cipher_strength,action}` — connections with weak cipher suites
- [x] Log format: hard-block → `BYPASS  | {ip} | score=N/A | bypass=tls_version`
- [x] Log format: scored → `BLOCK   | {ip} | score=N | dial=N | signals=[tls_version(+40)]`

- [x] JSON log: hard-block connections (TLS 1.0/1.1, SSLv3) use verb `BYPASS  ` with `bypass=tls_version`; not scored
- [x] JSON log: scored TLS violations appear in `signals` array with name `tls_version` or `weak_cipher`

### Unit Tests  (`tests/unit/test_tls_enforcer.py`)
- [x] `TLSEnforcer.check()`: TLS 1.3 → no signal
- [x] `TLSEnforcer.check()`: TLS 1.2, `flag_tls_12: false` → no signal
- [x] `TLSEnforcer.check()`: TLS 1.2, `flag_tls_12: true` → signal emitted
- [x] `TLSEnforcer.check()`: TLS 1.1, bypass enabled → returns None (hard block)
- [x] `TLSEnforcer.check()`: TLS 1.1, bypass disabled → RiskSignal emitted
- [x] `TLSEnforcer.check()`: TLS 1.0, bypass enabled → returns None
- [x] `TLSEnforcer.check()`: SSLv3 → returns None regardless of bypass setting
- [x] `TLSEnforcer.check()`: weak cipher, `block_weak_ciphers: false` → RiskSignal
- [x] `TLSEnforcer.check()`: weak cipher, `block_weak_ciphers: true` → returns None
- [x] `TLSEnforcer.check()`: mixed cipher list (one weak) → signal emitted
- [x] `TLSEnforcer.check()`: all strong ciphers → no signal

### Integration Tests  (`tests/integration/test_pipeline.py`)
- [x] TLS 1.1 connection, bypass enabled → hard block at pipeline entry; scorer not called
- [x] TLS 1.1 connection, bypass disabled → reaches scorer; `tls_version` signal in score
- [x] Weak cipher connection, `block_weak_ciphers: false` → scored and actioned by dial
- [x] Hot reload changes `flag_tls_12: true` → next connection emits signal; no restart

### Chaos Tests  (`tests/chaos/test_redis_failure.py`)
- [x] Redis unavailable during TLS check: in-process bypass list used; no crash; connection processed
