# `x-ja4-fingerprint` STIX 2.1 Cyber Observable Object Extension

**Version:** 1.0
**Extension definition ID:** `extension-definition--3b37e1e8-5a20-4c3d-aa0c-9a581b6f9d4e`

> **This UUID is permanent. Do not change post-publication.**
> A backward-incompatible change requires a new extension definition with a new UUID
> and a new directory under `docs/stix/`.

## 1. Motivation

STIX 2.1 has no native way to express a TLS client fingerprint. The standard's
`pattern_type` field accepts only `stix | pcre | sigma | snort | suricata | yara`,
so a new pattern type cannot be invented without breaking the spec. The
correct way to add a new observable to STIX 2.1 is to define a new
**Cyber Observable Object (SCO)** via an extension with
`extension_type: "new-sco"`, then reference that SCO from inside a normal
`Indicator` pattern.

This extension defines `x-ja4-fingerprint` as such an SCO. Indicator objects
referencing it keep `pattern_type: "stix"` so they remain interoperable with
any STIX-aware TAXII server.

## 2. Definition

### 2.1 Extension definition object

```json
{
  "type": "extension-definition",
  "spec_version": "2.1",
  "id": "extension-definition--3b37e1e8-5a20-4c3d-aa0c-9a581b6f9d4e",
  "name": "JA4 Fingerprint SCO",
  "description": "Defines x-ja4-fingerprint as a STIX 2.1 Cyber Observable Object representing a JA4 TLS ClientHello fingerprint.",
  "created": "2026-04-08T00:00:00Z",
  "modified": "2026-04-08T00:00:00Z",
  "created_by_ref": "identity--ja4proxy-project",
  "schema": "https://ja4proxy.io/stix/extensions/ja4-fingerprint/schema.json",
  "version": "1.0",
  "extension_types": ["new-sco"]
}
```

### 2.2 `x-ja4-fingerprint` SCO instance

```json
{
  "type": "x-ja4-fingerprint",
  "spec_version": "2.1",
  "id": "x-ja4-fingerprint--0e3b8c44-5f2e-4d2a-9ed7-8a1a2b3c4d5e",
  "value": "t10d170900_9dc949161b6c_b64c0ad42cb7",
  "extensions": {
    "extension-definition--3b37e1e8-5a20-4c3d-aa0c-9a581b6f9d4e": {
      "extension_type": "new-sco",
      "likely_category": "c2_framework",
      "likely_tool": "cobalt_strike",
      "ja4x": null,
      "source": "ja4proxy-community-feed"
    }
  }
}
```

### 2.3 Required fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | yes | MUST be the literal `"x-ja4-fingerprint"`. |
| `spec_version` | string | yes | MUST be `"2.1"`. |
| `id` | string | yes | STIX identifier of the form `x-ja4-fingerprint--<UUIDv4>`. |
| `value` | string | yes | The JA4 TLS ClientHello fingerprint. See §3 for the value format. |
| `extensions` | object | yes | MUST contain exactly one key, the extension-definition ID above. The value MUST contain `extension_type: "new-sco"`. |

### 2.4 Optional extension properties

The object under the extension-definition key MAY contain:

| Field | Type | Description |
|-------|------|-------------|
| `likely_category` | string \| null | Free-form category tag (`c2_framework`, `scanner`, `malware`, `legitimate_browser`, …). |
| `likely_tool` | string \| null | Free-form tool name (`cobalt_strike`, `sliver`, `nuclei`, …). |
| `ja4x` | string \| null | Optional companion JA4X X.509 fingerprint when known. |
| `source` | string | Producer identifier; defaults to `ja4proxy-community-feed`. |

Consumers MUST tolerate unknown additional properties under the extension key
without erroring.

## 3. JA4 value format

The `value` field carries a JA4 fingerprint string in the public JA4 format
(see <https://github.com/FoxIO-LLC/ja4>):

```
t{tls_version}{transport}{cipher_count}{ext_count}{alpn?}_{cipher_hash}_{ext_hash}
```

* `t` — literal prefix.
* `tls_version` — two digits encoding the TLS major/minor (`13` for TLS 1.3, `12` for 1.2, `10` for 1.0).
* `transport` — `d` for TCP, `q` for QUIC.
* `cipher_count` and `ext_count` — two-digit fields each.
* `alpn` (optional) — two-character ALPN tag (`h2`, `h1`, `00`, …).
* Two `_`-separated hex hashes, each exactly 12 characters of `[0-9a-f]`.

Example: `t13d1516h2_8daaf6152771_b0da82dd1658`.

A consumer MUST reject any `value` that contains whitespace, NUL bytes,
backticks, or that exceeds 128 bytes — these are log-injection / control-string
vectors. The reference implementation in
`src/analytics/ti_feeds/stix_ja4.py::validate_ja4()` enforces all of the above
plus a permissive structural regex.

## 4. Indicator referencing the SCO

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--a1b2c3d4-5678-4aaa-9bbb-ccccddddeeee",
  "name": "Cobalt Strike default TLS profile",
  "pattern_type": "stix",
  "pattern": "[x-ja4-fingerprint:value = 't10d170900_9dc949161b6c_b64c0ad42cb7']",
  "indicator_types": ["malicious-activity"],
  "confidence": 95,
  "valid_from": "2026-04-08T00:00:00Z",
  "kill_chain_phases": [
    {"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}
  ]
}
```

The pattern is a normal STIX 2.1 comparison expression of the form
`[x-ja4-fingerprint:value = '<value>']`. Consumers extract the value with a
small regex; the reference implementation lives at
`src/analytics/ti_feeds/stix_ja4.py::parse_ja4_from_pattern()`.

Variants with logical operators (`AND`, `OR`, `FOLLOWED BY`) are **out of
scope for v1.0**. Producers using such patterns SHOULD emit one indicator per
JA4 value and rely on the consumer's `confidence` and `valid_until` fields for
deduplication.

## 5. Round-trip with the JA4proxy publisher

The Phase 20 TAP TAXII publisher (`src/tap/export/taxii_server.py`) emits
exactly the SCO and Indicator forms in §2.2 and §4. The Phase 85 consumer
(`src/analytics/ti_feeds/taxii.py`) parses the same forms. Round-trip
testing — publish, fetch, parse, compare — is part of the Phase 85 integration
test plan (`tests/integration/test_ti_feeds_e2e.py`).

## 6. Validation

A JSON Schema for the SCO is provided at
[`ja4-fingerprint/schema.json`](ja4-fingerprint/schema.json). The instance in
§2.2 validates against it cleanly. Implementations are RECOMMENDED to apply
this schema as a first-line input filter on any inbound `x-ja4-fingerprint`
object before further processing.
