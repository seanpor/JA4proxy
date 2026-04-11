# JA4proxy STIX 2.1 Extensions

This directory holds the standards-track artifacts for the JA4proxy STIX 2.1
extensions. They are versioned alongside the code so the proxy's TAXII publisher
(`src/tap/export/taxii_server.py`, Phase 20) and consumer
(`src/analytics/ti_feeds/`, Phase 85) can be reviewed against a single source
of truth.

## Index

| Document | Purpose |
|----------|---------|
| [`ja4-fingerprint-extension.md`](ja4-fingerprint-extension.md) | Prose specification of the `x-ja4-fingerprint` Cyber Observable Object (SCO) extension, with worked examples for the SCO, the extension definition, and a referencing `Indicator` SDO. |
| [`ja4-fingerprint/schema.json`](ja4-fingerprint/schema.json) | JSON Schema (Draft 2020-12) that validates an `x-ja4-fingerprint` SCO instance. Used by the TAXII consumer for input sanitisation and by tests for round-trip validation against the prose spec. |

## Status

The extension is currently published from this repository only. A community
PR against [`oasis-open/cti-stix2-json-schemas`](https://github.com/oasis-open/cti-stix2-json-schemas)
is tracked as a Phase 85 business-track follow-up; opening that PR is **not**
a precondition for merging the engineering work.

## Versioning

The extension definition UUID
(`extension-definition--3b37e1e8-5a20-4c3d-aa0c-9a581b6f9d4e`) is **permanent**.
Backward-incompatible schema changes require a new extension definition with a
new UUID and a new directory under `docs/stix/`. The current version is `1.0`.
