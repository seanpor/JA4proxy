# Licensing Posture

<!-- Suggested location: docs/compliance/LICENSING.md (matches the house style
     of the existing docs/compliance/*.md documents) -->

This document records what license applies to which parts of JA4proxy, the
obligations attached to each, and the project's obligations to downstream
recipients.

## 1. Original code — MIT

All original work is (c) 2026 Sean O'Riordain, MIT License (`LICENSE` at
repository root).

## 2. Core JA4 (TLS client fingerprinting) — BSD 3-Clause

JA4 is (c) FoxIO, LLC and published under the permissive BSD 3-Clause
License with no patent claims. JA4proxy implements the JA4 specification
independently (`internal/tls/ja4.go`); it does not copy FoxIO source code.
No additional obligations arise beyond accurate identification of the method.

## 3. JA4+ methods (JA4X, JA4T, JA4Q) — FoxIO License 1.1

`internal/tls/ja4x.go`, `internal/tap/ja4t.go`, and `internal/quic/ja4q.go` implement JA4X, JA4T, and JA4Q.
All are JA4+ methods (c) FoxIO, LLC, **patent pending**, licensed under the
FoxIO License 1.1 (`LICENSE.foxio` at repository root; canonical text:
https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE).

Obligations under Section 2 of that license:

1. **Notice retention.** Copyright, patent and other IP notices placed on the
   software by the licensor must be retained — hence the per-file headers on
   every file that implements a JA4+ method.
2. **Downstream license terms.** Anyone receiving any part of the JA4+ code
   from us must also receive the license terms or the canonical URL. This is
   satisfied by: the per-file headers (URL), `LICENSE.foxio`, the `NOTICE`
   file, and inclusion of `LICENSE`, `NOTICE`, and `LICENSE.foxio` in every
   distribution artifact (git archive, release tarball, container image).
3. **No sublicensing.** The MIT grant in `LICENSE` does not extend to the
   JA4+ files. Those files carry `SPDX-License-Identifier: LicenseRef-FoxIO-1.1`
   headers to make the carve-out machine-readable.

## 4. Use restrictions — non-commercial only

The FoxIO License 1.1 permits personal use, academic R&D, and internal
business use where the software is not directly monetized. It **excludes**:

- any use for which fees or anything of value are charged, directly or
  indirectly;
- providing the software on a hosted or managed service basis to others;
- providing maintenance, support, or development services for the software.

Consequence for this project: distributing JA4proxy (which embeds JA4+
implementations) as a commercial product or managed service requires an
OEM/commercial license from FoxIO, LLC, independent of the attribution
measures above. Compliance action: contact FoxIO before any monetized
release. (The license's Violations clause provides a 30-day cure path for
first-time notice of a violation; proactive compliance is preferable.)

## 5. Trademark

JA4 and JA4+ are trademarks of FoxIO, LLC. Use here nominatively identifies
the fingerprint methods. This project is not affiliated with or endorsed by
FoxIO, LLC.

## 6. Consumers vs. implementers

The following consume fingerprint *strings* as data and are covered by the
MIT license like the rest of the original code — they do not implement JA4+
methods: the Redis store/consumer pipeline, the management API, the STIX
threat-intel parser, and test fixtures. If a future change adds computation
of a JA4+ method anywhere else, that file gains the same header and this
document is updated.

## 7. Ground truth

JA4X/JA4T/JA4Q outputs are validated against the canonical FoxIO reference
implementation (`ja4` Rust tool / Wireshark JA4+ plugin) using FoxIO's
published test captures, in the style of the existing DERIVATION.md
provenance records.

## 8. Royalty-Free Commercial / Enterprise Profile (Zero FoxIO Footprint)

For commercial users (e.g. banks, financial services, enterprise SaaS) who deploy JA4proxy without an OEM commercial license from FoxIO, LLC, the codebase supports a **Royalty-Free / Pure FOSS Edition**:

- **Go Build Tag**: Compile with `-tags no_ja4plus` (or target `make go-build-foss`).
- **Container Build**: Use `deploy/docker/Dockerfile.go-proxy.foss`.
- **License Footprint**: Pure MIT and BSD-3-Clause only. Zero code under `LicenseRef-FoxIO-1.1`.
- **Behavior Under FOSS Profile**:
  - **Core JA4** (TLS client fingerprinting) remains 100% active, permissive BSD-3-Clause.
  - **JA4X** (`internal/tls/ja4x_stub.go`): returns standard sentinel (`000000000000_000000000000_000000000000`), excluding patent-pending x509 fingerprint logic.
  - **JA4T** (`internal/tap/ja4t_stub.go`): returns empty string, excluding patent-pending TCP options fingerprint logic. Passive OS classification (`tap.Classify`) remains 100% active.
  - **JA4Q** (`internal/quic/ja4q_stub.go`): returns empty string, excluding patent-pending QUIC ClientHello hash logic. QUIC decoding and traffic parsing remain 100% active.
  - All threat intelligence, Redis scoring, CIDR rules, tarpitting, and telemetry storage operate unrestricted.

