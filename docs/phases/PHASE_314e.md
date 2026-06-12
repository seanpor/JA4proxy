# PHASE 314e — TAP Intelligence Exporters

> **STATUS: PROPOSED — OUTLINE. Depends on 314a–314c.**
> Detailed plan to be written before start.

## Goal

Export the fingerprints / verdicts the sensor produces to downstream security
tooling, so the passive intelligence is usable outside JA4proxy.

## Scope (each exporter independent and isolated)

EDL (External Dynamic List, pull), F5, Palo Alto, Kafka, Syslog CEF, TAXII 2.1,
MISP. Metric `ja4proxy_tap_export_errors_total`.

## Key decisions / constraints carried from review

- **Per-exporter fail-open** (CLAUDE.md): every external call logs + increments a
  counter + returns neutral; **one failing exporter never affects another**.
- This is as large as a full phase on its own — likely split per exporter group
  (e.g. 314e-1 pull/EDL+TAXII+MISP, 314e-2 push/Kafka+Syslog+F5+PaloAlto) when detailed.
- Reuse the existing JA4proxy export patterns where they exist; reference (don't
  port verbatim) the archived Python exporters at
  `git show 5afeba26:archive/python_legacy/src/tap/export/`.

## To detail before start

Per-exporter protocol/auth, the data-minimisation contract (export fingerprints +
verdicts, never raw payload), retry/circuit-breaker behaviour, and the test matrix
(one isolated-failure test per exporter).
