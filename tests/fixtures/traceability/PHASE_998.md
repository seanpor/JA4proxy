# Phase 998 — Traceability Fixture (UNTAGGED)

## Goal

A minimal phase doc that is *not* opted into REQ tagging. Even though it
contains a REQ-style line, the script must skip it because the manifest
fixture does not flag this phase as `req_tagged: true`.

## Acceptance Criteria

- [ ] REQ-998-01: This requirement should NOT appear in the generated
      traceability matrix because the phase is not opted in.
