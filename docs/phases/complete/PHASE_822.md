# Phase 822 — Go 1.26.6 bump and `.trivyignore` first-/third-party split

> **Status:** PROPOSED (2026-08-15)
> **Size:** SMALL
> **Dependencies:** 820 (stacked — both edit `.trivyignore`)
> **Branch:** `phase-822-go-bump-trivyignore-split`

---

## Goal

Two changes that together stop the scan gate lying about our own product:

1. **Bump the Go toolchain 1.26.5 → 1.26.6**, clearing **six** Go stdlib
   HIGH CVEs from every first-party image — with a real fix, not a waiver.
2. **Split `.trivyignore`** into first-party and third-party files, so a waiver
   granted to a monitoring sidecar can never again silently suppress the same
   finding in the proxy we ship.

---

## Why

### The scan gate currently covers our proxy with other images' waivers

`Makefile:609` (third-party) and `Makefile:647` (first-party) pass the **same**
`--ignorefile /scan/.trivyignore`. Trivy's ignorefile has no per-image scoping,
so every exception written for an abandoned sidecar also applies to
`ja4proxy:2.0.0`.

That is not hypothetical. `CVE-2026-39821` and `CVE-2026-46600` are waived with
justifications written entirely about Grafana, Promtail, Alertmanager and
cAdvisor — reasoning "they consume metrics/logs or serve authenticated admin
UIs only", which is flatly untrue of an internet-facing TLS proxy. Both are
present in `ja4proxy:2.0.0` (`usr/local/bin/ja4pd`, `stdlib v1.26.5`), and both
are fixed by Go 1.26.6.

The `.trivyignore` header rule reads *"only when there is genuinely no fix
available"*. For our own images that rule was being violated silently, because
the file could not express "this waiver is for someone else's container".

### Six more arrived overnight

A Trivy DB update between 2026-08-14 and 2026-08-15 surfaced a batch of new Go
stdlib CVEs, all in `stdlib v1.26.5`, all fixed in **1.26.6**:

```
CVE-2026-33818  CVE-2026-56853  CVE-2026-56858
CVE-2026-56859  CVE-2026-56860  CVE-2026-56862
```

They turn `make scan-images` red on `main` today, independently of any phase.
For the four third-party images (node-exporter, prometheus, alertmanager,
redis_exporter) the only remedy is an upstream rebuild, so those need dated
exceptions. **For our own images the remedy is a one-line bump**, and after the
split those two facts are recorded in different files with different rules.

---

## Scope

| File | Change |
|---|---|
| `deploy/docker/Dockerfile.go-proxy` | `golang:1.26.5-alpine` → `1.26.6-alpine` + new digest |
| `deploy/docker/Dockerfile.ja4-tap` | same |
| `deploy/docker/Dockerfile.cli` | same |
| `deploy/docker/Dockerfile.mockbackend` | same |
| `deploy/docker/security-scan/Dockerfile` | same |
| `go.mod` | `go 1.26.5` → `1.26.6` |
| `.github/workflows/ci.yml` | 6 × `go-version: "1.26.5"` → `"1.26.6"` |
| `.github/workflows/nightly-benchmark.yml` | same |
| `.trivyignore` | **deleted**, split into the two files below |
| `.trivyignore.first-party` | new — waivers for images we build |
| `.trivyignore.third-party` | new — waivers for pinned upstream images |
| `Makefile` | `scan-images` / `scan-first-party` use their own ignorefile |
| `scripts/scan_exceptions.py` | read both files, report which is which |

New digest, resolved from the registry:
`golang:1.26.6-alpine@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df`

`go.mod` is bumped alongside the CI pins so that a developer building locally on
1.26.5 gets the fixed toolchain via `GOTOOLCHAIN=auto` rather than silently
producing a vulnerable binary. `go-proxy-image.yml` already uses
`go-version-file: go.mod`, so it follows automatically.

**Not bumped:** `tests/docker/Dockerfile.test-runner` (floating `golang:1.26-alpine`)
and `deploy/docker/update-checker/Dockerfile` (`golang:1.25.10-alpine`) — neither
is a shipped artefact and neither is in `FIRST_PARTY_IMAGES`. Noted, not touched.

---

## The split

`.trivyignore.first-party` — images we build. Rule: **a fix that exists
upstream is not a waiver candidate.** If a bump or rebase clears it, do that.
Expected residents: the pip-vendored `msgpack`/`setuptools` pair, `protobuf` in
the CI-only test image, `python-ecdsa` in management.

`.trivyignore.third-party` — pinned upstream images. Rule: **no fix reachable
without replacing the image.** This is the honest criterion, and it is the one
the old single file's header claimed but could not enforce.

Both keep the Phase 226 policy: one entry per CVE, a justification stating why
no fix and why not exploitable, and a `exp:` date at most 7 days out.

---

## Implementation plan

1. Bump the five Dockerfiles, `go.mod`, and the CI workflow pins.
2. Rebuild `ja4proxy:2.0.0` and confirm `stdlib` reports `v1.26.6` and that all
   eight CVEs (the two waived plus the six new) are gone **without** any
   ignorefile.
3. Create the two ignorefiles: move each existing entry to the file matching the
   image that actually carries it, verified against a no-ignorefile scan rather
   than against the old justification text.
4. Remove `CVE-2026-39821` / `CVE-2026-46600` from the first-party side entirely
   — they are fixed for us — and correct the third-party justifications that
   named our image.
5. Add third-party exceptions for the six new CVEs, justified as "upstream
   rebuild required", dated today+7.
6. Point `scan-images` at `.trivyignore.third-party` and `scan-first-party` at
   `.trivyignore.first-party`.
7. Update `scripts/scan_exceptions.py` and the runbook.

---

## Test strategy

- **A first-party waiver must not be readable by the third-party scan, and vice
  versa** — a unit test asserting the two Makefile targets reference different
  ignorefiles, and that neither references the retired `.trivyignore`.
- **Regression pin for the original defect:** assert that no CVE appears in
  `.trivyignore.first-party` whose Trivy record carries a non-empty
  `FixedVersion` reachable by a base-image or dependency bump — i.e. the header
  rule becomes machine-checked for the file where it is absolute.
- `make scan` green.
- `make lint`, `make test` green.
- Existing Go test suite passes on the new toolchain.

---

## Acceptance criteria

1. `ja4proxy:2.0.0` reports `stdlib v1.26.6` and carries **zero** of the eight
   CVEs with no ignorefile applied.
2. `.trivyignore` no longer exists; both replacements do.
3. `scan-images` and `scan-first-party` use different ignorefiles.
4. No first-party image relies on a waiver written for a third-party image.
5. `make scan` passes.
6. `make lint`, `make test`, `make check-manifest` pass.

---

## Out of scope

- Removing cadvisor / promtail / alertmanager / Grafana (later phases).
- Phase 821a/b/c.
- `tests/docker/Dockerfile.test-runner` and the update-checker image.
