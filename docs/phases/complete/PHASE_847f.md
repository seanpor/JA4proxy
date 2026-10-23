<!--
title: Reachability_Evidence_Binding
audience: developer
last_reviewed: 2026-10-22
phase: 847f
-->

# Phase 847f — Reachability evidence binding

> **Size:** MEDIUM
> **Dependencies:** [847a]
> **Branch:** `phase-847f-reachability-binding`
> **Part of:** Phase 847 (umbrella) — see `docs/phases/PHASE_847.md`

---

## Goal

Turn waiver **justifications into automated assertions**, so a waiver's stated
premise is *checked*, not merely *asserted*. If the premise stops being true, CI
says so — instead of the waiver silently outliving its justification.

This is what separates an evidenced waiver from a hand-wave. Before this phase
every waiver carried a `reachability:` value that was free text: a claim with no
checker behind it, and therefore a claim that can only ever decay.

---

## The enum, as built

The plan sketched four values. The registry's **actual** vocabulary is what the
enum had to be reconciled against, because the plan's names predated the data:

| `reachability` | Kind | Assertion |
|---|---|---|
| `internal-monitoring-only` | machine | The carrier's service publishes **no host port on a non-loopback address**, in any deployment this repository ships. |
| `local-socket-only` | machine | The carrier's service publishes **no host port at all** — a loopback port is still a network route, so this is strictly stronger than the value above. |
| `dev-tooling-only` | machine | The carrier package is **not a declared dependency of any deployed image**. |
| `not-imported` | machine | No first-party module imports the carrier package, **and** it is not a declared dependency of any deployed image. |
| `input-path-unreachable` | **attested** | The vulnerable code path is not reachable by untrusted input. No static signal exists for this, so the claim is a documented attestation: the waiver must carry a `reachability_evidence:` field. |

Reconciliations against the plan's table, recorded rather than silently applied:

- The plan's **`cli-tooling-only`** is the registry's `dev-tooling-only` (8
  waivers already used it). The plan's name is dropped; the data won.
- The plan's **`input-path-unreachable`** ships as an *attested* value, which the
  plan's own notes explicitly permit ("may legitimately ship as a documented
  manual attestation — do not block the phase on automating it"). It is
  deliberately the **only** escape hatch, it costs written evidence to use, and
  the summary line reports how many claims are attested so a registry drifting
  towards attestation is visible rather than silent.
- **`local-socket-only`** was already in use 7 times but was absent from the
  plan's table. It is registered, and it earned its keep immediately (see the
  findings below).

A claim nothing checks is exactly what this programme exists to remove, so an
unregistered value is rejected by the renderer at authoring time.

---

## Findings — three premises that were already broken

The checks were written against the live registry, and running them found real
defects. All three are the *good* kind of failure: the roadmap says a broken
premise must produce a re-justification, and these did.

### 1. A port-parsing bug in 847e made 3 true waivers look false, and 3 false ones look true

`medium_inventory._host_part` split a port mapping on the first `:`:

```
"${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_GRAFANA:-3000}:3000"
  -> host = "${AGENT_BIND_IP"     # the colon inside ${…} ended the field
```

That is not a loopback address, so **grafana, prometheus and alertmanager were
reported as published** — contradicting the function's own docstring ("the
*default* is what decides"). Reading it from the other side: the 847e inventory
over-reported exposure, which is the safe direction for a measurement, but the
numbers it published (`51 published`) were wrong and 21 waivers whose premise is
genuinely true would have failed a naive check.

The port parsing now lives in **one** module, `scripts/compose_exposure.py`, used
by both the inventory and these checks — two implementations of "is this
published?" is the divergence that caused the bug. The inventory was re-measured
against live Trivy: **152 findings, unchanged**, with `published` corrected from
51 to **1**. Corrected: `grafana`, `prometheus`, `alertmanager` →
`no published host port`.

### 2. `CVE-2026-103111` was tagged with a premise its carrier does not have

The waiver covers pcre2 in `haproxy:2.8.28-alpine` **and**
`tecnativa/docker-socket-proxy:v0.5.0`, and was tagged `local-socket-only`. The
socket proxy has no published port and does hold that premise. **haproxy
publishes `443:443` and `80:80` in `docker-compose.prod.yml` and `443:443` in
`docker-compose.scale.yml`** — it is reachable on every interface.

The rationale's actual claim is an *input-path* claim, not a network claim:
"haproxy uses pcre2 only for its own static config patterns". Re-tagged to
`input-path-unreachable` with `reachability_evidence` naming the unreachable
path. Re-justified, not deleted — which is the whole point of the phase.

### 3. `local-socket-only` first asserted more than its name claims

The first draft of the check required the service to *also* mount a local socket.
The live registry killed that idea: `alloy` mounts `/var/run:/var/run:ro` in the
monitoring stack, but the **production** stack mounts only its config and log
directory. A service with no socket at all is *more* isolated than the premise
requires, not less — so a missing socket mount was a false failure. The check now
asserts the sound core (no published port) and reports the socket mounts it finds
as supporting evidence.

### 4. `not-imported` could pass *vacuously* on a namespace distribution

The first waiver authored after the checks went live was a brand-new CVE
(`CVE-2026-114603`, OpenTelemetry `tracestate` quadratic parsing, published
2026-10-22) that reddened `make lint-static` mid-phase. Triage was the routine
kind — `semgrep` pins `opentelemetry-api~=1.37.0`, the fix is 1.45.1, and the
combination does not resolve — so it became waiver 37 with
`reachability: not-imported`.

Authoring it exposed a hole in the check. `opentelemetry-api` is a **namespace**
distribution: its import root is `opentelemetry`, which is neither the
distribution name nor its hyphen/underscore variant, and it was not in
`IMPORT_ALIASES`. The check therefore looked for the strings
`opentelemetry-api`/`opentelemetry_api` in the import graph, found nothing, and
passed — not because the premise held, but because it was asking the wrong
question. It would have kept passing after `import opentelemetry` landed in
`src/`.

Two fixes, both in the check rather than the waiver:

- `_candidate_import_names` now always includes the underscore variant of the
  distribution name (`pip-audit` → `pip_audit`), which no alias entry can be
  forgotten for.
- `IMPORT_ALIASES` gains `opentelemetry-api → {opentelemetry}`, and the table's
  docstring now says *why* namespace distributions must be listed explicitly.

Both directions are pinned by tests: an `import opentelemetry` in a scratch tree
breaks the claim, and so does an `import pip_audit` for a `pip-audit` carrier.


---

## Scope

| Aspect | Decision |
|---|---|
| Compose files read | `prod`, `monitoring`, `poc`, `scale` (`DEPLOYED_COMPOSE_FILES`) — every stack this repository ships. Not the CVE gate's `prod`+`monitoring` pair, because `management` (a runtime service) is absent from the production compose file and the premise is about *any* deployment. |
| Deliberately excluded | `docker-compose.test.yml` (CI harness), `docker-compose.pentest.yml` (a hostile range), `docker-compose.override.yml` (a developer tweak), and the `redis-tls` / `logtide-eval` overlays. |
| CI-only images | A service behind a `profiles:` gate (`test`, `traffic`) only starts when the profile is named, so it is **not deployed** and does not contribute to a runtime dependency set. This is structural; no hand-kept image list exists anywhere in the checks. |
| Unreadable input | Fails closed (exit 2). A missing compose file is an unreadable input, not an empty deployment. |
| Operator overrides | `${VAR:-default}` is judged by its **default** — the committed configuration is what the repository ships. `.env` is gitignored, so there is nothing else to read. An interpolation with no default cannot be read and is therefore judged *not* loopback: fail closed. |

What these checks **do not** claim is worth stating plainly: `dev-tooling-only`
and `not-imported` inspect **declared** dependencies and **static** imports. A
transitive introduction (adding `requests` pulls in `urllib3`) or a dynamic
`importlib.import_module("mcp")` is invisible to both. `not-imported` maps a
distribution to its import name through a curated table (`IMPORT_ALIASES`); a
distribution whose import root is neither its own name nor its underscore
variant, and that is missing from the table, is invisible until someone adds it
— which is why the table is a documented part of the check, not an
implementation detail (finding 4).

---

## Failure behaviour

`scripts/reachability_checks.py` prints the waiver id, the premise, and the
evidence (file, service, port), then:

> Re-justify this waiver or remove the exposure; **do not delete the waiver to
> silence CI.**

The check is read-only — it never touches `security/waivers.yaml`. Deleting a
waiver removes the *record* of an exposure, not the exposure itself, so
automatic removal is not a fix and is not offered. Exit codes: `0` all premises
hold, `1` a premise is broken, `2` the checks could not be evaluated.

---

## Wiring

- `scripts/reachability_checks.py` — the check library and CLI (`--json`).
- `scripts/compose_exposure.py` — the one implementation of "is this published?",
  shared with `scripts/medium_inventory.py`.
- `scripts/render_waivers.py` — `reachability` is required, must name a registered
  check, and an attested value must carry `reachability_evidence`. The evidence is
  rendered into `.trivyignore.third-party` so it is visible where the exemption is
  consumed.
- `make reachability-check` — standalone signal; also runs inside `make
  lint-static` (the pre-PR gate) and, via the unit tests, inside `make test`.

---

## Test strategy (as executed)

- **Live registry:** all 37 waivers' premises hold — 36 machine-checked, 1
  attested.
- **Binding validity:** every registered value is accepted by the schema, an
  unregistered one is rejected, a missing field is rejected.
- **Negative tests, one per machine check** (the phase's acceptance criterion):
  a scratch compose file publishing `3000:3000` breaks
  `internal-monitoring-only`; a scratch service publishing `2375:2375` breaks
  `local-socket-only`; adding `urllib3` to a deployed image's requirements breaks
  `dev-tooling-only`; a module importing `mcp` breaks `not-imported`. Each is a
  real scratch tree, not a patched function.
- **Attestation:** an attested claim with no evidence, or with placeholder
  evidence, fails.
- **The mechanism has teeth but no teeth marks:** the run is asserted to be
  read-only (the registry is byte-identical before and after), and every failure
  message is asserted to contain "Re-justify".
- **Regression for finding 1:** the `${VAR:-default}` port form is pinned as
  loopback, and `medium_inventory` is asserted to agree with the shared parser.

---

## Acceptance criteria

- [x] `reachability:` is a validated enum bound to registered checks.
- [x] `scripts/reachability_checks.py` implements every registered check.
- [x] A CI test runs all bound checks against live compose/source and fails on a
      broken premise (demonstrated with scratch compose edits — see the negative
      tests).
- [x] A broken premise produces a "re-justify this waiver" failure, never a
      silent waiver removal.
- [x] Three already-broken premises found and re-justified, not deleted.
- [x] A waiver authored mid-phase (`CVE-2026-114603`) exposed a **vacuous pass**
      in `not-imported` for namespace distributions; fixed in the check and
      pinned by negative tests rather than worked around in the waiver.
- [x] `make preflight` passes.

---

## Files changed

| File | Change |
|------|--------|
| `scripts/compose_exposure.py` | New — the shared "is this published?" implementation |
| `scripts/reachability_checks.py` | New — the check library, enum, and CLI |
| `scripts/medium_inventory.py` | Uses the shared parser (fixes finding 1) |
| `scripts/render_waivers.py` | Validates the enum; requires evidence for attested claims; renders it |
| `security/waivers.yaml` | `CVE-2026-103111` re-tagged + evidenced; `CVE-2026-59951` → `not-imported`; new `CVE-2026-114603` (`not-imported`, semgrep-only OpenTelemetry DoS) |
| `.trivyignore.third-party` | Regenerated |
| `.pip-audit-ignores` | Regenerated (now 9 ids) |
| `docs/security/CVE_EXCEPTIONS.md` | New `CVE-2026-114603` exception, expiry 2027-01-21 |
| `security/baseline-medium.json`, `security/medium-inventory.md` | Re-measured (152 findings unchanged; exposure corrected) |
| `tests/unit/test_reachability_checks.py` | New |
| `tests/unit/test_compose_exposure.py` | New |
| `Makefile` | `reachability-check`; `lint-static` runs the checks |
| `docs/fragments/phase-847f-reachability-binding.md` | Changelog fragment |

---

## Out of scope

- Automating `input-path-unreachable`. It ships as an attested value by design;
  the check asserts the attestation is substantive, not that it is correct.
- Reachability analysis of third-party image contents. The 152 MEDIUM findings
  live inside binaries whose source is not ours; nothing here claims otherwise,
  and `security/medium-inventory.md` continues to record them as **unknown**.
- Deprecating `make scan` (de-required since 847c) or the `Security Scan` job.

---

## Close-out

Landed on branch `phase-847f-reachability-binding`, bundled with 847g and 824c in
one PR: the three touch the same waiver registry and the same gate, and splitting
them would have produced intermediate commits where the derived ignorefiles
disagreed with the registry.

| Gate | Result |
|------|--------|
| `scripts/reachability_checks.py` | 28 bound checks — 27 machine-checked, 1 attested, **0 broken** |
| `render_waivers.py --check` | derived files match the registry |
| `tests/unit/test_reachability_checks.py` | namespace/underscore negative tests green |
| `make lint`, `make test`, `make preflight` | green |

The count moved 37 → 28 during 847g, not because anything here was relaxed but
because ten entries were deleted when their carriers were bumped out of the
finding: the checks run over whatever the registry contains, and a shrinking
registry is the point.

### Residual

`input-path-unreachable` remains an **attested** value: the check verifies that
substantive evidence was written, not that the evidence is correct. One waiver
uses it (`CVE-2026-103111`, haproxy). Automating the claim would mean modelling
haproxy's request path, which is a different phase's worth of work; recording it
as attested is the honest stop.
