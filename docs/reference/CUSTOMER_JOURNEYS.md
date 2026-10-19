<!--
title: Customer_Journeys
audience: reference
last_reviewed: 2026-10-15
phase: 824a
-->

# Customer Journeys

What people actually *do* with JA4proxy, end to end, from both the command line
and the management console — and what observable thing proves each one worked.

This document is the **permanent home** of the journey catalogue. Phase 824's
sub-phases reference it; they do not restate it. Each journey exists so that a
persona-level claim ("an engineer can stop a bot attack") becomes a check that
runs after every set of changes, instead of a claim nobody tests.

---

## How to read a journey

Every journey states:

- **Trigger** — what just happened, in the operator's words.
- **CLI path** — the commands an operator would run.
- **Console path** — the pages and panels they would use.
- **Proves it worked** — the observable outcome a regression test asserts.

"Proves it worked" is the part that matters. It must be an outcome, never
"the command exited 0". Where a journey has an enforcement action, the assertion
has **two halves**: the bad traffic is actioned *and* a legitimate control group
is still served. A test that only asserts "bad traffic blocked" would pass a
proxy that blocks everything — the most expensive failure under `CLAUDE.md`'s
core asymmetry.

---

## Summary

| # | Journey | Regression tier | Automated? |
|---|---|---|---|
| J1 | Stop the bots | T2 | Phase 824e |
| J2 | Day-one deploy | T2 | Phase 824e |
| J3 | Demo / showcase | T3 | planned |
| J4 | False-positive rescue | T2 | Phase 824e |
| J5 | Tuning the dial with evidence | T3 | planned |
| J6 | Retrospective: "what happened at 03:00?" | T3 | planned |
| J7 | Change config without dropping traffic | T3 | planned |
| J8 | Degraded dependencies (fail open) | T2 | Phase 824e |
| J9 | Audit and compliance evidence | T3 | planned |
| J10 | Capacity check | T4 | blocked (Phase 819a) |
| J11 | Zero-downtime upgrade & rollback | T3 | planned |

Tier definitions and the cost argument live in `docs/phases/PHASE_824e.md`.

---

## J1 — Stop the bots hammering at the door

**Trigger:** traffic is up, the backend is straining, and the engineer believes
it is automated.

| Step | CLI | Console |
|---|---|---|
| See it happening | `./scripts/ja4-admin.sh status` | dashboard `/` — connection rate, action breakdown |
| Confirm it is bots, not launch day | `./scripts/ja4-admin.sh top 20` | Threat posture panel — top JA4s with corpus labels |
| Turn enforcement on | `./scripts/ja4-admin.sh dial 40` | Dial widget on `/` |
| Watch it take effect | `ja4proxy_connections_total{action="block"}` rising | Action breakdown + Bans panel |
| Identify the attacker | `./scripts/ja4-admin.sh report` | `/fingerprint/{ja4}` and `/ip/{ip}` |
| Tighten if needed | `./scripts/ja4-admin.sh block-ja4 <FP>` | Lists page `/lists` |
| Confirm no collateral damage | `ja4proxy_connections_total{action="allow"}` for browser-shaped traffic held | panel1-harm (Phase 821b) |

**Proves it worked:** offered bot traffic is blocked **and** the legitimate
control group is still served. Both halves are required.

**Regression note:** the second assertion is the more important one.

---

## J2 — Day-one deploy

**Trigger:** first install; the engineer wants it running without blocking anyone.

| Step | CLI | Console |
|---|---|---|
| Bring the stack up | `make start-poc` | — |
| Confirm it is healthy | `make status` | `/` |
| Confirm the dial is monitor-only | `./scripts/ja4-admin.sh dial` (expect `0`) | Dial widget reads 0 |

**Proves it worked:** stack healthy, scoring visible, and **zero** blocks. A
first deploy that blocks real users is the worst possible first impression
(default dial is 0; see `CLAUDE.md`).

---

## J3 — Demo / showcase

**Trigger:** showing the product to someone.

| Step | CLI | Console |
|---|---|---|
| Bring up demo + traffic + monitoring | `make demo` | `/`, Grafana |
| Pre-flight the demo | `make demo-check` | — |
| Send one non-browser connection | `make demo-bot` | Threat posture panel |
| Drive the dial | `./scripts/ja4-admin.sh dial <N>` | Dial widget |
| Assert the data flow | `make demo-verify` | all panels |

**Proves it worked:** every panel shows non-empty data within N seconds of
traffic starting, and toggling the dial visibly changes the action mix.

This is the only journey that exercises proxy + analytics + Redis + console +
metrics together with real traffic, and so it is the highest-value regression
fixture in the set. The environment is Phase 816's; this journey asserts on it.

---

## J4 — False-positive rescue

**Trigger:** "our customer can't reach the site."

| Step | CLI | Console |
|---|---|---|
| Find why the IP was actioned | `./scripts/ja4-admin.sh blocked` | `/ip/{ip}` — action, score, signals |
| Release it immediately | `./scripts/ja4-admin.sh unblock-ip <IP>` | Bans panel — release action |
| Prevent recurrence | `./scripts/ja4-admin.sh whitelist-ja4 <FP>` | Lists page `/lists` |

**Proves it worked:** the client is served again **within one propagation
interval**, and a repeat of the same fingerprint is not re-blocked.

Under `CLAUDE.md`, unblocking must be fast — pub/sub is used for removals
precisely because new blocks may propagate slowly but releases must not.

---

## J5 — Tuning the dial with evidence

**Trigger:** enforcement is on but at a guessed level.

| Step | CLI | Console |
|---|---|---|
| Read the score distribution | `./scripts/ja4-admin.sh top 20` | Threat posture panel |
| Raise in steps | `./scripts/ja4-admin.sh dial <N>` | Dial widget |
| Confirm the record | — | Audit page `/audit` |

**Proves it worked:** the dial change is recorded in `management:policy_audit`
with attribution, and the action mix shifts as predicted.

---

## J6 — Retrospective: "what happened at 03:00?"

**Trigger:** the engineer was not watching, and something changed.

| Step | CLI | Console |
|---|---|---|
| Reconstruct the window | Prometheus range query | Grafana |
| Read the policy changes | `./scripts/ja4-admin.sh status` | Audit page `/audit` |
| Inspect the raw events | Redis `events:connection` stream | — |

**Proves it worked:** a past window can be reconstructed **after** the fact.
This is what justifies keeping Prometheus and the event stream at all.

---

## J7 — Change config without dropping traffic

**Trigger:** a policy edit is needed, without an outage.

| Step | CLI | Console |
|---|---|---|
| Apply new config | `kill -HUP <ja4pd pid>` | `/security-policy` |
| Confirm it took | `ja4proxy_config_reloads_total` incrementing | — |

**Proves it worked:** the new config is live, `ja4proxy_config_reloads_total`
increments, `ja4proxy_config_reload_failures_total` does not, and an in-flight
connection survives.

---

## J8 — Degraded dependencies (fail open, verified)

**Trigger:** Redis dies, feeds go stale, AbuseIPDB times out.

| Step | CLI | Console |
|---|---|---|
| Confirm traffic still flows | `make status` | `/` — panels show "unavailable", not stale values |
| Confirm the proxy failed open | `ja4proxy_connections_total{action="allow"}` still moving | — |

**Proves it worked:** traffic still flows, the proxy fails **open**, and the
console says so **visibly** rather than showing stale numbers as current.

This journey is the direct test of the doctrine split from Phase 821a: **the
proxy fails open, the console fails visibly.** Nothing else tests that pairing
end to end. The console's "unavailable" state must map to the UI health check's
`DEGRADED`, **not** to `BROKEN`/RED (see `docs/phases/PHASE_824d.md`).

---

## J9 — Audit and compliance evidence

**Trigger:** an auditor or a data-subject request arrives.

| Step | CLI | Console |
|---|---|---|
| Who changed the dial, and when | — | Audit page `/audit` |
| DSAR export for an IP | `./scripts/ja4-admin.sh report` | `/audit` |

**Proves it worked:** the audit trail answers the question without reading logs
by hand, and the DSAR export is **complete** — a truncated export silently
under-reports.

**Regression note:** the DSAR export is `management/api/routes/compliance.py`.
Its former unbounded read is fixed (`JA4PROXY-2026-0035`, `closed_commit:
ce4da33`). The still-open unbounded read in
`management/api/routes/connections.py` is a **different** endpoint
(memory exhaustion on the profile/table views), not the DSAR path; it is tracked
separately, not here.

---

## J10 — Capacity check before going live

**Trigger:** "will it hold at our expected load?"

| Step | CLI | Console |
|---|---|---|
| Measure throughput and latency | `make bench-macro` | Grafana |
| Find what breaks first | saturation sweep | — |

**Proves it worked:** throughput and latency measured **under saturation**.

**Regression note:** blocked on Phase 819a. The existing benchmark is
rate-limited and reports a constant, so this journey must not be built on it
until that is fixed.

---

## J11 — Zero-downtime upgrade & rollback

**Trigger:** a new release is deployed via Docker Compose or Helm.

| Step | CLI | Console |
|---|---|---|
| Apply new image while traffic flows | `docker compose up -d proxy` | panels still render |
| Roll back immediately | redeploy prior image | panels still render |

**Proves it worked:** zero dropped connections during the container swap
(graceful drain — `cmd/ja4pd/compat.go` `drain()`), Redis schema compatibility
maintained across n-1 and n, and console partials render without 5xx throughout
the upgrade window.

---

## UI route coverage (the UI half of the regression layer)

The console is a shell page plus htmx partials polled from
`/api/v1/partials/*`. The shell renders **identically** when a partial behind it
is broken, so every partial that the UI fetches must be covered by a route test.

Measured 2026-10-15 across `management/templates/**`:

- **20 `hx-get` partial targets**, plus `/api/v1/tls-health` = **21**.
- **`management/tests/test_ui_regression.py` (Phase 826) covers 18 of the 20
  partials** — and `tls-health` — with an authenticated GET that fails on a 404.
  Tier 1 is parametrised over URLs extracted from the templates, so it is
  self-maintaining.
- **Exactly 2 partials are invisible to that gate because the extractor drops
  brace-wrapped URLs:** `attack-top` and `attack-fingerprint-table`. Those two
  are brace-only in the templates (`{% if attack_mode_active %}`), so the
  extractor's old regex skipped them. Phase 824c fixes that hole and adds the
  missing static checks (mutating targets + reverse direction). Phase 824b adds
  per-partial auth enforcement and positive panel landmarks.

Phase 824c fixes the extractor so Tier 1 sees the missing two, and adds static
forward/reverse/mutating checks. Phase 824b adds parametrised unauthenticated
(401) and positive-landmark assertions for the partials, because a "200 and no
error marker" is not proof the partial rendered the right panel. Re-derive the
authoritative list with:

```bash
# every hx-* target, with its method
grep -rhoE 'hx-(get|post|put|patch|delete)="[^"]*"' management/templates/ | sort -u
```

Mutating targets (`hx-post`, `hx-delete`, `hx-put`, `hx-patch`) must never be
probed with a request — they change bans, dials, audit and triage state. See
`docs/phases/PHASE_824.md` for the full list.
