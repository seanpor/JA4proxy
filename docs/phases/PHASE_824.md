<!--
title: Customer_Journeys_And_Journey_Regression
audience: developer
last_reviewed: 2026-08-15
phase: 824
-->

# Phase 824 — Customer journeys, and how they become regression tests

> **Status:** PROPOSED (2026-08-15)
> **Size:** LARGE
> **Dependencies:** none to write the journeys; J3 overlaps Phase 816; the
> UI health work shares the three-state model from Phase 821a
> **Branch:** `phase-824-customer-journeys`

---

## Goal

Write down what people actually *do* with JA4proxy, end to end, from both the
command line and the management console — then turn each of those journeys into
something that gets checked after every set of changes, with an explicit **RED
flag when the UI is broken**.

Today the test suite proves the parts work. It does not prove **a person can get
their job done**. Those are different claims, and only the second one matters to
a user.

---

## Why this is needed (the specific gap)

The suite has ~1868 unit tests, 751 management tests, and integration tests. What
it does not have is a single test that asserts *"an engineer under bot attack can
turn enforcement on, watch it work, and identify the attacker"*.

**The UI gap is sharper, and it is structural.** The console is a shell page plus
htmx partials polled from `/api/v1/partials/*`. `management/tests/test_pages.py`
asserts the shell renders — status 200, `"JA4"` appears in the body. But the shell
renders **exactly the same** when every partial behind it is broken, because htmx
fetches them *after* page load. The dashboard could be entirely blank and those
tests stay green.

Fifteen `hx-get` URLs are referenced across the templates. **Six already have
route-resolution assertions** that a rename would break — `situation`
(`test_situation_bar.py`), `infrastructure` (`test_infrastructure_partial.py`),
`threat-posture`, `triage-queue`, `list-table` (`test_codeql_305_regression.py`)
and `tls-health`. The gap is the **other nine**: `health-cards`, `dial`, `bans`,
`audit`, `intelligence`, `intelligence-review`, `attack-top`,
`attack-fingerprint-table`, `attack-mode-indicator`.

*(An earlier draft of this document claimed nothing asserted any of them. That
was wrong, and is corrected here — the six that are covered were covered
incidentally, by tests written for other purposes, which is exactly why the
coverage is patchy rather than systematic.)*

All fifteen resolve today — verified 2026-08-15 — but two are defined in
`attack_mode.py:212` and `tls_health.py:113` rather than `partials.py`, so a
router refactor can blank a panel with nothing to catch it.

That is the RED flag this phase is about.

---

## The journeys

Ten. J1 and J3 are the two named in the request; the rest are what fell out of
asking "what else does someone actually need to do?".

Each journey states the trigger, the CLI path, the UI path, and — the part that
matters for regression — **what observable thing proves it worked**.

### J1 — "Stop these bots hammering at the door" *(the primary journey)*

**Trigger:** traffic is up, the backend is straining, the engineer believes it's
automated.

| Step | CLI | Console |
|---|---|---|
| See it's happening | `ja4p status`, `ja4proxy_connections_total` by action | Dashboard: connection rate, action breakdown |
| Confirm it's bots, not launch day | inspect JA4 distribution in `events:connection` | Threat posture panel: top JA4s with corpus labels |
| Turn enforcement on | raise the dial | Dial widget |
| Watch it take effect | `connections_total{action="block"}` rising | Action breakdown + bans panel |
| Identify the attacker | JA4, ASN, country, SNI patterns | Fingerprint / IP-detail pages |
| Tighten if needed | add JA4 to blacklist | Lists page |
| **Confirm no collateral damage** | browser-shaped block rate | Panel 1 (Phase 821b) |

**Proves it worked:** offered bot traffic is blocked, *and* the legitimate-client
control group is still served. **Both halves are required** — a journey test that
only asserts "bad traffic blocked" would pass a proxy that blocks everything.

Given CLAUDE.md's core asymmetry, the second assertion is the more important one.

### J2 — Day-one deploy

Install and get running **without blocking anyone**. Default dial 0, monitor
mode. **Proves it worked:** stack healthy, scoring visible, and *zero* blocks —
a first deploy that blocks real users is the worst possible first impression.

### J3 — Demo / showcase *(overlaps Phase 816)*

Single command brings up backend + traffic generator (good and bad) + proxy +
console + Prometheus/Grafana. Someone watches the dashboard react live and drives
the dial. **Proves it worked:** every panel shows non-empty data within N seconds
of traffic starting, and toggling the dial visibly changes the action mix.

This is also the **highest-value regression fixture** in the whole set: it is the
only journey that exercises proxy + analytics + Redis + console + metrics
together with real traffic. Phase 816 builds the environment; this phase defines
what must be *asserted* about it.

### J4 — False-positive rescue *(the one the asymmetry demands)*

**Trigger:** "our customer can't reach the site."

Find the IP, see why it was actioned and its score, verify it's legitimate,
unblock immediately, then prevent recurrence (whitelist the JA4). **Proves it
worked:** the client is served again *within one propagation interval*, and a
repeat of the same fingerprint is not re-blocked.

Per CLAUDE.md, unblocking must be fast — pub/sub is used for removals precisely
because new blocks may propagate slowly but releases must not.

### J5 — Tuning the dial with evidence

Raise enforcement in steps, each justified by observed score distribution rather
than guesswork. **Proves it worked:** the dial change is recorded in
`management:policy_audit` with attribution, and the action mix shifts as
predicted.

### J6 — Retrospective: "what happened at 03:00?"

The engineer wasn't watching. Reconstruct from the event stream, audit log and
metrics history. **Proves it worked:** a past window can be reconstructed
*after* the fact — this is what justifies keeping Prometheus and the event
stream at all.

### J7 — Change config without dropping traffic

Edit policy, reload via SIGHUP or the console, no restart, no connection loss.
**Proves it worked:** new config is live, `config_reloads_total` increments,
`config_reload_failures_total` does not, and an in-flight connection survives.

### J8 — Degraded dependencies *(fail-open, verified)*

Redis dies. Feeds go stale. AbuseIPDB times out. **Proves it worked:** traffic
still flows, the proxy fails *open*, and the console says so **visibly** rather
than showing stale numbers as current.

This journey is the direct test of the doctrine split established in Phase 821a:
**the proxy fails open, the console fails visibly.** Nothing else tests that
pairing end to end.

### J9 — Audit and compliance evidence

Who changed the dial, when, and on whose authority; DSAR export for a given IP.
**Proves it worked:** the audit trail answers the question without reading logs
by hand, and DSAR export is *complete* (see the `connections.py` bounded-read
issue extracted from Phase 821b — a truncated export silently under-reports).

### J10 — Capacity check before going live

Does it hold under expected load, and what breaks first? **Proves it worked:**
throughput and latency measured *under saturation* — note Phase 819a found the
existing benchmark is rate-limited and reports a constant, so this journey must
not be built on it until that is fixed.

---

## How journeys become regression tests

### The shape

Each journey is a scripted scenario against the POC stack: bring up
`docker-compose.poc.yml` (+ monitoring), drive it through the **CLI and HTTP API**
exactly as a user would, assert on **observable outcomes** — metrics, Redis state,
API responses, rendered HTML — then tear down.

Three rules, each of which exists because its absence produces a test that passes
while the product is broken:

1. **Assert on outcomes, never on "the command exited 0".** J1 asserts blocked
   *and* allowed counts, not that a `curl` returned.
2. **Every journey with an enforcement action needs a control group.** Legitimate
   traffic must be present and must survive. Otherwise "block everything" passes.
3. **Distinguish "no data" from "broken".** Reuse Phase 821a's three-state model:
   `Ok` / `Empty` / `Unavailable`. A journey asserting a panel is non-empty must
   fail differently when the panel is *broken* than when traffic simply hasn't
   arrived yet — otherwise a flaky timing failure and a real regression look
   identical, and the flaky one trains people to ignore both.

### Cadence — honest about cost

Running all ten on every PR is not viable; each needs a full stack and real
traffic. Tiering:

| Tier | What | When | Budget |
|---|---|---|---|
| **T1** | UI route + partial health (§next), no stack needed | **every PR** | seconds |
| **T2** | **J1, J2, J4, J8** — the safety-critical set | see caveat below | ~5 min |
| **T3** | J3, J5, J6, J7, J9 | nightly + pre-release | ~20 min |
| **T4** | J10 capacity | pre-release only | long |

T2 is deliberately the *asymmetry* set: enforcement works (J1), first deploy
harms nobody (J2), a wrongly blocked real user can be freed (J4), degradation
fails open (J8).

**J4 belongs here, not in T3.** An earlier draft called T2 "the asymmetry set"
while leaving J4 — unblocking a wrongly blocked real user — in the nightly tier.
Under CLAUDE.md that is the most expensive failure in the catalogue, and it is
also the *cheapest* to test: seed a ban, release it via the API, assert the
release propagates within one interval. No traffic generator, no saturation.

**Caveat on "every PR".** This repo's own full-stack job, `poc-cold-start`
(`.github/workflows/ci.yml:473-490`), is deliberately **path-filtered off most
PRs** because compose bring-up is expensive. J2 must assert *zero* blocks so it
cannot reuse J1's stack (J1 raised the dial), and J8 destroys Redis — up to
three bring-ups. So T2 should start as `continue-on-error` on PRs and required
on push to `main`, or be path-filtered like `poc-cold-start`. Only **T1** is
cheap enough to be unconditionally required.

**This touches branch protection.** `tests/test_workflow_pinning.py:303` asserts
the protection contexts equal ci.yml's non-`continue-on-error` job names plus
externals — so any new required job must be added via
`scripts/branch_protection.sh` in the same change, or that test fails. And one
flaky required check stalls the whole merge queue.

`make test-journeys` runs a tier; CI selects by trigger.

---

## Checking the UI, and the RED flag

Three tiers, cheapest first. The first two need **no browser** and run in the
existing tools container.

### Tier 1 — Every referenced partial resolves *(every PR, seconds)*

Extract every `hx-get` / `hx-post` URL from `management/templates/**` and assert
each one:

- resolves to a registered route **anywhere** in the app (not just `partials.py`
  — two live URLs are defined in `attack_mode.py` and `tls_health.py`);
- returns 2xx for an authenticated request;
- returns `< 500` unauthenticated (a 500 means it crashed before auth ran — the
  existing `test_pages.py` rule, applied to partials);
- returns HTML, not a JSON error body.

**Self-maintaining by construction:** the URL list comes *from the templates*, so
adding a panel automatically adds coverage. This is the check that does not exist
today, and it is the cheapest one with the highest yield.

### Tier 2 — Panels render content, not their error state *(every PR)*

A 200 is not success — a panel can return 200 containing "unavailable". For each
partial, with a seeded fixture: assert its landmark content is present **and** its
error/empty markers are absent. This is what separates "the route works" from
"the panel works".

### Tier 3 — Real browser *(nightly + pre-release)*

Playwright against the demo stack (J3). Only this tier catches htmx wiring, JS
errors, CSP violations and layout collapse. Assert: no console errors, every
polled region updates within its interval, and the J1 flow is completable by
clicking.

Deliberately **not** on every PR — a browser stack per PR is a poor trade.

### The RED flag: `/api/v1/health/ui`

A single endpoint that server-side fetches every partial the dashboard polls and
reports per-panel status:

```
GET /api/v1/health/ui
{
  "status": "RED",
  "panels": [
    {"id": "infrastructure",  "state": "OK",      "ms": 41},
    {"id": "threat-posture",  "state": "EMPTY",   "ms": 12, "note": "no events in window"},
    {"id": "bans",            "state": "BROKEN",  "ms": 5,  "error": "500 from /api/v1/partials/bans"}
  ]
}
```

**Four** states, not three. An earlier draft collapsed Phase 821a's
`Unavailable` (the data source did not answer) into `BROKEN`, which directly
contradicted this phase's own acceptance criterion 6: J8 requires that with
Redis stopped the console shows "unavailable" and **passes**. Under that mapping
the same state would have been RED. That is the identical mistake 821a warns
about for `EMPTY`, made one level up:

| State | Meaning | RED? |
|---|---|---|
| `OK` | rendered with data | no |
| `EMPTY` | rendered, legitimately no data in window | **no** |
| `DEGRADED` | a dependency is down; the proxy is failing open by design | **no** — alert separately |
| `BROKEN` | route missing, 5xx, non-HTML, or timeout | **yes** |

`EMPTY` and `DEGRADED` must never count as RED, or a quiet system — or one
correctly weathering a Redis outage — reports itself broken and the flag gets
ignored within a week.

This one mechanism serves three consumers:

- **The operator** — one place that says whether the console is trustworthy.
- **Prometheus** — `ja4proxy_console_panel_health{panel,state}`, so it can alert.
- **CI** — the T1/T2 regression assertion *is* "`/api/v1/health/ui` is not RED",
  so the check an operator trusts and the check CI runs are the same code. A
  health endpoint that CI doesn't use is one nobody notices has rotted.

### Mechanism, auth, and what must NOT be probed

**Fetch in-process, not over the network.** The endpoint must not HTTP-request
its own app: `Dockerfile.management:45` runs `--workers 1`, so a *synchronous*
client inside an `async def` blocks the only event loop, the self-request can
never be served, and the endpoint CI gates on hangs until timeout. Use
`httpx.AsyncClient(transport=ASGITransport(app=request.app))` — the pattern
`tests/unit/test_infrastructure_partial.py:44` already uses. It also avoids
hardcoding host/port/scheme. The endpoint must exclude **itself** from the
extracted URL set, or a template polling it recurses.

**Authentication.** `/api/v1/health` is unauthenticated (it is the container
HEALTHCHECK), but every partial requires `get_current_user`. Left open, this
endpoint becomes an anonymous amplifier — one request fans out to 15
authenticated, Redis-touching renders — and the sample body above leaks upstream
error text. So: **require at least `auditor`**, return stable reason codes rather
than upstream error strings, and expose the Prometheus gauge via the existing
`/metrics` surface refreshed by a background task, **not** as a scrape-triggered
fan-out.

**Do not point the container HEALTHCHECK at it.** A RED console would restart the
management container — the opposite of "the console fails visibly".

**Never probe `hx-post` URLs.** Tier 1 must check `hx-post` targets for
*existence* against `app.routes` (path + method) and fetch **only** `hx-get`.
The hx-post set mutates state — `/api/v1/bans`, `/api/v1/lists/ja4/blacklist/…`,
`/api/v1/triage/dismiss/…`, `/api/v1/intelligence/…`. Probing them would create
bans and blacklist entries, and under `/api/v1/health/ui` it would do so on a
live system on every operator refresh. Under the core asymmetry that is a
false-positive generator wired into a health check.

**Design caution:** the endpoint must not become self-fulfillingly green. If it
only checks HTTP status it will report OK for a panel rendering "unavailable" —
exactly the failure it exists to catch. It must apply the Tier-2 content check,
and it must be tested by **deliberately breaking a panel** and asserting it goes
RED. A health check never proven to fail is not a health check.

### Extraction is not as self-maintaining as it looks

Seven of the URLs contain Jinja rather than a literal path — `?window={{ window }}`,
`?filter={{ key }}`, `attack-top{% if attack_mode_active %}?…{% endif %}` — so a
raw regex yields strings that 422 rather than 200. And
`management/templates/partials/threat_posture.html:228` assembles an `hx-get`
**in JavaScript**, invisible to any static scan; today it happens to duplicate
the static URL, so the extractor is lucky rather than correct. The
implementation needs URL normalisation plus a per-route sample-value fixture,
and must either scan `<script>` blocks and `management/static/*.js` or ban
JS-assembled `hx-get` outright.

### Check the reverse direction too

Route → template, not just template → route. `/api/v1/partials/attack-table`
(`partials.py:1297`) is registered and referenced by no template — a panel
deleted from the UI whose route was left behind. Same extraction run backwards.

---

## Scope

**In:** the journey catalogue (this doc, as the reference the team works from);
`docs/reference/CUSTOMER_JOURNEYS.md` as the permanent home; the T1 and T2 UI
checks; `/api/v1/health/ui` and its metric; `make test-journeys` with tier
selection; J1, J2 and J8 implemented as T2 journeys.

**Out:** J3's environment (Phase 816 builds it — this phase asserts on it);
Playwright/Tier 3 (own phase, after T1/T2 prove out); J10 (blocked on Phase 819a's
benchmark fix); the console panels themselves (Phase 821a/b).

---

## Acceptance criteria

1. All ten journeys documented with trigger, CLI path, UI path, and an explicit
   "proves it worked" assertion.
2. T1 catches a deliberately renamed partial route — **demonstrated failing**,
   not assumed.
3. T2 catches a panel that returns 200 while rendering its error state.
4. `/api/v1/health/ui` returns RED when a panel is broken and **not** RED when a
   panel is legitimately empty. Both cases tested.
5. J1 fails if enforcement stops working **and** fails if the legitimate control
   group starts being blocked.
6. J8 passes with Redis stopped: traffic flows, console shows "unavailable"
   rather than stale values.
7. `make test-journeys TIER=2` runs in under ~5 minutes.
8. Redis stopped yields `DEGRADED`, **not** RED (the J8/criterion-4 contradiction).
9. Tier 1 fetches no `hx-post` URL — asserted by seeding a ban count and
   checking it is unchanged after a full T1 run.
10. The URL extractor is tested against a Jinja-expression URL and the
    JS-assembled one at `threat_posture.html:228`.
11. The reverse check flags `/api/v1/partials/attack-table` as route-without-template.
12. A CHANGELOG fragment exists at `docs/fragments/phase-824-*.md`, and
    `docs/reference/CUSTOMER_JOURNEYS.md` carries the required frontmatter.
13. `make lint`, `make test`, `make scan` clean.

---

## Open questions for review

0. **Should upgrade/rollback be J11?** The review flagged it as the most
   frequent post-day-one operation — new proxy version without dropping traffic
   — and the repo ships Helm charts and a release pipeline. I think yes; it is
   omitted above only because it was not in the original ten.
1. **Is `/api/v1/health/ui` the right home for the RED flag**, or should it be a
   CLI target (`make ui-health`) so it works without the console running? My view:
   endpoint first — it is what an operator and Prometheus can both consume — with
   a thin `make` wrapper for CI.
2. **Ten journeys, or fewer?** J6 and J9 could fold together as "retrospective
   evidence". I have kept them separate because their consumers differ (engineer
   vs auditor) and J9 has a compliance obligation attached.
3. **Does T2 need seeded fixtures per panel**, or is the J3 demo stack a
   sufficient data source? Fixtures are faster and more deterministic; the demo
   stack is more honest. Possibly both — fixtures for T2, demo stack for T3.
