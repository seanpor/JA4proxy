<!--
title: Get_Ahead_Of_The_CVE_Renewal_Treadmill
audience: developer
last_reviewed: 2026-08-19
phase: 829
-->

# Phase 829 — Get ahead of the CVE renewal treadmill

**Status:** PROPOSED
**Depends on:** #459 (the 2026-08-19 bumps and waiver refresh, merged)
**Closes:** #451 §3, and the recurrence behind #450

## Why

`.trivyignore.third-party` holds 56 exceptions. Every week a workflow slides
their `exp:` dates forward, a human is asked to review 50-odd entries, and the
file is exactly as large the following week. That is the treadmill.

It is not merely tedious. On **2026-08-19** `make scan-images` was **failing**
on `grafana/alloy:v1.18.1` — two unwaived HIGHs (`CVE-2026-56864`,
`CVE-2026-56865`) that entered the vulnerability database *after* the previous
day's renewal review. Nobody had changed that image. The security gate broke
because the ignorefile went stale underneath it, and nothing noticed until
someone re-scanned by hand.

Three causes, measured:

### 1. The renewal workflow never scans

`.github/workflows/trivyignore-renewal.yml` runs `scan_exceptions.py`
(a listing) and `renew_trivyignore.py` (a date rewrite, `renew_trivyignore.py:47`).
Neither invokes Trivy. The workflow therefore **cannot** detect a CVE that did
not exist last week — it can only re-date the ones already written down.

That is the exact mechanism behind the 2026-08-19 gate failure, and it will
recur on 2026-08-26 unchanged.

### 2. Justifications are hand-written prose about versions that move

18 of the 56 entries claimed to cover `promtail:3.6.11` (removed in phase-825),
`grafana:13.0.4-ubuntu` (now 13.0.6) and `prom/haproxy-exporter:v0.15.0`
(retired in phase-820) — images **not in the deployment at all**. The waivers
were correct; the stated reason for each was false, which defeats the point of a
*justified* exception. #459 rewrote them from measured data, by hand. Nothing
stops them rotting again.

### 3. One image is two thirds of the file

Re-measured 2026-08-19, `aquasec/trivy:0.71.0`, no ignorefile, raw CVE-ID sets:

| Scenario | Entries needed | vs today |
|---|---:|---:|
| Today | 56 | — |
| After the #459 bumps | 56 | **0** |
| + Grafana 13.2.0 | 56 | **0** |
| **Without cadvisor** | **21** | **−35** |
| Without cadvisor **and** Grafana 13.2.0 | 34 | −22 |

```
 49 HIGH/CRIT  cadvisor v0.52.1        exclusive carrier of 24
 15            grafana 13.0.6-ubuntu   exclusive carrier of 4
 14            alloy v1.18.1           exclusive carrier of 3
  8            loki / node-exporter / redis_exporter / prometheus   exclusive carrier of 0
  0            haproxy, redis, docker-socket-proxy, ja4proxy-tap
```

`gcr.io/cadvisor/cadvisor:v0.52.1` is the only change that shrinks the file.
Upgrading it does not help — `v0.55.1` is a measured net regression (3C/46H →
3C/47H; clears `CVE-2024-41110` but adds `CVE-2026-31789`, also CRITICAL) and is
the newest published tag.

Note the ordering trap in that table: **Grafana 13.2.0 is entry-neutral today
but costs 13 entries once cadvisor is gone**, because cadvisor is currently
masking 13.2.0's new HIGHs. If both are wanted, cadvisor goes first and the
Grafana question is re-measured afterwards.

## The thing that makes §3 tractable

**Alloy already contains cadvisor.** Verified against
`grafana/alloy:v1.18.1` (the deployed digest):

```
prometheus.exporter.cadvisor            ← component present in the binary
github.com/google/cadvisor              ← library linked in
github.com/google/cadvisor/cache/memory
github.com/google/cadvisor/collector
github.com/google/cadvisor/container
```

So the stack runs cadvisor's code twice: once inside Alloy, which is deployed,
scanned and scraped anyway; and once as a standalone image carrying 49
HIGH/CRITICAL findings and 24 exclusive waivers.

**Precedent: phase-820 did this exact class of change.** It removed the
abandoned `prom/haproxy-exporter` sidecar in favour of HAProxy's built-in
exporter. That worked, and it required migrating alert selectors — the native
exporter labels series `proxy=` where the sidecar used `frontend=`/`backend=`
(`prometheus.yml:120-123`). Expect the same kind of migration here, and treat
"the metric names match" as something to prove, not assume.

## What depends on cadvisor today

Removing it is not free. Current consumers:

| Consumer | Detail |
|---|---|
| Recording rules | `ja4proxy:container_mem_pct`, `ja4proxy:container_cpu_throttle_ratio` (`recording_rules.yml:129-138`) |
| Alerts | container OOM kills, restart loops, memory pressure, CPU throttling, Redis memory headroom (`alerts.yml:409-581`) |
| Dashboard | `ja4proxy-infrastructure.json` |
| Scrape job | `prometheus.yml:102-118`, incl. two `metric_relabel_configs` |

Metrics actually referenced, by count:

```
14 container_mem_pct (recorded)      3 container_cpu_usage_seconds_total
 5 container_memory_working_set_bytes 2 container_start_time_seconds
 5 container_name                     2 container_oom_events_total
 4 container_cpu_throttle_ratio       4 container_network_* / container_fs_*
 3 container_spec_memory_limit_bytes  1 container_cpu_cfs_throttled_seconds_total
```

## Scope

### 829a — Make the renewal workflow measure, not just re-date

Highest value, smallest change, no security trade.

- Add a scan step to `trivyignore-renewal.yml`: run Trivy over the third-party
  image list (`scripts/check_image_versions.py --list-third-party`) with **no
  ignorefile**, and diff the measured HIGH/CRITICAL set against the waived set.
- Report **both** directions in the PR body:
  - **gaps** — measured but not waived. These break `make scan-images`. This is
    what nothing detected on 2026-08-19.
  - **dead entries** — waived but no longer carried by any deployed image.
    These are the only entries that can ever be deleted, and today nothing
    tells anyone they exist.
- Also check each image's registry for a newer tag and record the raw CVE-ID set
  difference, so the reviewer sees "v0.34.0 clears 20, introduces 2" instead of
  being asked to take release notes on trust.

A gap must fail the workflow loudly. A dead entry is informational.

### 829b — Generate the carrier claim

- New `scripts/refresh_trivyignore_justifications.py`: rewrite each entry's
  "carried by" line from scan data, leaving the human "why not exploitable here"
  reasoning untouched. That half is a judgement about our deployment and must
  never be machine-written.
- Run it from 829a's workflow so the claim cannot drift from reality again.
- The file's dated history sections are **not** regenerated — they record what
  was true at the time and rewriting them would falsify the record.

### 829c — Replace the standalone cadvisor with Alloy's built-in exporter

The −35 entries. Also the only part with a real downside.

1. Enable `prometheus.exporter.cadvisor` in `deploy/monitoring/alloy/config.alloy`.
2. Run **both** in parallel for one observation window and diff the emitted
   series — names *and* labels — before removing anything.
3. Migrate alert/recording-rule selectors for whatever differs.
4. Remove the `cadvisor` service and its scrape job; delete the newly-dead
   ignorefile entries (829a will list them).

**The security trade, stated plainly.** Alloy today runs `cap_drop: ALL`, no
Docker socket, as uid 473 — deliberately, per `JA4PROXY-2026-0017`. cadvisor
needs `SYS_PTRACE`, `DAC_READ_SEARCH`, and read mounts of `/rootfs`, `/sys`,
`/var/lib/docker`, `/dev/disk` and `/dev/kmsg` — themselves already the reduced
set from `JA4PROXY-2026-0016`, which cut it back from `privileged: true`.

Merging them gives the process that reads every container's logs the host
visibility cadvisor needs. That is a genuine concentration of privilege, and it
is the reason this is a phase and not a chore. The alternative — accept cadvisor
as a permanent, separately-documented exception set and stop re-litigating 24
entries weekly — is a legitimate outcome of this phase, not a failure of it.

## Testable outcomes

| # | Outcome | How it is measured |
|---|---|---|
| O1 | A CVE present in a deployed image but absent from the ignorefile fails the renewal workflow | Inject a synthetic finding; assert non-zero exit and a named gap |
| O2 | A waived CVE carried by no deployed image is reported as dead | Add a bogus entry; assert it is listed for deletion |
| O3 | The renewal PR body states measured deltas, not release notes | Assert the body contains cleared/introduced ID counts per candidate bump |
| O4 | A date-only renewal cannot mask a new CVE | Regression test for the 2026-08-19 failure: renew with a DB containing an unwaived CVE → workflow fails |
| O5 | Carrier claims are generated, never hand-written | Run the generator twice; second run is a no-op diff |
| O6 | The generator never rewrites the human "why not exploitable" text | Assert those lines are byte-identical across a run |
| O7 | Dated history sections are never regenerated | Assert the pre-1900-char header is byte-identical after a run |
| O8 | Alloy's cadvisor exporter emits every metric the alerts use | Diff series names against the 16 referenced metrics; assert none missing |
| O9 | Label sets match, or every divergence has a migrated selector | Diff label keys per metric; each difference maps to an updated rule |
| O10 | No alert or recording rule references a metric nothing emits | Parse `alerts.yml` + `recording_rules.yml`, assert every `container_*` is in the live scrape |
| O11 | Removing cadvisor deletes exactly the entries 829a predicted | Assert post-removal ignorefile == predicted set (21) |
| O12 | Alloy's added privileges are the minimum cadvisor needs, and enumerated | Assert the compose diff adds only `SYS_PTRACE`/`DAC_READ_SEARCH` + the named read-only mounts |

## Tests

**`tests/unit/test_trivyignore_drift.py`** (829a)

- `test_unwaived_cve_is_reported_as_a_gap` (O1)
- `test_gap_fails_the_check` (O1) — exit code, not just output. A report nobody
  reads is what produced the 2026-08-19 failure.
- `test_waived_but_uncarried_cve_is_reported_dead` (O2)
- `test_date_only_renewal_does_not_hide_a_new_cve` (O4) — the direct regression
  test for this phase's founding incident.
- `test_clean_state_is_silent` (O1/O2) — vacuity guard: a correct file must
  produce no gaps and no dead entries, or the checker is asserting nothing.

**`tests/unit/test_justification_generator.py`** (829b)

- `test_carrier_line_matches_scan_data` (O5)
- `test_generator_is_idempotent` (O5)
- `test_human_reasoning_is_untouched` (O6)
- `test_dated_history_is_untouched` (O7)
- `test_entry_count_is_unchanged` (O5) — a generator that silently drops an
  entry would delete a waiver and break the gate.

**`tests/integration/test_container_metrics_parity.py`** (829c)

- `test_every_referenced_metric_is_emitted` (O8) — parses the rules for
  `container_*` and checks each against the live Alloy scrape.
- `test_label_keys_match_for_referenced_metrics` (O9)
- `test_no_rule_references_a_dead_metric` (O10) — catches the phase-820 failure
  mode (`frontend=` → `proxy=`) before it reaches an alert that silently never
  fires.
- `test_alerts_still_evaluate_after_migration` (O10) — load rules into
  `promtool check rules`.

**`tests/unit/test_monitoring_privileges.py`** (O12)

- `test_alloy_gains_only_the_capabilities_cadvisor_needed`
- `test_alloy_does_not_gain_the_docker_socket` — `JA4PROXY-2026-0017` removed it
  deliberately; this phase must not reintroduce it by the back door.

## Risks

| Risk | Mitigation |
|---|---|
| Alloy's exporter emits different labels; alerts silently stop firing | O9/O10, and the parallel-run window in 829c step 2. This exact failure has happened here before (phase-820) |
| Concentrating cadvisor's host access into the log shipper | O12 bounds it to the minimum; if the trade is judged bad, the phase's answer is the documented-permanent-exception route instead |
| A generated justification reads as authoritative but is only a carrier list | 829b generates the carrier claim **only**; the exploitability judgement stays human |
| 829a's scan lengthens the weekly workflow | It scans 12 images that are already pulled by `make scan-images`; run it on the same schedule, not per-push |
| Removing cadvisor loses OOM/restart alerting during migration | Parallel run before removal; do not delete the scrape job and the service in the same commit |

## Non-goals

- Not deciding the Grafana 13.2.0 question (#451 §2). It must be re-measured
  **after** 829c, because cadvisor currently masks 13.2.0's new HIGHs.
- Not changing the exception policy itself (7-day windows, one entry per CVE).
- Not touching `.trivyignore.first-party` — different rule, different file.

## Acceptance

- [ ] O1–O12 have passing tests, each mutation-checked or carrying a vacuity guard
- [ ] `make test`, `make lint`, `make scan` pass
- [ ] A dry run of the renewal workflow against a deliberately-stale ignorefile
      reports the gap and exits non-zero
- [ ] If 829c lands: `make scan-exceptions` shows 21 third-party entries, and
      every alert that referenced a `container_*` metric still evaluates
- [ ] If 829c is rejected on privilege grounds: that decision is recorded as an
      ADR, and the cadvisor entries are moved to a clearly-labelled permanent
      section so they stop consuming weekly review
