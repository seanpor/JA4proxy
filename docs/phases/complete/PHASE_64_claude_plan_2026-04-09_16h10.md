# Phase 64 — Review & Re-plan (2026-04-09 16:10)

> **Status:** PROPOSAL — supersedes the structure of `PHASE_64.md`.
> **Author:** Claude (Opus 4.6), commissioned review.
> **Scope:** Pure docs/scripts/YAML. **No Go code, no Python code.** Every
> sub-phase below ships either a shell script, a Markdown runbook, a
> Prometheus alert rule, or an append to an existing tool.

---

## 1. Why this re-plan exists

`PHASE_64.md` was originally drafted when the Python proxy (`proxy.py`) was
production. It was lightly patched on 2026-04-09 with a "Hot-reload signal
target — read this first" preamble that retrofits Go-correct commands at the
top, but the body of the document still carries Python-prototype DNA and
several stale assumptions. Since that draft was written, two things have
happened:

1. **Phase 63 shipped the TLS cert-expiry gauge** (`ja4proxy_tls_cert_expiry_timestamp_seconds`,
   `internal/metrics/metrics.go` + `cmd/proxy/main.go`).
2. **The Phase 200-series strategic review** (200, 201, 202, 203) was carved
   out and now owns every Go-runtime correctness, security, and CI gap.
   Phase 64 must not duplicate any of that work.
3. **Phase 101** (cross-phase gap register) exists for items that fall out of
   scope of any one phase.

This document records the review findings, lists what is genuinely still
needed, and re-organises the remaining work into nine independent
sub-phases that a junior team can pick up in parallel.

---

## 2. Findings — what is stale or wrong in PHASE_64.md

| § in PHASE_64.md | Issue | Reality |
|---|---|---|
| §6.1 | Wraps the cert-expiry alert in `unless absent_over_time(...)` "until Phase 63 lands the gauge" | **Phase 63 is COMPLETE.** The gauge is live. The guard clause is no longer needed and should be removed. |
| §3.5, §5, §7 | Reference `ja4proxy-cli backup list / restore / run --immediate` | The Go `ja4proxy-cli` (`cmd/ja4proxy-cli/main.go`) has `dial`, `config reload`, `health`, `ip`, `allowlist`, `blocklist`, etc. — **no `backup` subcommand**. Phase 19 backup/restore is a separate tool surface; the runbook must call whatever Phase 19 actually shipped, not invent commands. |
| §2.3 | Podman/Quadlet smoke test copies `deploy/rhel/quadlets/*.{container,network,kube}` | **That directory does not exist.** Phase 76 was a paper-only "best practices" phase. The smoke test has nothing to copy. This deliverable is blocked until someone produces real Quadlet unit files. |
| §2.1, §7.2, §8 | Use `docker-compose` (v1, EOL) and `docker volume rm ja4proxy_redis-data` (a guess) | Should use `docker compose` (v2). Volume name must be confirmed against `docker-compose.poc.yml` rather than guessed. |
| §3.5 prose | "If a recent Phase 19 backup exists…" — written conditionally | Phase 19 is COMPLETE. The runbook can be definite, not hedged. |
| §3.2 | Mixes `ja4proxy@1` systemd template names with `docker-compose ps ja4proxy-1` in the same scenario | Confusing for a junior reader. Either pick one deployment model per scenario, or factor the deployment-specific commands into a small lookup table at the top of the runbook. |
| §5, §6, §7 | Several `pkill -HUP -f bin/proxy` "dev fallback" notes | Belong in the legacy/dev overlay's own docs, not the main production runbooks. Drop them — the operator running these commands is on production. |
| Whole doc | Never states "no Go code; no Python code" | Should be the headline so a junior dev knows this is a non-code phase and doesn't try to "fix" the Go binary. |

### Items already covered elsewhere (drop / cross-link only)

- **Phase 202** — `Dockerfile.go-proxy` USER hardening, default credential
  removal, GitHub Actions SHA-pinning, SBOM/cosign image signing. Already
  scoped. PHASE_64 should cross-link, not duplicate.
- **Phase 200 / 201 / 203** — Go correctness gaps (PROXY protocol trust,
  Redis TLS, signal score drift, missing JA4T/weak ciphers/DGA/health
  checks). Unrelated to deployment validation; keep a "see also" line so
  reviewers do not conflate the two work-streams.
- **Phase 101** — Cross-phase gap register. Items that can't be addressed in
  PHASE_64 should be filed there (see §5 below).

---

## 3. What is still genuinely needed

Eight artifacts. All are scripts, Markdown, or YAML. No code changes to the
Go proxy or any service.

1. `scripts/smoke/test_docker_compose.sh` — CI-runnable end-to-end stack
   smoke test. Compatible with Docker Compose v2.
2. `scripts/smoke/test_helm_kind.sh` — CI-optional Helm + kind smoke test.
3. `docs/runbooks/disaster_recovery.md` — five failure scenarios, each with
   symptoms, impact, simulate command, recovery steps, RTO, RPO. Opens
   with a "See also" block linking to the existing runbook library
   (`redis_operations.md`, `go_proxy_operations.md`,
   `security_incident_response.md`, `feed_management.md`,
   `external_api_failures.md`, `scaling.md`, `zero_downtime_rollouts.md`).
   Does **not** duplicate any of those.
4. `docs/runbooks/gameday_scenarios.md` — four GameDay exercises, designed
   to be runnable in the staging stack without consulting the runbook.
5. `docs/runbooks/credential_rotation.md` — Redis password (zero-downtime
   via Redis ACL), AbuseIPDB API key, S3/GCS IAM keys.
6. `docs/runbooks/tls_certificate_rotation.md` + new
   `monitoring/alertmanager/rules/tls_alerts.yml` containing
   `JA4proxyTLSCertExpiringSoon` (warning, < 30 days) and
   `JA4proxyTLSCertExpiryCritical` (critical, < 7 days). **No
   `absent_over_time` guard** — Phase 63's gauge is live.
7. `docs/runbooks/rolling_upgrade.md` — Docker Compose path, Kubernetes
   path (DaemonSet rolling update via Helm), and rollback for both.
8. `scripts/measure_mttr.sh` → `MTTR_BASELINE.md`, plus a `--section
   deployment` flag added to `scripts/generate_validation_report.py` that
   embeds smoke-test results, the MTTR baseline, and the DR exercise
   history into the validation report.

---

## 4. Sub-phase split

Nine sub-phases. Each is one branch, one PR, one reviewer. No sub-phase
blocks any other (the only inter-dependency is that 64i *reads* the output
of 64a and 64h when present, and degrades gracefully when absent — the
original `_section_deployment()` already does this).

### Conventions for every sub-phase

- All work happens on `claude/phase-64<letter>-<description>`.
- All shell scripts: `set -euo pipefail`, exit 0 = pass, exit 1 = fail with
  reason on stderr, structured output under `test-results/smoke/` where
  applicable.
- All Markdown runbooks: H1 title, "See also" block linking to existing
  runbooks before any new content, every command block prefixed by what it
  does and what success looks like.
- Every sub-phase MUST be tested by the author against either the local
  `make start` stack or a `kind` cluster before opening the PR. "I read
  the script and it looks right" is not acceptance.
- Each sub-phase ends by writing a `PHASE_64<letter>_notes.md` summarising
  what was done, what was tested, and any new Phase 101 gap entries that
  fell out of the work.

### File ownership matrix

| Sub-phase | Owns (creates) | Touches (appends only) |
|---|---|---|
| 64a | `scripts/smoke/test_docker_compose.sh` | `Makefile` (bottom), `.github/workflows/ci.yml` (new job) |
| 64b | `scripts/smoke/test_helm_kind.sh` | `Makefile` (bottom), `.github/workflows/ci.yml` (new optional job) |
| 64c | `docs/runbooks/disaster_recovery.md` | — |
| 64d | `docs/runbooks/gameday_scenarios.md` | — |
| 64e | `docs/runbooks/credential_rotation.md` | — |
| 64f | `docs/runbooks/tls_certificate_rotation.md`, `monitoring/alertmanager/rules/tls_alerts.yml` | `Makefile` (only if a `lint-alertmanager` target needs the new file) |
| 64g | `docs/runbooks/rolling_upgrade.md` | — |
| 64h | `scripts/measure_mttr.sh`, `MTTR_BASELINE.md` | `Makefile` (bottom) |
| 64i | (extends) `scripts/generate_validation_report.py` | — |

There is **no shared-file conflict** between any two sub-phases except the
bottom of `Makefile`, where each sub-phase appends its own named target
under a `## Phase 64<letter>` comment per CLAUDE.md's shared-file rules.

---

### Sub-phase 64a — Docker Compose smoke test

**Deliverable:** `scripts/smoke/test_docker_compose.sh` and a
`make smoke-docker` target. Required CI status check.

**What the script must do:**
1. `mkdir -p test-results/smoke` and open a timestamped log.
2. `docker compose up -d` (note: v2 syntax, no hyphen).
3. Poll `http://localhost:8090/api/v1/health/deep` for up to 60 s; fail if
   it never returns 200.
4. Verify every service in `docker compose ps --format json` has
   `State == "running"`. Fail with the list of unhealthy services if not.
5. Send a synthetic TLS connection to `localhost:8080` via
   `openssl s_client`. Treat any TLS-layer response as success; treat
   `Connection refused` as failure (the proxy is not listening).
6. `docker compose down -v` and write `PASS` to
   `test-results/smoke/docker-compose.result` on success.

**Acceptance criteria:**
- [ ] Script runs to PASS on a clean clone after `make build`.
- [ ] Script exits non-zero with a clear stderr message if any container is
      not running.
- [ ] `make smoke-docker` invokes the script.
- [ ] CI job `smoke-docker` is added to `.github/workflows/ci.yml` as a
      required status check on PRs targeting `main`.
- [ ] Script uses `docker compose` (v2), never `docker-compose` (v1).
- [ ] `PHASE_64a_notes.md` records the host the script was tested on,
      compose version, and the resulting log file.

**Out of scope:** Helm, kind, podman, MTTR measurement.

---

### Sub-phase 64b — Helm + kind smoke test

**Deliverable:** `scripts/smoke/test_helm_kind.sh` and a `make smoke-k8s`
target. Optional CI status check (only runs when `helm/kind-action` is
present).

**What the script must do:**
1. Skip with exit 0 and a clear `SKIP:` message if `kind` or `helm` are not
   on `$PATH`.
2. Create a single-node `kind` cluster named `ja4proxy-smoke`. Always
   delete it on exit via `trap`.
3. `helm install ja4proxy deploy/helm/ja4proxy/ --wait --timeout=120s`.
4. `kubectl rollout status daemonset/ja4proxy --timeout=60s`.
5. `kubectl exec` into the first pod and curl its in-pod health endpoint.
6. Write `PASS` to `test-results/smoke/helm-kind.result` on success.

**Acceptance criteria:**
- [ ] Script runs to PASS on a workstation with `kind` and `helm`
      installed.
- [ ] Script skips cleanly (exit 0, no error) when `kind` is absent.
- [ ] CI job `smoke-k8s` added to `.github/workflows/ci.yml` using
      `helm/kind-action@v1` as a prior step. Job is non-blocking
      (continue-on-error) until the team confirms it is stable, then
      promoted to required.
- [ ] `PHASE_64b_notes.md` records kind version, helm version, and the pod
      log on success.

**Out of scope:** Helm chart changes (chart already exists). If the chart
needs fixing for the smoke test to pass, that fix is a separate PR against
the Helm chart owner — file a Phase 101 entry rather than blocking 64b.

---

### Sub-phase 64c — Disaster Recovery runbook

**Deliverable:** `docs/runbooks/disaster_recovery.md`.

**Structure (mandatory):**

1. **See also** block — bullet list linking to every existing runbook in
   the table at PHASE_64.md §3.6. Reviewer must reject the PR if this
   block is missing or if the body duplicates content from any linked
   runbook instead of linking to it.
2. **Deployment quick reference** — small table mapping
   {Docker Compose, Kubernetes, RHEL/Quadlet} to the equivalent
   `start / stop / status / logs / hot-reload` commands. Every later
   scenario references this table by name instead of inlining commands
   for all three deployment types.
3. **Five scenarios**, each with the same H3 substructure:
   - Symptoms (what an operator observes first)
   - Impact (what the proxy does during the failure)
   - Simulate (the exact command to trigger this in a test stack)
   - Recovery steps (numbered, with expected output for each command)
   - RTO target
   - RPO
4. **Runbook Exercise History** — empty H2 section that 64d will populate
   after the first GameDay.

**The five scenarios:**
1. Redis failure (proxy fails open; restore Redis; verify reconnect).
2. Single proxy node failure (HAProxy detects within `inter` seconds;
   restart node; verify backend UP).
3. Total fleet failure (P1; collect logs; identify cause; revert config if
   needed; restart fleet).
4. Config corruption / malformed dial change (drop to monitor mode first,
   then revert config, then restore intended dial).
5. Redis data loss (distinct from scenario 1; bans / rate-limit state
   gone; restore from Phase 19 backup if available, else dial=0 while
   state rebuilds from live traffic).

**Acceptance criteria:**
- [ ] File exists with all five scenarios in the structure above.
- [ ] "See also" block present and links to every existing runbook in the
      §3.6 table.
- [ ] No scenario duplicates content from any linked runbook (reviewer
      check).
- [ ] No reference to `ja4proxy-cli backup` — must call whatever Phase 19
      shipped (verify by reading PHASE_19 notes / its CLI surface).
- [ ] Scenario 5 references the Phase 19 backup tool by its actual name
      and command.
- [ ] All hot-reload commands use Go-production form
      (`systemctl kill --signal=HUP ja4proxy.service` or container/pod
      equivalents). No `pkill -f proxy.py`, no `pkill -f bin/proxy`.
- [ ] `PHASE_64c_notes.md` lists which Phase 19 commands were verified
      against the actual tool.

---

### Sub-phase 64d — GameDay scenarios doc

**Deliverable:** `docs/runbooks/gameday_scenarios.md` and the first
"Runbook Exercise History" entry in `docs/runbooks/disaster_recovery.md`.

**Content:** Four GameDay exercises (Redis outage, node failure, total
fleet failure, dial corruption), each with environment, duration, trigger
command, what the team is expected to do *before* opening the runbook, and
success criteria with measurable RTO targets.

**Acceptance criteria:**
- [ ] File exists with all four exercises in the structure above.
- [ ] Each exercise links back to the matching scenario in
      `disaster_recovery.md`.
- [ ] After the author runs the first GameDay (Redis outage) against the
      local `make start` stack, they append a dated entry to the
      "Runbook Exercise History" section of `disaster_recovery.md`
      recording the date, the team member who ran it, the measured MTTR,
      and any gaps found.
- [ ] `PHASE_64d_notes.md` records what gaps the first GameDay surfaced
      (file each as a Phase 101 entry).

**Coordination note:** 64d touches `disaster_recovery.md` (created by
64c). If 64c is not yet merged, 64d holds the "Runbook Exercise History"
edit for a follow-up commit on the 64d branch *after* 64c lands. This is
the only inter-sub-phase ordering.

---

### Sub-phase 64e — Credential rotation runbook

**Deliverable:** `docs/runbooks/credential_rotation.md`.

**Sections:**
1. Redis auth password rotation — zero-downtime via Redis ACL
   (`ACL SETUSER default on >NEW >OLD …`), staged hot reload across all
   proxy nodes, then drop the old password.
2. AbuseIPDB API key rotation — verify new key, hot reload, watch
   `ja4proxy_abuseipdb_lookups_total{result="hit"}`, then revoke old key
   in the AbuseIPDB dashboard with a 30-second safety delay.
3. Cloud storage credentials (AWS S3 + GCS) — IAM key rotation, secret
   update, restart of the backup container, manual backup verification,
   then delete the old IAM key.

**Acceptance criteria:**
- [ ] All three rotation procedures documented with the steps above.
- [ ] All hot-reload commands use Go-production form.
- [ ] Each procedure has an explicit "Rollback" subsection that gets the
      old credential back into service quickly if anything goes wrong.
- [ ] No `kill -HUP $(pgrep -f proxy.py)`. No `ja4proxy-cli backup`
      references unless that command actually exists.
- [ ] `PHASE_64e_notes.md` records that each procedure was at minimum
      dry-run-walked through against the local stack.

---

### Sub-phase 64f — TLS certificate rotation runbook + alert rule

**Deliverable:**
- `docs/runbooks/tls_certificate_rotation.md`
- `monitoring/alertmanager/rules/tls_alerts.yml`

**Runbook sections:**
1. Certificate expiry monitoring — references the Phase 63 gauge and
   points to the new alert rule file.
2. Server-side TLS certificate rotation (rolling, one node at a time, hot
   reload via SIGHUP).
3. mTLS CA certificate rotation with a dual-CA trust bundle period (combined
   PEM file → reload → migrate clients → drop old CA → reload).

**Alert rules (`tls_alerts.yml`):**
```yaml
groups:
  - name: tls_certificate_expiry
    rules:
      - alert: JA4proxyTLSCertExpiringSoon
        expr: (ja4proxy_tls_cert_expiry_timestamp_seconds - time()) / 86400 < 30
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "TLS certificate expires in {{ $value | humanize }} days"
          description: |
            The proxy's server-side TLS certificate expires in less than 30 days.
            Rotate using docs/runbooks/tls_certificate_rotation.md.

      - alert: JA4proxyTLSCertExpiryCritical
        expr: (ja4proxy_tls_cert_expiry_timestamp_seconds - time()) / 86400 < 7
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "TLS certificate expires in {{ $value | humanize }} days — CRITICAL"
          description: |
            The proxy's server-side TLS certificate expires in less than 7 days.
            Rotate immediately using docs/runbooks/tls_certificate_rotation.md.
```

**No `absent_over_time` guard.** Phase 63's gauge is live.

**Acceptance criteria:**
- [ ] Runbook file exists with all three sections.
- [ ] Alert rule file exists, parses cleanly under `make lint-alertmanager`
      (or whatever the existing alertmanager lint target is called).
- [ ] Runbook references the Phase 63 gauge by its real name
      (`ja4proxy_tls_cert_expiry_timestamp_seconds`).
- [ ] No mention of Phase 63 being incomplete or pending.
- [ ] `PHASE_64f_notes.md` records the lint result and a manual sanity
      check that the gauge actually exists in
      `internal/metrics/metrics.go`.

---

### Sub-phase 64g — Rolling upgrade runbook

**Deliverable:** `docs/runbooks/rolling_upgrade.md`.

**Sections:**
1. Prerequisites — HAProxy with health checks, ≥ 2 instances, smoke test
   passing in staging.
2. Docker Compose rolling upgrade — drain via HAProxy admin socket,
   recreate one service at a time, wait for health, re-enable, repeat.
3. Kubernetes rolling upgrade — `helm upgrade` with `--wait`, monitor via
   `kubectl rollout status`. DaemonSet `maxUnavailable: 1` invariant.
4. Rollback procedure — both deployment models, specifying the exact
   command (`docker compose up -d --force-recreate --image …` /
   `kubectl rollout undo daemonset/ja4proxy`).

**Acceptance criteria:**
- [ ] Runbook covers all four sections.
- [ ] All commands use `docker compose` (v2), not `docker-compose` (v1).
- [ ] Rollback subsections give a single-command answer for each
      deployment type.
- [ ] `PHASE_64g_notes.md` records that the rollback path was at minimum
      dry-run-walked through.

---

### Sub-phase 64h — MTTR baseline automation

**Deliverable:** `scripts/measure_mttr.sh`, a `make measure-mttr` target,
and a committed `MTTR_BASELINE.md` produced by running the script once.

**Script behaviour:**
- Brings up the local Compose stack and waits for `health/deep` healthy.
- Runs Scenarios 1, 2, 4, 5 from PHASE_64.md §3 (3 is GameDay-only).
- Measures wall-clock time from trigger to recovery.
- Writes `MTTR_BASELINE.md` with a results table mapping scenario →
  measured MTTR → RTO target → PASS/FAIL.
- Exits 0 if all four scenarios are within RTO; 1 otherwise.

**Acceptance criteria:**
- [ ] Script runs end-to-end on the local stack and produces
      `MTTR_BASELINE.md`.
- [ ] All four scenarios PASS within their RTO targets on the author's
      workstation. If any fail, file a Phase 101 entry rather than
      lowering the target.
- [ ] `MTTR_BASELINE.md` is committed.
- [ ] `make measure-mttr` invokes the script.
- [ ] Script uses `docker compose` (v2).
- [ ] Volume name in scenario 5 is verified against
      `docker-compose.poc.yml`, not guessed.
- [ ] `PHASE_64h_notes.md` records the host CPU/RAM and the four
      measured MTTR values.

**Out of scope:** Scenario 3 automation (deliberately GameDay-only).

---

### Sub-phase 64i — Validation report deployment section

**Deliverable:** `--section deployment` flag added to
`scripts/generate_validation_report.py`.

**Behaviour:** When passed `--section deployment`, the script appends a
"Deployment Validation Evidence" section containing:
- Smoke test results (read from `test-results/smoke/*.result`).
- MTTR baseline table (read from `MTTR_BASELINE.md` and embedded
  verbatim).
- DR runbook exercise history (extracted from the matching section in
  `docs/runbooks/disaster_recovery.md`).

**Graceful degradation:** If any input is missing, the section emits a
single line stating what to run to produce it. The script never fails
because an input is missing — it is meant to run alongside in-progress
work.

**Acceptance criteria:**
- [ ] Flag works end-to-end with all inputs present (run after 64a + 64h
      + 64c + 64d have all merged, or stage them locally).
- [ ] Flag works gracefully with all inputs absent (each missing input
      produces a single helpful line, no exception).
- [ ] At least one unit test for the new code path under `tests/`.
- [ ] `PHASE_64i_notes.md` records both the all-present and all-absent
      runs.

---

## 5. Items dropped from scope — file as Phase 101 entries

| Dropped item | Why | Phase 101 entry to file |
|---|---|---|
| Podman/Quadlet smoke test (`scripts/smoke/test_podman_quadlet.sh`) | `deploy/rhel/quadlets/` does not exist; Phase 76 was paper-only | "Phase 76 produced a strategy doc but no Quadlet artifacts. Phase 64 cannot ship the Quadlet smoke test until `deploy/rhel/quadlets/{*.container,*.network,*.kube}` exist. Owner: TBD." |
| `ja4proxy-cli backup …` references | The Go CLI does not have a `backup` subcommand; Phase 19's tool is separate | "Document discrepancy: PHASE_64.md (and possibly other phases) reference `ja4proxy-cli backup` commands that do not exist on the Go CLI. Audit all runbooks for similar phantom commands." |
| `absent_over_time` guard on cert-expiry alert | Phase 63's gauge is live | (No entry needed — fully resolved by 64f.) |
| Mixed deployment-model commands in DR scenarios | Confuses readers | (No entry — resolved by 64c's "Deployment quick reference" table.) |

---

## 6. What this re-plan does NOT change

- **Phase 64's epic membership** in `manifest.yaml` stays as it is
  (Operations / Enterprise Readiness epic — whichever it currently sits
  in).
- **The `Depends on: Phase 63` line** in PHASE_64.md is now satisfied;
  no other phase dependency needs editing.
- **Phases 200, 201, 202, 203** are untouched. They remain the right
  place for Go correctness work.
- **Phase 101** receives at most two new gap entries (see §5).

---

## 7. Recommended landing order (not required — sub-phases are independent)

If a single agent picks up multiple sub-phases sequentially, the most
useful order is:

1. **64a** (Compose smoke) — gives CI a real smoke gate.
2. **64h** (MTTR script) — depends on 64a being green to be meaningful.
3. **64c** (DR runbook) — backbone for 64d, 64e, 64f, 64g.
4. **64f** (TLS cert rotation + alert) — small, high-value, no
   dependencies.
5. **64e** (Credential rotation) — small, no dependencies.
6. **64g** (Rolling upgrade) — small, no dependencies.
7. **64b** (Helm + kind smoke) — useful but optional in CI.
8. **64d** (GameDay doc + first exercise log) — needs 64c merged first
   for the cross-link to land cleanly.
9. **64i** (Validation report section) — last, so its end-to-end test
   can use real outputs from 64a/64c/64d/64h.

A team running multiple sub-phases in parallel can ignore this order
entirely. The only true ordering constraint is that **64d's edit to
`disaster_recovery.md` must follow 64c's creation of that file**.

---

## 8. Open questions for the maintainer

1. The original PHASE_64.md should be either (a) replaced wholesale by
   nine new files (`PHASE_64a.md` … `PHASE_64i.md`) and a one-line
   "superseded by sub-phases" note, or (b) restructured in place into
   nine sub-sections that map 1:1 to the sub-phases above. Which form
   does the maintainer prefer? **This document does not pre-empt that
   choice** — it captures the plan only.
2. Is there an existing Phase 19 backup CLI invocation that 64c, 64e,
   and 64h should standardise on? If so, supply the canonical command
   string and the agents will use it verbatim.
3. Should 64a's CI job be added as a *required* status check immediately,
   or merged as non-blocking first and promoted after a one-week
   stability window? Recommendation: non-blocking → promote.
