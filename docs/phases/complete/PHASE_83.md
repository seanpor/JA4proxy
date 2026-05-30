# Phase 83: `ja4proxy-cli` Go Binary

> **Prerequisites:** Phase 79 (Management API v2 — stable endpoints and auth).
> Phase 82 (Policy-as-Code — `policy validate/apply/diff` contract to match).

> **Scope note:** The original Phase 83 covered CLI + Terraform provider + Kubernetes
> operator + CMDB/NetBox + emergency playbooks. After review, scope was split:
> - Phase 83 (this file): `ja4proxy-cli` binary only
> - Phase 93: Terraform provider + emergency runbook playbooks
> - Phase 94: Kubernetes operator + CMDB/NetBox integration

---

## 1. Overview

Platform engineers and on-call SREs operate from terminals, especially at 2 AM
during incidents. `ja4proxy-cli` is the single most-requested day-2 tool identified
in the enterprise readiness gap analysis. It replaces the Python stopgap script
(`scripts/ja4proxy-policy.py`) and provides a stable, signed binary for all
terminal-based operations.

The CLI stub (mock responses, cobra scaffolding, output formatters) **can and should
be developed in parallel with waiting for Phase 79 to merge**, switching to the real
API once it is available. Integration tests run against `ManagementAPIMock`.

---

## 2. Command Reference

```
ja4proxy-cli ip lookup <ip>
  → score history, active bans, signal breakdown, last 10 connections
  (client-side aggregation: calls /api/v1/bans/{ip} + /api/v1/connections?ip=&limit=10)

ja4proxy-cli ip ban <ip-or-cidr> [--ttl 3600] [--reason "scanning activity"]
  → POST /api/v1/bans/{ip} (IP in path; body: ttl seconds + reason; CIDRs work natively)

ja4proxy-cli ip release <ip> [--confirm]
  → DELETE /api/v1/bans/{ip}; requires --confirm

ja4proxy-cli ip watchlist add <ip> [--ttl 24h] [--reason "monitoring"]
  → POST /api/v1/watchlist

ja4proxy-cli ip watchlist remove <ip> [--confirm]
  → GET /api/v1/watchlist?ip=<ip> to find ID, then DELETE /api/v1/watchlist/{id}
  (lookup-then-delete pattern; errors if no matching entry found)

ja4proxy-cli allowlist add <ja4-fingerprint> [--reason "..."] [--expires 2027-01-01] [--ticket CHG0001]
  → POST /api/v1/allowlist

ja4proxy-cli allowlist remove <ja4-fingerprint> [--confirm]
  → GET /api/v1/allowlist to find ID by ja4 value, then DELETE /api/v1/allowlist/{id}

ja4proxy-cli allowlist list [--output json|table|csv]
  → GET /api/v1/allowlist

ja4proxy-cli blocklist add <ja4-fingerprint> [--reason "..."] [--ticket INC0001]
  → POST /api/v1/blocklist

ja4proxy-cli blocklist remove <ja4-fingerprint> [--confirm]
  → GET /api/v1/blocklist to find ID by ja4 value, then DELETE /api/v1/blocklist/{id}

ja4proxy-cli blocklist list [--output json|table|csv]
  → GET /api/v1/blocklist

ja4proxy-cli dial get
  → GET /api/v1/dial

ja4proxy-cli dial set <0-100> --confirm [--ticket CHG0001234] [--notes "..."]
  → PATCH /api/v1/dial; prints "PENDING APPROVAL: {decision_id}" on 202

ja4proxy-cli config reload [--node ja4proxy-prod-03]
  → POST /api/v1/nodes/{host}/reload (all nodes: iterate GET /api/v1/nodes first)

ja4proxy-cli health [--all-nodes]
  → GET /api/v1/nodes (for all nodes) + GET /api/v1/health/deep (for local node)
  Table: node, status, version, dial, redis_latency_ms, uptime

ja4proxy-cli fingerprint <ja4> [--history 30d] [--output json|table]
  → GET /api/v1/fingerprints/{ja4}/history

ja4proxy-cli policy validate --file ja4proxy-policy.yaml [--current-dial N]
  → offline, no API; re-uses src/governance validation logic compiled into binary

ja4proxy-cli policy apply --file ja4proxy-policy.yaml [--dry-run] [--url <url>] [--token <tok>]
  → same Management API calls as scripts/ja4proxy-policy.py

ja4proxy-cli policy diff --file ja4proxy-policy.yaml [--url <url>] [--token <tok>]
  → same as Python stopgap; exit 0 = no drift, exit 1 = drift
```

### 2.1 Simulation Commands — Deferred

```
ja4proxy-cli simulation run/status/report
```

These commands require Phase 100-M (simulation API endpoints in the Management API).
In Phase 83, stub these commands with:
```
Error: simulation commands require Phase 100-M (simulation API not yet available)
```
Document stubs with `// TODO(phase-100-M)` comments.

---

## 3. Output Formats

All read commands (`list`, `lookup`, `health`, `fingerprint`, `dial get`) support:

```bash
--output table    # default; human-readable aligned columns
--output json     # machine-readable; pipeable to jq
--output csv      # for spreadsheet import
```

Mutating commands print one-line confirmations, always in plain text regardless of
`--output` setting. JSON output for list commands:

```bash
ja4proxy-cli allowlist list --output json | jq '.[].ja4'
ja4proxy-cli health --all-nodes --output json | jq '.[] | select(.status != "healthy")'
```

---

## 4. Authentication

Resolution order (first match wins):
1. `--token <value>` flag
2. `JA4PROXY_TOKEN` environment variable
3. `~/.config/ja4proxy/cli.yaml` key `token`
4. OS keychain via `99designs/keyring` (set on first interactive use)

URL resolution order:
1. `--url <value>` flag
2. `JA4PROXY_URL` environment variable
3. `~/.config/ja4proxy/cli.yaml` key `url`

Config file format (`~/.config/ja4proxy/cli.yaml`):
```yaml
url: https://ja4proxy-mgmt.corp.internal
token: ""            # leave blank to use keychain or env var
default_output: table
confirm_mutating: true   # set false to skip prompts in non-interactive scripts
```

---

## 5. Binary Distribution & Security

All releases must include:
- GPG signature (detached `.asc`) signed with the project's release key (stored in
  CI as a GitHub Actions secret `GPG_SIGNING_KEY`)
- SLSA provenance attestation (level 2: build on GitHub-hosted runner, provenance
  JSON uploaded to the GitHub release)
- `checksums.txt` with SHA-256 of every binary

Goreleaser handles all three when configured correctly. The release workflow lives at
`.github/workflows/release-cli.yml` (new in this phase). Document the signing setup
in `docs/developer/RELEASE_PROCESS.md`.

Distributed as:
- Standalone binary download from GitHub releases (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64)
- Container image `ghcr.io/anomalyco/ja4proxy-cli:latest` (`FROM scratch` + binary)
- Copied into the proxy container image at `/usr/local/bin/ja4proxy-cli` (update Dockerfile)

---

## 6. File Locations

All CLI code lives in the **existing Go module** (`github.com/anomalyco/ja4proxy`,
root `go.mod`). No new module or repo required.

```
cmd/ja4proxy-cli/
  main.go                       # cobra root; reads config, wires subcommands

internal/cli/
  client/
    client.go                   # aiohttp → net/http API client; all HTTP calls here
    client_test.go              # table-driven tests; uses httptest.NewServer()
  commands/
    ip.go                       # ip lookup, ban, release, watchlist add/remove
    ip_test.go
    allowlist.go                # allowlist add, remove, list
    allowlist_test.go
    blocklist.go
    blocklist_test.go
    dial.go                     # dial get, dial set
    dial_test.go
    config.go                   # config reload
    config_test.go
    health.go                   # health --all-nodes
    health_test.go
    fingerprint.go              # fingerprint <ja4> --history
    fingerprint_test.go
    policy.go                   # policy validate/apply/diff
    policy_test.go
    simulation.go               # stub only — returns Phase 100-M error
  output/
    table.go                    # tablewriter wrapper
    json.go                     # encoding/json wrapper
    csv.go                      # encoding/csv wrapper
    output_test.go
  auth/
    auth.go                     # token + URL resolution (flag → env → config → keychain)
    auth_test.go
  config/
    config.go                   # load/write ~/.config/ja4proxy/cli.yaml
    config_test.go

.github/workflows/
  release-cli.yml               # Goreleaser + GPG sign + SLSA provenance + checksums

docs/developer/
  RELEASE_PROCESS.md            # GPG key setup, Goreleaser config, signing verification
```

---

## 7. Phase 79 API Endpoint Mapping

Phase 79 is complete and merged to main. All endpoints below are verified against
the Phase 79 implementation in `management/api/routes/`.

| CLI Command | HTTP | Endpoint | Notes |
|-------------|------|----------|-------|
| `ip lookup` | GET | `/api/v1/bans/{ip}` + `/api/v1/connections?ip=&limit=10` | Client-side aggregation |
| `ip ban <ip>` | POST | `/api/v1/bans/{ip}` | IP is **path param**; body: `{ttl: int (seconds), reason: str}`. No ticket field in Phase 79 bans. |
| `ip ban <cidr>` | POST | `/api/v1/bans/{cidr}` | Same endpoint — `{ip:path}` allows `/` so CIDRs work natively (e.g. `/api/v1/bans/198.51.100.0/24`) |
| `ip release` | DELETE | `/api/v1/bans/{ip}` | `{ip:path}` — also handles CIDRs |
| `ip watchlist add` | POST | `/api/v1/watchlist` | Body: `{entry, reason, expires_at, ticket}` |
| `ip watchlist remove` | GET → DELETE | `/api/v1/watchlist` → `/api/v1/watchlist/{id}` | Lookup-then-delete |
| `allowlist add` | POST | `/api/v1/allowlist` | Body: `{entry, reason, expires_at, ticket}` |
| `allowlist remove` | GET → DELETE | `/api/v1/allowlist` → `/api/v1/allowlist/{id}` | Lookup-then-delete |
| `allowlist list` | GET | `/api/v1/allowlist` | Supports `?managed_by=` filter |
| `blocklist add` | POST | `/api/v1/blocklist` | |
| `blocklist remove` | GET → DELETE | `/api/v1/blocklist` → `/api/v1/blocklist/{id}` | Lookup-then-delete |
| `blocklist list` | GET | `/api/v1/blocklist` | |
| `dial get` | GET | `/api/v1/dial` | |
| `dial set` | PATCH | `/api/v1/dial` | Body: `{setting, notes}`; 202 → PendingApproval |
| `config reload` | GET + POST | `/api/v1/nodes` → `/api/v1/nodes/{host}/reload` | Iterate all nodes if `--node` not given |
| `health` | GET | `/api/v1/nodes` + `/api/v1/health/deep` | |
| `fingerprint` | GET | `/api/v1/fingerprints/{ja4}/history` | |
| `policy validate` | — | none (offline) | Calls compiled-in Go validator |
| `policy apply` | multiple | same as Python script | |
| `policy diff` | multiple | same as Python script | |
| `simulation *` | — | NOT AVAILABLE | Stub only — see §2.1 |

**Lookup-then-delete pattern:** `allowlist remove <ja4>` and `blocklist remove <ja4>`
do a `GET` list, search for an entry with matching `ja4` field, then `DELETE` by its
`id`. If no matching entry is found, exit 1 with "no entry found matching <ja4>".
Same logic for `watchlist remove <ip>`.

---

## 8. Parity with Python Stopgap

`scripts/ja4proxy-policy.py` is the current implementation of `policy validate/apply/diff`.
When Phase 83 ships, the Python script becomes the legacy path. The Go CLI must produce
**identical exit codes** and **equivalent output** for all known inputs.

### 8.1 Parity Requirements

| Behaviour | Python script | Go CLI must match |
|-----------|--------------|-------------------|
| Valid policy, `validate` | exit 0, stdout "Policy is valid." | identical |
| Invalid policy, `validate` | exit 1, stderr "ERROR: ..." | exit 1, stderr starts with "ERROR:" |
| Pending approval, `apply` | exit 2, stdout "PENDING APPROVAL: {id}" | identical |
| `apply` success | exit 0, stdout "N added, M removed, P unchanged" | identical |
| Drift detected, `diff` | exit 1, stdout "Drift detected: N unexpected entries" | exit 1, stdout contains "Drift detected" |
| No drift, `diff` | exit 0, stdout "No drift detected." | identical |

Error message text may differ between Python and Go implementations (cerberus vs Go
validation). Exit codes are the contract, not message text.

### 8.2 Parity Test

Add `tests/integration/test_cli_parity.py`:
- Compiles the Go CLI binary with `subprocess.run(["go", "build", ...])` in a `pytest`
  fixture (skip if Go toolchain not available)
- Runs a set of 8 known-good and known-bad policy YAML files through both the Python
  script and the Go CLI
- Asserts matching exit codes for each input
- Asserts the Python script can be retired without any CI change once Go CLI passes
  all cases

---

## 9. Test Plan

### Unit tests (in `internal/cli/`)

Each command file has a corresponding `_test.go`. Use `httptest.NewServer()` as the
mock API. No live network required.

| Test file | Coverage target |
|-----------|----------------|
| `client_test.go` | auth header sent, 401 → error, 5xx → error, timeout handling |
| `ip_test.go` | ban+release round-trip, watchlist add/remove, lookup aggregation |
| `allowlist_test.go` | add, list, remove (lookup-then-delete), remove-not-found |
| `blocklist_test.go` | same as allowlist |
| `dial_test.go` | get, set, 202 pending approval flow |
| `config_test.go` | reload all nodes, reload specific node |
| `health_test.go` | healthy output, degraded node highlighted |
| `fingerprint_test.go` | history output in table + json |
| `policy_test.go` | validate valid, validate invalid, apply dry-run |
| `output_test.go` | table/json/csv formatters for same data struct |
| `auth_test.go` | flag > env > config > keychain resolution order |

### Integration tests (against ManagementAPIMock)

Add `tests/integration/test_cli_integration_test.go` (Go) OR use existing Python
mock in `tests/mocks/management_api_mock.py`:
- Full command roundtrip: `ban → lookup (confirms ban) → release → lookup (no ban)`
- `allowlist add → list (entry present) → remove → list (entry gone)`
- `dial set` → mock returns 202 → CLI exits 2 with PENDING APPROVAL message
- `health --all-nodes` renders table with correct node count

### Parity tests

`tests/integration/test_cli_parity.py` — see §8.2.

### Makefile target

```makefile
## Phase 83 targets
test-phase-83:
	go test ./internal/cli/... -v -count=1
	python3 -m pytest tests/integration/test_cli_parity.py -v
.PHONY: test-phase-83
```

---

## 10. ADRs Required

Write before starting implementation:

| ADR | Decision | Options |
|-----|----------|---------|
| ADR-083a | Binary signing & release tooling | Goreleaser (recommended) vs manual `go build` + `gpg --detach-sign` |
| ADR-083b | Policy validator implementation in Go | Re-implement cerberus-equivalent in Go vs call Python subprocess vs API-only validate endpoint |

**ADR-083b detail:** The Python `policy validate` is offline (no API). The Go CLI
needs its own validation. Options:
- A: Re-implement the 7 validation rules in Go (`go-yaml` + `net` for CIDR, regex for
  JA4). ~200 lines. Independent of Python runtime. **Recommended.**
- B: Add `POST /api/v1/config/validate` to Phase 79 and have CLI call it. Requires
  API access for an offline operation. Breaks air-gapped use case.
- C: Shell out to Python. Requires Python runtime on the operator's machine. Not viable
  for a standalone Go binary.

---

## 11. Acceptance Criteria

- [ ] ADR-083a (release tooling) and ADR-083b (Go validator) written before coding starts
- [ ] `cmd/ja4proxy-cli/main.go` compiles with `go build ./cmd/ja4proxy-cli/`
- [ ] All commands in §2 implemented (simulation stubs excepted — see §2.1)
- [ ] Lookup-then-delete pattern works correctly for `allowlist remove`, `blocklist remove`, `ip watchlist remove`
- [ ] `--output json|table|csv` for all read commands
- [ ] Mutating commands require `--confirm` (or `--confirm` flag explicitly passed)
- [ ] `dial set` with mock returning 202 → CLI exits 2 with "PENDING APPROVAL: {decision_id}"
- [ ] Auth resolution order correct: flag > env > config file > keychain (unit test)
- [ ] Parity tests pass: all 8 policy test cases produce matching exit codes vs Python script
- [ ] Binary distributed as: standalone download + container image + in proxy container at `/usr/local/bin/ja4proxy-cli`
- [ ] `.github/workflows/release-cli.yml` produces GPG-signed release with SLSA attestation and `checksums.txt`
- [ ] `docs/developer/RELEASE_PROCESS.md` documents signing setup and verification steps
- [ ] `make test-phase-83` passes
- [ ] `scripts/ja4proxy-policy.py` marked deprecated (header comment) once Go CLI parity confirmed

---

## 12. Known Gaps / Deferred

| Item | Deferred to | Notes |
|------|-------------|-------|
| `simulation run/status/report` | Phase 100-M | Simulation API endpoints not yet defined; stubs with clear error message |
| Windows installer / MSI packaging | Business track | Binary zip is sufficient for enterprise; MSI is a distribution preference |
| Shell completions (`bash`/`zsh`/`fish`) | Follow-on PR | cobra generates these; low effort; can ship as a separate PR after main AC |
