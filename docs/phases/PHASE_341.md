# Close Remaining OPEN Findings

## Goal
Close the 4 remaining OPEN findings (JA4PROXY-2026-0060, 0062, 0066, 0079) from the security findings register.

---

## F-0060: Reassembly Buffer Purging Logged Inconsistently (LOW)

### What's wrong
`internal/tap/reassembler.go` silently purges buffers via 3 code paths — only incrementing Prometheus counters, producing zero log output. The proxy side (`cmd/ja4pd/main.go:809`) logs `"reassembly: ..."` at Debug level. Operators debugging TAP-mode connection failures have no log trail.

### Files to change

**`internal/tap/reassembler.go`** — add 3 `Debug()` log lines. The file uses logrus via a package-level `log` import. Check the existing import block; if `"github.com/sirupsen/logrus"` is not imported, add it. The logger variable name is `log` (package-level).

Exact changes:

1. **`markGap()` function (~line 142–149):** After `*done = true` (line ~148), add:
   ```go
   log.Debugf("reassembly: gap detected, abandoning stream (skipped %d bytes)", skip)
   ```
   (The `skip` variable is in scope — it's the function parameter.)

2. **`appendDir()` — room <= 0 branch (~line 165–169):** After `*done = true` (line ~167), add:
   ```go
   log.Debugf("reassembly: buffer full, purging direction (cap=%d)", cap(*buf))
   ```

3. **`appendDir()` — buffer cap hit after append (~line 194–197):** After `*done = true` (line ~196), add:
   ```go
   log.Debugf("reassembly: buffer exceeded max handshake bytes, purging direction")
   ```

**`cmd/ja4pd/pentest_f003_f005_test.go`** — extend `TestReassemblyLogLevel` to also scan `internal/tap/reassembler.go`. Currently the test only scans `cmd/ja4pd/main.go`. Add a second scan loop for the reassembler file, asserting the same invariant: any line containing `"reassembly:"` must not use `.Info(` or `.Warn(`.

### Notes for implementer
- The finding notes reference `main.go:741` but the actual log line is at line 809 and already uses `.Debug()` — that part is fine.
- The `"per-connection cap exceeded"` exemption in the test (line 61) is dead code (no such line exists in main.go). Leave it — don't remove test exemptions unless explicitly asked.

---

## F-0062: Config MaxConnectionLimit Not Implemented (LOW)

### What's wrong
**Nothing — this is stale.** The field was originally named `MaxConnectionLimit` but was renamed to `MaxConnections` during Phase 216 remediation. It IS wired into the Go proxy:
- `internal/config/loader.go:439`: `MaxConnections int \`yaml:"max_connections"\``
- `cmd/ja4pd/main.go:327`: `maxConns := cfg.Proxy.MaxConnections`
- `cmd/ja4pd/main.go:476–487`: `admitConn()` enforces via semaphore
- Regression test: `cmd/ja4pd/pentest_accept_loop_semaphore_regression_test.go`

### Files to change
**`docs/security/findings.yaml`** — find the entry for `JA4PROXY-2026-0062` (lines ~1959–1978). Change:
```yaml
status: OPEN
```
to:
```yaml
status: FIXED
closed_commit: <merge commit SHA of this PR>
notes: "Stale — field renamed from MaxConnectionLimit to MaxConnections during Phase 216.
  Wired into Go proxy at cmd/ja4pd/main.go:327, enforced via acceptSem semaphore.
  Regression test: pentest_accept_loop_semaphore_regression_test.go."
```

### Notes for implementer
- No code changes. Only findings.yaml status update.
- The `closed_commit` should be filled in after the PR merges.

---

## F-0066: Webhook URL Validation TOCTOU (LOW)

### What's wrong
`internal/webhook/delivery.go:doHTTPPost` calls `isPrivateTarget()` at line 361 (DNS resolution #1), then `client.Do()` triggers `newSafeTransport.DialContext` (DNS resolution #2 at line 332). The redundant first check creates a TOCTOU window: DNS could rebind to a private IP between the two resolutions.

The `newSafeTransport.DialContext` is the real security boundary — it resolves DNS at TCP connect time and rejects private IPs atomically. The `isPrivateTarget` pre-check is redundant and its only caller is `doHTTPPost`.

### Files to change

**`internal/webhook/delivery.go`** — remove the `isPrivateTarget` call from `doHTTPPost` (lines 361–363):

Delete these 3 lines:
```go
    if isPrivateTarget(ep.URL) {
        return fmt.Errorf("webhook: blocked private/loopback target (SSRF prevention): %s", ep.URL)
    }
```

Keep the `isPrivateTarget` function definition (lines 296–318) — don't delete it. It's a useful utility and removing dead code is out of scope.

### Why this is safe
- `isPrivateTarget` is called from exactly 1 place: `doHTTPPost` line 361. No other callers in the codebase (including tests).
- `newSafeTransport.DialContext` resolves DNS at connection time (line 332) and rejects private IPs (line 340–341). This cannot be bypassed.
- The `http.Client` is created per-call with `Transport: newSafeTransport(...)` at `deliverToEndpoint` line 231. No code path creates a client without this transport.
- DNS lookup failure is fail-closed in both paths (isPrivateTarget returns true, DialContext returns error).
- Tests use `JA4PROXY_TEST_ALLOW_LOOPBACK=true` which bypasses both checks — no test breakage.

### Notes for implementer
- Run `go build ./...` after the edit to confirm no compilation errors.
- Run `go test ./internal/webhook/...` to verify existing tests pass.

---

## F-0079: Redis Password Exposed on CLI in PoC Compose (LOW)

### What's wrong
`deploy/docker/docker-compose.poc.yml` lines 119–120 pass `--requirepass ${REDIS_PASSWORD}` as a CLI argument to `redis-server`, making it visible in `ps aux`, `/proc/PID/cmdline`, and `docker inspect`.

The production compose (`docker-compose.prod.yml`) already uses the correct pattern: `--requirepass-file /run/secrets/redis_password` with Docker secrets.

### Files to change

**`deploy/docker/docker-compose.poc.yml`** — 3 changes:

**Change 1: Redis service command** (lines 115–120). Replace:
```yaml
  command:
    - redis-server
    # JA4PROXY-2026-0079: Password visible in process list for PoC only.
    # Production compose uses Docker secrets + --requirepass-file.
    - --requirepass
    - ${REDIS_PASSWORD:?REDIS_PASSWORD is required}
```
With:
```yaml
  command:
    - redis-server
    - --requirepass-file
    - /run/secrets/redis_password
```

**Change 2: Redis service — add secrets mount.** In the redis service definition, add:
```yaml
  secrets:
    - redis_password
```

**Change 3: Top-level secrets section.** Add after the `networks:` block (before EOF):
```yaml
secrets:
  redis_password:
    file: ../secrets/redis_password.txt
```

**Change 4: Add prerequisites comment** at the top of the file (after the existing header), matching prod:
```yaml
# Prerequisites (must be created before first deploy):
#   deploy/secrets/redis_password.txt — strong random password (min 32 chars)
#
# Quick start:
#   mkdir -p deploy/secrets
#   openssl rand -base64 48 > deploy/secrets/redis_password.txt
#   chmod 600 deploy/secrets/*.txt
```

### Why this is safe
- The `deploy/secrets/` directory is gitignored at 3 levels (path, wildcard, filename pattern). The secrets file will never be committed.
- The prod compose already uses this exact pattern. We're making PoC consistent with prod.
- The `management` service `REDIS_URL` at line 384 uses an env var (not CLI arg) — it's visible in `docker inspect` but NOT in `ps`. This is a separate concern and out of scope.

### Notes for implementer
- The secrets file (`deploy/secrets/redis_password.txt`) must exist before `docker compose up`. The prerequisites comment documents this.
- If the secrets file doesn't exist, `docker compose up` will fail with a clear error message about the missing secrets file.
- Run `docker compose -f deploy/docker/docker-compose.poc.yml config` to validate the compose file after changes.

---

## Test strategy
- **F-0060:** Extend `TestReassemblyLogLevel` in `cmd/ja4pd/pentest_f003_f005_test.go`
- **F-0062:** No new tests (stale finding, already tested)
- **F-0066:** Existing webhook tests pass; no new test needed (the fix removes code, not adds behavior)
- **F-0079:** `docker compose config` validates the compose file

## Acceptance criteria
- All 4 findings marked FIXED in `docs/security/findings.yaml`
- `findings_register.py validate` exits 0
- `go build ./...` passes
- `go test ./...` passes
- `docker compose -f deploy/docker/docker-compose.poc.yml config` exits 0

## Out of scope
- Production compose changes (already correct)
- Management service `REDIS_URL` env var exposure (env var, not CLI arg)
- Removing `isPrivateTarget` function definition (keep as utility)
- Removing dead test exemption for "per-connection cap exceeded"
