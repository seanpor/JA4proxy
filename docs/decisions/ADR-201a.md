# ADR-201a: Go Redis Client TLS — `MinVersion = TLS 1.2`, System CA Pool Only

**Status:** Accepted
**Date:** 2026-04-15
**Phase:** 201 (Go Redis TLS + Silent-Failure Hardening)

---

## Context

Before Phase 201 the Go Redis client (`internal/redis/client.go`) ignored the
`redis.ssl` flag from `config/proxy.yml`. Operators enabling `ssl: true`
received cleartext connections with no warning — a silent-failure class of bug
(see `docs/phases/PHASE_201_review.md` blocker #3). The Python proxy already
honours the flag (`proxy.py:1635-1678`) and has done since Phase 0.

Phase 201 adds TLS support to the Go client. Two sub-decisions were required
before wiring anything:

1. **What TLS minimum version to enforce?**
2. **How should the client trust the Redis server certificate — system CA pool,
   a bundled CA, or configurable via `ssl_ca_certs` (as Python supports)?**

Those choices are load-bearing: they determine which production Redis
deployments the proxy can talk to without custom configuration, and they set
the default security posture for operators who flip `ssl: true` without
reading the runbook.

---

## Options Considered

### 1. TLS minimum version

- **Option A — `MinVersion = TLS 1.0`.** Matches the broadest possible server
  population. Rejected: TLS 1.0 and 1.1 are formally deprecated (RFC 8996,
  2021); most cloud Redis offerings have removed them; shipping 1.0 by default
  would contradict the project's own TLS-version signal (see
  `internal/security/tls_enforcer.go:68` which scores deprecated TLS on the
  client-hello side).
- **Option B — `MinVersion = TLS 1.2`.** The floor currently accepted by every
  target environment (Redis Enterprise, AWS ElastiCache for Redis, Azure Cache
  for Redis, stunnel-terminated self-hosted Redis). Wide compatibility, no
  known-weak cipher suites.
- **Option C — `MinVersion = TLS 1.3`.** Best cryptographic posture. Rejected
  for Phase 201: some production-in-use stunnel versions and legacy Redis
  Enterprise builds still negotiate 1.2 only. Forcing 1.3 would break valid
  deployments for a marginal security gain, and can be revisited when those
  platforms catch up.

### 2. Server certificate verification

- **Option D — system CA pool (Go's default `crypto/tls` behaviour; leave
  `TLSConfig.RootCAs == nil`).** Works for any Redis server whose cert chains
  to a CA the OS already trusts (all major cloud providers, Let's Encrypt,
  corporate CAs installed via `update-ca-certificates`).
- **Option E — bundle a specific CA.** Rejected: fragile, and we do not ship
  Go binaries with a known target Redis deployment baked in.
- **Option F — configurable `ssl_ca_certs` (as Python has).** Desirable but
  out of scope for Phase 201. Adding it requires a file-reading helper with
  matching error handling and tests. Deferred.
- **Option G — client-certificate mTLS to Redis (`ssl_certfile`,
  `ssl_keyfile`).** Out of scope for Phase 201 for the same reason plus the
  larger surface (key rotation runbook, permissions, systemd `LoadCredential`
  story). Deferred.

---

## Decision

- **TLS:** When `redis.ssl: true`, the Go client dials with
  `TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}` and **no custom
  `RootCAs`** — Go falls back to the OS system trust store.
- **Username:** The `redis.username` YAML field is plumbed through to both
  `goredis.Options.Username` and `goredis.FailoverOptions.Username`. Empty
  string means the Redis 6+ default user. (Username itself is not sensitive
  enough to mandate a Vault lookup, but it is never logged as a value — only
  as a boolean `username_set`. See PHASE_201.md sub-phase 201a step 3.)
- **Custom CA bundles (`ssl_ca_certs`) and client-cert mTLS are explicitly
  deferred.** Operators needing a private CA must add it to the container's
  OS trust store (e.g. via `update-ca-certificates` in the Dockerfile or a
  mounted `/usr/local/share/ca-certificates/extra` directory). A follow-up
  phase will add first-class `ssl_ca_certs` / `ssl_certfile` support once
  rotation and reload semantics are specified.

## Compatibility

Validated-as-compatible targets under this decision (all negotiate TLS 1.2+
and chain to public CAs):

| Target | Notes |
|---|---|
| **Redis Enterprise Cloud** | TLS 1.2 minimum; public CA-signed endpoints. |
| **AWS ElastiCache for Redis** (with encryption in transit) | TLS 1.2 minimum; Amazon Trust Services CA in default OS stores. |
| **Azure Cache for Redis** | TLS 1.2 minimum; Microsoft CA in default OS stores. |
| **stunnel 5.56+** in front of self-hosted Redis | TLS 1.2 default; operator chooses cert. Use public CA or install custom CA into container trust store. |
| **GCP Memorystore for Redis** | TLS 1.2 minimum; Google Trust Services CA. |

Known *not* compatible without operator action:
- Self-hosted Redis with a private-CA-issued certificate and no OS trust-store
  update. Workaround documented in the runbook until `ssl_ca_certs` lands.

## Consequences

**Positive**
- Operators flipping `ssl: true` get a real TLS 1.2+ handshake or a loud
  ERROR log (fail-open to local cache is preserved — see PHASE_201.md 201a
  step 4).
- Matches Python's default behaviour for the common case (public-CA Redis).
- No new configuration surface to test or document beyond the existing
  `ssl`/`username` fields.

**Negative**
- Private-CA Redis deployments require an OS-level trust-store change until
  `ssl_ca_certs` is implemented. Documented in
  `docs/runbooks/go_proxy_operations.md` under the Phase-201 section.
- TLS 1.3-only Redis deployments will work (since 1.2 is a minimum, not a
  maximum), but any server that rejects 1.2 ClientHellos will be unreachable.
  No known production deployments do this.

**Withdrawn / not done in this ADR**
- Custom CA bundle support (Python's `ssl_ca_certs`).
- Client-certificate mTLS to Redis (Python's `ssl_certfile`/`ssl_keyfile`).
- TLS for the Management API / analytics node's Redis clients (separate
  phases — this ADR covers the Go proxy and sync-agent only).

## Revisit if...

- A production Redis target is found that rejects TLS 1.2 and only accepts 1.3
  (consider raising `MinVersion`).
- An operator ticket requests `ssl_ca_certs` — at which point, write the
  follow-up phase and a new ADR superseding this one's CA-pool decision.
- CVE activity against TLS 1.2 cipher suites warrants a cipher-suite
  allowlist (currently we rely on Go's defaults, which already exclude
  known-weak suites for `MinVersion >= 1.2`).

## Implementation notes

Verified against the Phase 201 merge on branch
`claude/phase-201-redis-tls-hardening`:

- Startup log line emitted from `internal/redis/client.go` `New()` is
  `"redis: dial options configured"` (Info) with fields `ssl` and `username`
  as Booleans — password is never logged.
- TLS sanity-ping failure surfaces as
  `"redis: TLS ping failed; continuing fail-open"` (Error) and `New()` still
  returns a non-nil `*Client`, preserving fail-open.
- Dial-option construction is factored into `buildStandaloneOptions` /
  `buildFailoverOptions`, both of which set
  `TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}` when `cfg.SSL`.
- Concurrency model: `Client.scriptMu` is a `sync.RWMutex` protecting
  `slidingWinSHA`. `loadScripts()` takes the write lock and delegates to
  `loadScriptsLocked()` which assumes the lock is already held; this
  split lets `HealthCheck` use a double-checked `RLock → Lock` pattern
  without re-entering the mutex. This keeps read-heavy hot-path calls
  (`SlidingWindowCount`, `SlidingWindowSHA`) on `RLock` while allowing
  safe reload under `Lock`.
- `ssl_ca_certs` / `ssl_certfile` workaround for private CAs is covered in
  `docs/runbooks/go_proxy_operations.md` under the Phase-201 alert section
  (point to OS-level trust-store update until a follow-up phase lands
  first-class CA bundle support).
