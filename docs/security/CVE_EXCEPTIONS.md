# CVE Exceptions

CVEs that fail CI can be temporarily accepted by adding an entry below. Each
entry MUST have an expiry date no more than 90 days in the future. Expired
entries are removed by whoever notices them first, and the CVE re-blocks CI
until the dependency is upgraded or the exception is renewed with a fresh
rationale.

## CVE triage SLA

- **HIGH / CRITICAL**: addressed (upgrade or accepted exception) within 7 days
- **MEDIUM**: addressed within 30 days
- **LOW**: tracked but no SLA — addressed during routine dependency rolls

## How an exception gets recorded

1. CI fails on a HIGH or CRITICAL CVE in `dependency-audit-python`,
   `dependency-audit-go`, or `dependency-review`.
2. The on-call engineer evaluates: is there an upstream fix? if so, upgrade.
3. If no fix exists yet, copy the template below into a new section, fill in
   every field, and open a PR. The PR description must link to the upstream
   issue or advisory.
4. The on-call CC's the security alias for visibility.
5. CI is configured to skip the listed CVE for the duration of the exception
   via the audit tool's ignore-vuln flag (added in the same PR).

## Template

```markdown
## CVE-YYYY-NNNNN
- **Severity**: HIGH | CRITICAL
- **Component**: <package name and exact pinned version>
- **Accepted by**: <name>
- **Date accepted**: YYYY-MM-DD
- **Expiry**: YYYY-MM-DD  (max 90 days from acceptance)
- **Upstream tracker**: <URL to GitHub issue / GHSA / vendor advisory>
- **Rationale**: <why this is acceptable in JA4proxy specifically — what
  mitigates the risk in our deployment, e.g. "code path not reachable from
  the proxy hot path; only invoked by the offline analytics processor which
  runs in a sandboxed namespace">
- **Re-evaluation trigger**: <event that causes re-evaluation before expiry,
  e.g. "upstream releases v1.2.4">
```

## Active exceptions

## CVE-2026-59951
- **Severity**: HIGH (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Component**: `mcp` 1.29.0 (transitive dependency of `semgrep`, not imported by any JA4proxy code)
- **Accepted by**: phase-824c
- **Date accepted**: 2026-10-16
- **Expiry**: 2027-01-14  (90 days)
- **Upstream tracker**: https://github.com/advisories/GHSA-84m7-p3x7-pcfv
- **Reason no upgrade fix is possible**: `semgrep` hard-pins `mcp==1.29.0`, and the
  latest semgrep release (1.181.0) still does; `mcp` 1.30.0 is the fix. Bumping
  `mcp` independently would break semgrep's resolution, so there is no safe
  resolution today. This mirrors the existing `click`/PYSEC-2026-2132 exception.
- **Rationale**: The vulnerability is unbounded session accumulation in MCP's
  **StreamableHTTP server transport** — it requires running an MCP *server* over
  streamable HTTP. JA4proxy never does: `mcp` is pulled in only by `semgrep` (a
  CLI scanner), no first-party module imports it, and no MCP server is exposed.
  The vulnerable code path is therefore unreachable in this deployment.
- **Re-evaluation trigger**: a semgrep release that pins `mcp>=1.30.0` (then
  upgrade semgrep and drop this exception), or any first-party use of `mcp`.

## CVE-2026-114603
- **Severity**: MEDIUM (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L; upstream advisory rates it Medium — availability only, no data exposure or code execution)
- **Component**: `opentelemetry-api` 1.37.0 (transitive dependency of `semgrep`, not imported by any JA4proxy code)
- **Accepted by**: phase-847f
- **Date accepted**: 2026-10-23
- **Expiry**: 2027-01-21  (90 days)
- **Upstream tracker**: https://github.com/advisories/GHSA-xcq7-p3pf-p88h
- **Reason no upgrade fix is possible**: `semgrep` 1.181.0 hard-pins
  `opentelemetry-api~=1.37.0` (with the matching SDK/exporter/instrumentation
  pins); the fix is 1.45.1. No semgrep release relaxes the pin, and a
  `pip install "opentelemetry-api>=1.45.1" "semgrep>=1.176.0"` resolves as
  `ResolutionImpossible`. Same shape as the `mcp` exception above.
- **Rationale**: Quadratic backtracking in `TraceState.from_header` when the
  default W3C Trace Context propagator parses an oversized `tracestate` header
  — a CPU/availability DoS on a service that extracts propagation headers from
  untrusted HTTP requests. JA4proxy does not: `opentelemetry-api` is installed
  only into the `ja4proxy-tools` CI image (via `requirements.txt`) because
  `semgrep` depends on it, no first-party module imports it, no OTEL propagator
  is wired into any request path, and no deployed image declares it
  (`requirements-analytics.txt` / `management/requirements.txt` do not).
  The `make lint-static` pip-audit gate and `make scan-regression` bind this
  claim to a machine check (`reachability: not-imported`): if first-party code
  ever imports `opentelemetry`, or a deployed image starts declaring it, the
  gate fails and demands re-justification.
- **Re-evaluation trigger**: a semgrep release that allows
  `opentelemetry-api>=1.45.1` (then upgrade semgrep and drop this exception),
  or any first-party import of `opentelemetry`.

