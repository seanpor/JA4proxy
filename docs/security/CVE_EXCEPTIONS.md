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

_None as of phase 61._
