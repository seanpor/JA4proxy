# Runbook: Security Scan Exceptions (`.trivyignore.*`)

> **Phase 822 — there are now TWO exception files, with different rules.**
>
> | File | Consumed by | Rule |
> |---|---|---|
> | `.trivyignore.first-party` | `make scan-first-party` | **A fix reachable by ANY rebuild we can perform is not a waiver candidate.** We control these images — do the fix. |
> | `.trivyignore.third-party` | `make scan-images` | **No fix reachable without replacing the image.** These are pinned upstream tags we cannot rebuild. |
>
> They were one file until Phase 822, and the Makefile passed it to both scans.
> Trivy's ignorefile has no per-image scoping, so a waiver written for an
> abandoned monitoring sidecar also suppressed the same finding in the proxy we
> ship — observed with `CVE-2026-39821`/`CVE-2026-46600`, both of which were
> fixed outright by a Go builder bump once the scopes were separated.
>
> `make scan-exceptions` reports both, tagged by scope.

`make scan` fails the build on any CRITICAL CVE in our images. When a CVE has
**no fix available** and is **not exploitable in our context**, it can be granted
a *justified, time-windowed* exception in the ignorefile for that image's
scope (see the table above). This is the **only**
sanctioned way to suppress a scan finding — and it always expires.

> Policy (Phase 226): no blanket ignores. Anything with an available fix is
> patched via `apt-get/apk upgrade` in the Dockerfile, **never** ignored here.

## View current exceptions

```bash
make scan-exceptions
```

Lists every entry with its expiry, **days remaining**, status (`ok` / `SOON` ≤3d
/ `EXPIRED` / `NO-EXP`) and justification. Exits non-zero if any entry is expired
or has no `exp:` date, so stale exceptions can't be forgotten.

## File format (both files)

Each exception, in either file, is a `#` comment block (the justification) immediately above a
`CVE-…  exp:YYYY-MM-DD` line:

```
# CVE-2026-8376 (CRITICAL) — Perl interpreter heap overflow, perl-base on
# python:3.14-slim. No fix (Debian marks it `affected`, no fixed version).
# Not exploitable: we never run the perl interpreter on untrusted input.
# Real fix: Phase 229 (perl-free base).
CVE-2026-8376 exp:2026-06-20
```

Trivy ignores the CVE **until** `exp:`, then it re-surfaces and the scan fails
again — forcing a re-review.

## Operator: add / edit / delete

| Action | How |
|--------|-----|
| **Add** | Confirm there is genuinely no fix (`make scan` shows `fix_deferred`/`affected`). Append a `#` block stating *why no fix* and *why not exploitable here*, then `CVE-XXXX-NNNNN exp:<today+7d>`. |
| **Edit / extend** | Change the `exp:` date and update the justification comment to say why it still applies. **Max window: 7 days** — keep exceptions short-lived. |
| **Delete** | When a fix lands, remove the comment block + CVE line and let `apt/apk upgrade` clear it; or remove once the risk is otherwise resolved. |

Always run `make scan-exceptions` after editing, and `make scan` to confirm the
gate is satisfied.

## Rules

1. **No blanket ignores** — one entry per CVE, each individually justified.
2. **Every entry needs an `exp:` date** (max +7 days) and a justification comment.
3. **Fixable ⇒ patch, don't ignore** — only no-fix CVEs belong here.
4. Prefer a **real fix** (base-image change, e.g. Phase 229) over repeatedly
   extending an exception.
