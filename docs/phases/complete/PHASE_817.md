---
phase: 817
title: "Analytics node crash-loop fix — src/utils missing from image (JA4PROXY-2026-0097)"
status: COMPLETE
created: 2026-08-05
completed: 2026-08-06
audience: [developer, security]
---

# Analytics node crash-loop fix

Remediation of **JA4PROXY-2026-0097**, found during the Phase 814 pentest cycle
while bringing up the isolated range. A trivial-fix-found-in-flight, taken
inline with a regression test and a register entry, exactly as
`docs/security/pentest/PROGRAMME.md` §5.5 allows.

## The finding

The analytics container crash-looped on **every** startup
(`RestartCount=152`, exit 1) with:

```
ModuleNotFoundError: No module named 'src.utils'
```

Root cause:

- `src/analytics/main.py:17` imports `from src.utils.logging_config import setup_logging`
- `src/analytics/Dockerfile` COPYs only `src/analytics` into the image
- `src/utils/` exists in the repo but never reaches the container

Nothing caught it because no test exercised the analytics image's import
closure. In a real deployment (`restart: unless-stopped`) it crash-loops
forever; the analytics node — which consumes the proxy's Redis event stream and
exports Prometheus metrics + writes detections back — is silently dead.

Severity **MEDIUM** (rubric **M-4**: affects the analytics node only, not the
proxy path). Not attacker-triggered; a build defect. Full entry:
`docs/security/findings.yaml` (0097), GitHub issue #398.

## The fix

One line in `src/analytics/Dockerfile`:

```dockerfile
COPY src/utils /app/src/utils
```

`src/utils` is self-contained (no further `src.*` imports), so copying just
this subtree is sufficient — verified by grepping its import closure.

## The regression test

`tests/unit/test_analytics_image_imports.py` — **static**, not a container
build. It parses every `src.*` import in the analytics package and every
`COPY src/<sub>` in the Dockerfile, and asserts the former is a subset of the
latter. This catches the whole *class* (any `src.*` import shipping without its
subtree), runs in milliseconds with no Docker, and directly guards the
invariant whose violation caused the crash.

The end-to-end "does the container start" check is the range bring-up itself.

## Verification

Two-state proof (PROGRAMME.md §10.3), both recorded:

| State | Result |
|---|---|
| Regression test vs **pre-fix** Dockerfile | **FAIL** — `missing src subtree(s): ['utils']` |
| Regression test vs **fix** | **PASS** (2 tests) |
| Analytics container rebuilt + started on the range | Gets **past import** — logs `Logging initialized` and `Starting JA4Proxy Analytics Node`; no `ModuleNotFoundError` |

## What fixing it revealed (recorded honestly)

Getting past the import surfaced a **separate, previously-masked** error:
`redis.exceptions.NoPermissionError` for the analytics Redis user. This is
**not introduced by this fix** — the container simply never reached Redis
before, dying at import.

Investigation traced it to the **range's** Redis rejecting auth for everyone
(`AUTH ... called without any password configured for the default user`) — the
range's ACL provisioning is incomplete, which also explains a management→Redis
`AuthenticationError` seen earlier the same session. That is a **range-quality
issue**, tracked separately (it blocks clean data-layer testing), not a product
vulnerability and out of scope here.

A genuine downstream question does remain for workstream **814k**: the analytics
ACL user is scoped to `~analytics:*` keys — can it actually read the proxy's
event stream it is meant to consume? That needs a working range Redis to answer
and is explicitly deferred, not silently dropped.

## Out of scope

- The range's Redis ACL provisioning gap (separate range-quality fix).
- Whether the analytics ACL keyspace grant is correct (814k, needs working Redis).
- A full container-startup smoke test in CI (the static import-closure test is
  the proportionate guard; a build-and-run smoke test is a candidate follow-up).

## Acceptance criteria

- [x] `src/utils` reaches the analytics image; `ModuleNotFoundError` gone.
- [x] Regression test fails pre-fix, passes post-fix (two-state proof recorded).
- [x] Analytics container starts past import on the range.
- [x] Finding 0097 registered (FIXED, regression_test, found_against, issue #398).
- [x] `make lint` / `make test` green; PR merged.
