---
phase: 823
title: "Test failures print no traceback inside Docker — conftest os._exit() preempts pytest's reporting"
status: COMPLETE
size: SMALL
created: 2026-08-05
renumbered: 2026-08-15
audience: [developer]
---

# Test failures print no traceback inside Docker

> **STATUS: PROPOSED — plan for review. No code until approved.**

## Goal (plain language)

When a test fails inside the container — which is how **every** Python test in
this project runs — pytest prints `F` and then nothing. No traceback, no
assertion message, no short test summary. The developer is told *that*
something failed and never *why*.

Found while writing tests during Phase 814a, where it cost a debugging cycle:
the failing test's assertion message was invisible, so the first hypothesis
(wrong monkeypatch) had to be tested by running the same logic outside pytest.

## The cause

`tests/conftest.py`'s `pytest_sessionfinish` hook:

```python
if os.path.exists("/.dockerenv") and not os.environ.get("PYTEST_XDIST_WORKER"):
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(int(exitstatus))
```

`os._exit()` terminates the process immediately. It runs before pytest's
terminal reporter has written the `FAILURES` section and the short test
summary, so that output is never produced.

The hook is not gratuitous — its docstring explains it exists to stop
containers hanging, and it deliberately exempts xdist *workers* so the
controller can still collect their results. The intent is sound; the
side-effect was not noticed because it only shows up when a test **fails**,
and it does not affect the exit code, so CI still goes correctly red — just
uninformatively.

## Measurement

A deliberately failing test (`assert False, "PROBE-MARKER-12345"`) placed in
`tests/unit/`, counting occurrences of the marker in the output:

| Run mode | Used by | Marker occurrences |
|---|---|---|
| `pytest … -n auto --dist=loadfile` | `make test` for `tests/unit/` and `management/tests/` | **0** |
| `pytest …` (no xdist) | `make test` for `tests/integration/` | **0** |
| Same, with `PYTEST_XDIST_WORKER` set (guard bypassed) | — control — | **2** |

So it affects **every** path in `make test`, not just the non-parallel one.
The control confirms the guard is the cause rather than something in pytest's
own configuration.

## Scope

In scope: make failure output survive, without reintroducing whatever hang the
hook was added to prevent.

Out of scope: changing the test suite, the container image, or how `make test`
invokes pytest.

## Implementation options

Ordered by preference. The choice needs a decision at review, because option A
depends on a fact worth confirming first.

### Option A — move the exit later, or drop it (recommended, if it still holds)

The hook dates from an older container/pytest combination. **First step is to
establish whether the hang it guards against still reproduces at all** —
`pytest-asyncio`, pytest and the base image have all moved since. If it does
not, delete the hook: the simplest fix is no code.

If it does still hang, keep `os._exit()` but move it strictly after the
terminal summary — `pytest_unconfigure` runs after all reporting, or a
`trylast`-ordered `pytest_sessionfinish`:

```python
@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus): ...
```

`trylast` alone may be enough: the terminal reporter's own `sessionfinish` runs
in the same phase, and hook ordering is what decides who wins. That needs
verifying empirically rather than assuming — the same discipline the rest of
this work has used.

### Option B — flush the report before exiting

Force the terminal reporter to emit its summary, then `os._exit()`:

```python
tr = session.config.pluginmanager.get_plugin("terminalreporter")
tr.summary_failures()
tr.short_test_summary()
```

Works, but reaches into pytest internals that are not a stable API — a
maintenance liability for a cosmetic-looking fix.

### Option C — narrow the condition

Only `os._exit()` when the run **passed** (`exitstatus == 0`). Failures then
exit normally and report fully; the hang guard still covers the common case.

Least invasive and lowest risk. It leaves the theoretical hang possible on a
failing run — but a hung *failing* run is far less costly than a silent one,
and the developer is present and watching in exactly that case.

## Test strategy

The bug is about output, so the test asserts on output:

- `tests/unit/test_conftest_reporting.py` — run pytest as a subprocess against
  a temporary failing test inside the container, assert the assertion message
  appears in the captured output. **Verified to fail on revert**, per this
  project's standing rule, using the marker method above.
- Cover both `-n auto` and non-xdist modes, since both are affected and they
  take different code paths through the hook.
- Confirm the exit code is still correct (non-zero on failure) — the fix must
  not trade an output bug for a much worse "CI goes green on failure" bug.
- Confirm the container still exits rather than hanging: run the full
  `make test` at least once and check it terminates.

## Acceptance criteria

- [ ] A deliberately failing test under `tests/` prints its assertion message
      and traceback, in both `-n auto` and non-xdist runs, inside the container.
- [ ] Exit codes unchanged: non-zero on failure, zero on success.
- [ ] `make test` completes and the container exits (no hang) — the property
      the hook was protecting.
- [ ] The regression test is verified to fail against the current `conftest.py`.
- [ ] Whichever option is taken, the reasoning is recorded in `conftest.py`
      next to the code, so the next person does not re-litigate it.

## Why this is worth a phase

It is small, but it taxes every future debugging session — including every
sub-phase of the 814 pentest programme, which will be writing a lot of tests
that are *supposed* to fail before they pass (the two-state proof in
`PROGRAMME.md` §10). A test framework that hides *why* a test failed is
directly in the way of that work.

It is also the same class of problem as Phases 810, 812 and 815: a mechanism
that quietly stopped doing its job, where nothing was watching. Here the
missing signal is the one a developer needs most, at the exact moment they need
it.

---

## Outcome (2026-08-15) — rescued, renumbered, implemented

This plan was written 2026-08-05 as **Phase 816** and preserved only on the
`handoff-to-deepseek` branch; it was never in `manifest.yaml`. In the meantime a
different, unrelated phase took the number 816 ("Demo environment — end-to-end
management console showcase", merged in #424), so this one was renumbered to
**823**. The analysis below is unchanged from the original.

### The measurement was re-run before choosing an option

The plan required establishing *empirically* whether the hang the hook guarded
against still reproduces, rather than assuming. Results on the current
`ja4proxy-tools` image:

| Configuration | Assertion message visible? | Hang? |
|---|---|---|
| Current conftest, `-n auto --dist=loadfile` | **no** (0 occurrences) | — |
| Current conftest, serial | **no** (0 occurrences) | — |
| `@pytest.hookimpl(trylast=True)` | **no** (0 occurrences) | — |
| Hook removed entirely | **yes** | **no** |

Two findings drove the decision:

1. **`trylast=True` does not work.** The plan floated it as the likely minimal
   fix "if the hang still reproduces". It doesn't fix the truncation — the
   terminal reporter's own `pytest_sessionfinish` runs in the same phase, and
   ordering alone does not decide which wins. This is recorded in the conftest
   comment so nobody "restores" the hook believing `trylast` makes it safe.
2. **The hang no longer reproduces.** With the hook removed: `tests/unit/`
   1864 passed in 16s under xdist and 34s serial; `management/tests/` 751
   passed in 43s. All exited 0, none hung (600s timeout).

So **Option A in its simplest form applies: the hook is deleted, not
reordered.** The simplest fix was no code.

### Delivered

- `tests/conftest.py` — `pytest_sessionfinish` hook removed, with the reasoning
  and the `trylast` dead-end recorded inline.
- `tests/unit/test_pytest_reporting.py` — four tests: assertion message visible
  in serial **and** xdist (run as real pytest subprocesses, asserting on actual
  reporter output), the `FAILURES`/summary section is emitted, and an AST-based
  guard that fails if any `os._exit()` call returns to the conftest. The guard
  was verified to fail when a call is reintroduced.

### Why it mattered

While landing Phases 820 and 822 this bug cost two debugging cycles directly:
`make test` failed in CI with `sss................F` and no traceback, and the
failing test had to be identified by re-running with `-v` and grepping. It was
initially misattributed to CI log buffering.
