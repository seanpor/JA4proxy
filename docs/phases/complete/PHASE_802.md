---
phase: 802
title: "Root Clutter Follow-Up: Stray Phase Notes, Dead Files — and a Critical No on Dotfile Relocation"
status: PROPOSED
created: 2026-07-21
audience: [developer]
---

# Root Clutter Follow-Up

> **STATUS: PROPOSED — plan for review. No code until approved.**
> Direct follow-up to [[PHASE_205]] (Repository Root Cleanup), which did most
> of its directory-move work but left two things unresolved: six phase-notes
> files that were never swept into the `docs/phases/` convention it
> established, and an ambitious dotfile-consolidation idea that was drawn in
> its "Proposed Root" diagram but — tellingly — never got an actual
> sub-task (205a–205h have no dotfile-move step). This phase closes the
> first gap and explains, with evidence, why the second one should stay
> closed.

## Origin

Asked directly: "should `PHASE_*.md` files be in `docs/phases/`? Can we put
the dotfiles in a `Dots` folder? What else can move? Critically review that
line of thought." This doc is that critical review, not just a task list —
Section 2 argues against half of what was asked, with receipts.

## 1. Phase notes at root — move them (low risk, matches existing convention)

`docs/phases/complete/` already holds **14** `PHASE_*_notes.md` files. Six
more sit at repo root instead, purely because nobody swept them after
Phase 205 closed:

| File | Belongs at |
|---|---|
| `PHASE_316a_notes.md` … `PHASE_316e_notes.md` (5 files) | `docs/phases/complete/` (Phase 316 series is done) |
| `PHASE_800_notes.md` | `docs/phases/` (Phase 800 is `IN_PROGRESS`, not `complete/` yet) |

**Verified safe to move:** grepped every `.md`/`.yml`/`.py`/`Makefile` in the
repo for references to these six filenames. Two hits, both prose mentions
(one in `PHASE_800.md`'s own body text, one in the `notify-scheduled-failure`
CI job's issue-body string added in phase-800) — neither is a path the
filesystem or a tool resolves, both just need their text updated to the new
location alongside the `git mv`.

## 2. The "Dots folder" idea — critical review: don't do a blanket move

### 2a. The stated rationale doesn't apply to dotfiles at all

Phase 205's entire case for moving things was "GitHub users must scroll past
[root clutter] to reach the README" — and its own accounting explicitly
**excludes dotfiles from that count**: *"GitHub visible entries (dotfiles
hidden): 14."* GitHub's default repo view already hides everything starting
with `.`. There is no scrolling problem to solve by moving `.bandit` — nobody
sees it on GitHub today, dotfile-in-root or not. The only thing a `Dots/`
folder would improve is a local `ls -la` / IDE sidebar, which is a real but
much smaller annoyance than the README-visibility problem 205 was solving.

### 2b. Phase 205 already drew this exact idea and never executed it

`PHASE_205.md`'s "Proposed Root" diagram shows a `.config/` directory
absorbing 10 linter dotfiles, with the caveat *"tools support `--config`
path flags... If a tool cannot read from `.config/`, leave its dotfile at
root and document why."* Sub-phases 205a–205h cover every other proposed
move (directories, docs, scripts) — **none of them is the dotfile
consolidation.** It was drawn, then quietly dropped without a recorded
decision. Today's root (`.bandit`, `.golangci.yaml`, etc. all still present)
confirms it never happened. That's a pattern worth noticing before repeating
the exercise: the idea looked good on a diagram and stalled the moment
someone had to scope the actual tool-by-tool work.

### 2c. Checked every tool's actual invocation — the risk is real and uneven

Grepped `Makefile` for how each dotfile-consuming tool is actually called.
The results split cleanly into two groups:

**Already pass an explicit config path — safe to relocate, one Makefile flag each:**

| Dotfile | Invocation |
|---|---|
| `.golangci.yaml` | `golangci-lint run --config .golangci.yaml ./...` |
| `.yamllint.yaml` | `yamllint -c .yamllint.yaml $(YAML_DIRS)` |
| `.gitleaks.toml` | `gitleaks ... --config /repo/.gitleaks.toml` |
| `.trivyignore` | `--ignorefile /scan/.trivyignore` (×2 in Makefile) **+** `trivyignores: .trivyignore` in `go-proxy-image.yml` |
| `.luacheckrc` | `luacheck --config /repo/.luacheckrc ...` |
| `.pymarkdown` | `pymarkdown --config /src/.pymarkdown scan ...` |
| `.codespellignore` | `codespell --ignore-words=/src/.codespellignore` |
| `.semgrep-phase122.yml` | `semgrep --config .semgrep-phase122.yml .` |

**Rely on implicit cwd auto-discovery — no flag exists to update; moving silently changes behaviour:**

| Dotfile | Invocation | What breaks |
|---|---|---|
| ~~`.bandit`~~ | ~~`bandit -r src/analytics/ -ll --skip B104` (no `-c`)~~ | ~~Container's `-w /src` = repo root; bandit finds `.bandit` only because it's *there*. Move it and bandit silently stops applying whatever `.bandit` restricts — no error, just a quieter scan.~~ **Incorrect — see correction below.** |
| `.checkmake.ini` | `checkmake Makefile` (no `--config`) | Same failure mode — silent fallback to checkmake defaults. |
| `.semgrepignore` | Not passed anywhere; semgrep reads it from cwd by `.gitignore`-style convention | A semgrep run (CI's `lint-semgrep`, or any dev running `semgrep` locally) silently stops excluding whatever `.semgrepignore` excludes. |

> **Correction, 2026-08-10 (Phase 800): the `.bandit` row above was wrong, and
> the file has been deleted.**
>
> Bandit never read `.bandit`. It was a *Python script* (`def get_skips():
> return "B103,B404,..."`), not the INI format bandit's `--ini` expects, and
> nothing in the repo imported or passed it. Bandit auto-discovers no such file
> here: every run logged `profile include tests: None / profile exclude tests:
> None` with the file sitting in cwd.
>
> Verified directly — a probe file using `hashlib.md5` (B324) and `yaml.load`
> (B506), both listed in `.bandit`'s skip string, was scanned in a cwd
> containing `.bandit` and again without it. **Byte-identical output both
> times; both issues reported either way.** The file restricted nothing, so
> there was no "quieter scan" to protect against.
>
> It was also internally incoherent: of its 17 IDs, `B410`/`B417` no longer
> exist in bandit 1.8 and `B905`/`B906` are ruff / flake8-bugbear codes, not
> bandit ones. The real risk was latent — had anyone ever "fixed" it into a
> working config, it would have silently disabled `hardcoded_password_string`
> (B105), `hardcoded_sql_expressions` (B608), `yaml_load` (B506),
> `hashlib_insecure_functions` (B324), `tarfile_unsafe_members` (B202) and
> `set_bad_file_permissions` (B103).
>
> **The other two rows were subsequently tested the same way. They do not both
> hold:**
>
> - **`.semgrepignore` — claim CONFIRMED.** Semgrep does auto-read it from cwd.
>   A probe tree with `ignored/**` in `.semgrepignore` reported only
>   `kept/bad.py` with the file present, and both `kept/bad.py` and
>   `ignored/bad.py` without it. This row stands as written: moving
>   `.semgrepignore` would silently widen the scan.
>
> - **`.checkmake.ini` — claim FALSE, but for the opposite reason to `.bandit`.**
>   checkmake does *not* auto-discover it from cwd. Proven three ways on a probe
>   Makefile with a 7-line recipe body: file in cwd, no flag → `maxbodylength`
>   still reported; file absent → identical output; `--config=.checkmake.ini`
>   passed explicitly → suppressed. So the file is **valid and load-bearing —
>   it is simply never passed**. On this repo's real Makefile, `checkmake
>   Makefile` yields **13** `maxbodylength` violations, and
>   `checkmake --config=.checkmake.ini Makefile` yields **0**.
>
>   Unlike `.bandit`, the fix here is to *pass* the file, not delete it:
>   `lint-makefiles` now invokes `checkmake --config=.checkmake.ini Makefile`.
>
>   Separately worth knowing: `lint-makefiles` is reached via `lint-infra` →
>   `lint`, but its `command -v checkmake` guard means it silently does nothing
>   unless checkmake happens to be installed — and nothing in this repo installs
>   it (no CI step, no tools image, unlike hadolint/shellcheck/trivy/semgrep,
>   which are all containerised). The step is currently a no-op everywhere.

The second group is the actual argument against a blanket move: for these
three, "add a flag" isn't available — semgrep and checkmake don't take one
for this purpose, and even where a flag exists in principle, **every
invocation site would need it**, including ones this repo doesn't control:
a contributor's editor plugin running `golangci-lint`/`bandit` on save, a
`pre-commit` hook, a fresh contributor typing `bandit -r src/` by habit.
Miss one, and the failure mode is a linter that silently checks less than it
used to — the same class of "quietly stopped working" bug Phase 800 spent
this whole session chasing in Docker's build cache. Trading a cosmetic `ls`
annoyance for a new instance of that bug class is a bad trade.

### 2d. `.hadolint.yaml` is a special case: already dead, not worth relocating either

`hadolint` is invoked via `docker run ... hadolint $(HADOLINT_IGNORE) --no-color - < "$$f"` — Dockerfile content piped over stdin, **no repo volume mounted at all**. `.hadolint.yaml` cannot be read by that invocation; it's referenced only in a Makefile *comment* ("see `.hadolint.yaml` for rationale"). Actual rule suppression happens via the `HADOLINT_IGNORE` CLI flags a few lines above. This file is vestigial today regardless of where it lives — flagged for a possible follow-up deletion, not a move.

### Recommendation

**Don't create a `Dots/`/`.config/` folder.** The payoff (tidier `ls -la`)
doesn't justify re-deriving and testing every tool's config-discovery
behaviour, including invocation paths outside this repo's control, for a
problem GitHub's UI has already solved. If the local-`ls` annoyance is
genuinely bothersome day to day, the eight "already explicit" tools in the
first table are the only ones worth touching — see §4 for a scoped,
optional version of that if wanted.

## 3. Other findings from a fresh root audit (not covered by Phase 205)

| Item | Tracked? | Finding |
|---|---|---|
| `dc_head.yml` | Yes | Orphaned — grepped every script/Makefile/compose file, zero references. Last touched by a Phase-233 commit and an old "propose Phase 160" commit; looks like a stray `docker compose config` dump someone left at root. Confirmed while bumping image versions this session (its `haproxy`/`redis` pins were separately kept in sync only because it happened to be touched then, not because anything reads it). |
| `.gitlab-ci/ja4proxy-policy.yml` | Yes | **Not this repo's CI config** — it's a distributable GitLab CI *template* for JA4proxy customers to `include:` in their own pipelines (policy-as-code, same category as `deploy/integrations/`). Phase 205 moved `integrations/` → `deploy/integrations/` for exactly this reason but didn't catch this one — it's mis-filed as a hidden CI dotdir, not mis-scoped as "maybe dead" (205's own note said "audit whether still in use" — it's in active use, just misplaced). |
Root `tailwind.config.js` **vs.** `management/tailwind/tailwind.config.js` | Yes (both) | **Corrected after reading `VENDOR.md` and the actual template** — root config is the live one, not the stray. `management/templates/base.html` loads `/static/vendor/tailwind.css`; that file only exists at `management/static/vendor/tailwind.css`, produced by the pipeline `VENDOR.md` documents (Tailwind v4 CLI + the **root** `tailwind.config.js`). `management/tailwind/tailwind.config.js`'s own header targets Tailwind v3 and writes to `management/static/tailwind.css` (no `vendor/`) — that path **doesn't exist on disk**, meaning that pipeline's documented output was never produced by what's actually deployed. `git log` confirms the ordering: root `tailwind.config.js` and `VENDOR.md` were both last touched by PR #155 ("vendor frontend assets and compile static CSS", 2026-06-14); `management/tailwind/` was last touched by the earlier PR #121 ("UI redesign", 2026-06-11) and never touched again — it's the superseded one. **D5 below is corrected accordingly: delete `management/tailwind/`, not the root config.** |
| `monitoring/`, `security/__pycache__/` at root | **No** (untracked, root-owned) | Local machine cruft, not a repo problem — `monitoring/` is a stray leftover from an unrelated Docker run (already called out in a `Makefile` comment as confusing `lint-yaml` locally); `security/` is an empty dir + `__pycache__` left over after Phase 205's `security/validation.py` move actually succeeded. Out of scope for this phase — it's this machine's disk, not the repository. |
| `requirements*.txt` × 3 at root | Yes | Phase 205 already explicitly evaluated and **dropped** this (its own X8: "cosmetic win did not justify atomic rewrites across Dockerfiles/CI/Makefile/Dependabot"). Not reopening it here — citing it so nobody re-proposes it a third time without checking history first. |

## Key decisions (for review)

| # | Decision | Why |
|---|---|---|
| D1 | Move `PHASE_316a-e_notes.md` → `docs/phases/complete/`, `PHASE_800_notes.md` → `docs/phases/`. | Matches the convention 14 other phases already follow; zero functional risk (verified above). |
| D2 | **Do not** create a `Dots/`/`.config/` folder for linter dotfiles. | §2 — the stated rationale doesn't apply to hidden files, Phase 205 already tried and dropped it, and three tools (`bandit`, `checkmake`, `semgrep`'s ignore-file) have no safe relocation path without risking silent scan-scope regressions in invocations this repo doesn't control. |
| D3 | Move `.gitlab-ci/ja4proxy-policy.yml` → `deploy/integrations/gitlab-ci/` (or `deploy/gitlab-ci/`). | It's a product/customer deliverable, not this repo's CI config — belongs with `deploy/integrations/`, not disguised as a dotdir. |
| D4 | Delete `dc_head.yml`. | Confirmed orphaned; deleting (not moving) since there's no live consumer to relocate it for. |
| D5 | Delete `management/tailwind/` (the whole directory, not just its config). Keep the root `tailwind.config.js` — it's the live one `VENDOR.md`'s documented build actually uses. | §3 correction: initial research had this backwards. `management/tailwind/tailwind.config.js` targets Tailwind v3 and writes to a CSS path (`management/static/tailwind.css`) that doesn't exist on disk — its pipeline was superseded by PR #155's root-config + `vendor/tailwind.css` build, which is what `base.html` actually loads. Keeping a stale, never-produces-output copy around risks someone editing it and wondering why nothing changes. |
| D6 | Leave `.hadolint.yaml` in place, untouched, this phase. | It's dead either way (§2d) — deleting it is a separate, smaller decision than this phase's scope; don't bundle it in just because it was noticed here. |

## Implementation plan

1. `git mv PHASE_316{a,b,c,d,e}_notes.md docs/phases/complete/`
2. `git mv PHASE_800_notes.md docs/phases/`
3. Update the two prose references (`docs/phases/PHASE_800.md`, `.github/workflows/ci.yml`'s `notify-scheduled-failure` issue body) to the new paths.
4. Confirm no template or build script references `management/tailwind/` (re-grep at implementation time — none found as of this doc), then `git rm -r management/tailwind/`. Keep the root `tailwind.config.js`.
5. `git mv .gitlab-ci/ja4proxy-policy.yml deploy/integrations/gitlab-ci/ja4proxy-policy.yml`; update its own internal `include: local:` example path in the file's header comment. **Do not** edit the references found in `docs/reports/05_deployment_supply_chain_review.md`, `docs/phases/complete/PHASE_205_review.md`, or `docs/phases/complete/PHASE_82.md` — all three are dated, point-in-time historical records of a past state, not live documentation; retroactively editing them to reflect a 2026-07-21+ move would misrepresent what those reviews actually found at the time. Re-grep for `.gitlab-ci` at implementation time to confirm no *live* doc (e.g. a current deployment guide) references the old path.
6. `git rm dc_head.yml`.
7. `make lint-docs` / `make lint-md` (whichever link-check target exists) to confirm no dangling references from steps 3–6.
8. CHANGELOG fragment, manifest `802` → `COMPLETE`.

## Test plan

- `grep -rln` for every old path (six notes filenames, `.gitlab-ci`, `dc_head.yml`, `management/tailwind/`) across the repo post-move → zero hits outside this phase's own commit.
- `make lint-docs` (or equivalent link-checker) passes.
- `make test` and `make lint` unaffected (none of these files are inputs to either — the entire point of D2 is that the *tooling-input* dotfiles are the ones being left alone).

## Acceptance criteria

- [ ] Six phase-notes files relocated; both prose references updated.
- [ ] `.gitlab-ci/` content moved under `deploy/`; all doc references updated; no repo-root dotdir masquerading as a customer deliverable.
- [ ] `dc_head.yml` and `management/tailwind/` (the superseded Tailwind v3 pipeline, not the live root config) removed.
- [ ] No new `Dots/`/`.config/` directory created — D2 stands as a documented "no," not silence.
- [ ] `.hadolint.yaml`'s dead status is noted but left untouched (D6).
- [ ] Full CI green; no dangling links.

## Out of scope

- **Dotfile-to-subfolder relocation for the "already explicit `--config`" tools** (`.golangci.yaml`, `.yamllint.yaml`, `.gitleaks.toml`, `.trivyignore`, `.luacheckrc`, `.pymarkdown`, `.codespellignore`, `.semgrep-phase122.yml`). These *could* move with acceptable risk if the local-`ls` clutter is a genuine, ongoing annoyance — but given §2a (GitHub doesn't show them anyway) the payoff is purely local-developer convenience. Worth doing only if explicitly requested with that trade-off understood; not bundled into this phase's default scope.
- **`requirements*.txt` consolidation into `pyproject.toml`** — already evaluated and dropped by Phase 205 (X8). Not reopened.
- **`.hadolint.yaml` deletion** — noted as dead (§2d) but deleting unused config is a different, smaller decision than relocating live config; left for a follow-up if wanted.
- **Local, untracked root cruft** (`monitoring/`, `security/__pycache__/`) — not a repository concern; this machine's own cleanup, not a phase.

## Risks

- **Low overall** — every move in scope (§1, D3–D5) was verified reference-free or has its references enumerated above; this is the deliberately "easy" half of the original question. The higher-risk half (dotfile relocation) is the one this phase recommends *against*, which is itself the main output of the critical review requested.
- **`.gitlab-ci/` move risk: LOW-MEDIUM.** It's a template file users `include:` by a literal path in their own GitLab pipelines. If any external documentation (not just this repo's docs) points at the current path, moving it is a breaking change for those users — check `docs/reports/05_deployment_supply_chain_review.md` and any customer-facing docs for the exact `include:` path shown to users before moving, and consider whether a version bump / release note is warranted alongside the move.
