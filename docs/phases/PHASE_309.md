---
phase: 309
title: Documentation Content Audit — Source-of-Truth Review of All Docs
status: PLANNED
created: 2026-06-10
audience: [developer, operator, security]
---

# Documentation Content Audit — Source-of-Truth Review of All Docs

> The documentation has drifted from the product. The user guide reads as a
> proof-of-concept; tables overflow the page in the reference manual; version
> strings say "Edition 1.0" while the product ships v2.0.0; and an unknown
> amount of prose describes commands, ports, keys, and architecture that the
> Go-native v2.0.0 code no longer matches. This phase reviews the **contents**
> of every document for correctness and coherence, verifying each claim against
> the **live source code and config** — not against historical phase docs.
>
> [[PHASE_307]] did a coherence + link-remediation pass. This phase goes deeper:
> it is about **factual correctness vs the implementation**, document by
> document. Because the corpus is large (~140 documents), the work is broken
> into independently-shippable chunks ("work packages"). Each chunk ships as its
> own branch + PR and can be split further if still too big.

## Ground rules (the review constitution)

These apply to **every** work package without exception.

1. **Source-of-truth precedence.** When a doc and the code disagree, the code
   wins. Order of authority:
   `live code/config (cmd/, internal/, config/proxy.yml, Makefile, deploy/) `
   `> shipped artifacts (PDFs, Helm chart, compose) > phase docs/manifest`.
   **Phase docs are a historical record and are presumed stale** — never cite a
   phase doc as evidence that a feature behaves a certain way today.
2. **Verify, don't assume.** Every command, flag, port, path, env var, metric
   name, Redis key, config key, binary name, and file reference in a doc must be
   confirmed to still exist in the code before it is left unchanged.
3. **ADRs are history, not specs.** Do not rewrite an ADR to match current code.
   Verify the decision still holds; if superseded, append a dated
   "Superseded by …" note rather than editing the original rationale.
4. **No claim without evidence.** Performance numbers, efficacy percentages, and
   capacity figures must trace to a measured, dated source
   (e.g. `docs/performance/benchmarks.md`). Unsourced marketing claims are
   removed or corrected, per the discipline already applied to the brochure.
5. **Go is production; Python is experimental.** Operator-facing instructions
   target the Go binaries (`ja4pd`, `ja4p`) and the container/compose deploy
   path. Python-proxy references are removed from production guidance (continuing
   [[PHASE_307]]'s cleanup) and retained only where prototyping is the subject.
6. **Coherence.** Terminology, product/binary naming, version strings, and
   cross-references must agree across all documents.

## Documentation metadata standard (set in WP-0, applied everywhere after)

Every document carries, going forward:

- **Version:** `2.0.0` (decision: match the product version string, not an
  "Edition N" scheme).
- **Last reviewed:** the date the *content* was verified against the code — a
  **content-revision date, not the LaTeX/PDF build date**. This is the gap the
  user flagged: `\the\year` / PDF `CreationDate` must never stand in for it.
- **Mechanism:**
  - LaTeX docs — `\docversion{2.0.0}` + `\lastreviewed{YYYY-MM-DD}` macros in
    `docs/pdf/shared/ja4proxy-style.sty`, rendered on the title page / cover in
    place of the current `\date{Edition 1.0 \the\year}` and the hardcoded
    "Edition 1.0" on the back cover.
  - Markdown docs — the existing HTML-comment frontmatter already used in
    `docs/README.md` (`title:`, `audience:`, `last_reviewed:`), extended with a
    `version:` field. A doc is "reviewed" only when its `last_reviewed` is bumped
    by a WP that actually verified it.

## Work packages (chunks)

Executed roughly in this order; each is its own PR. A ✅ in "Verified vs" means
the WP's acceptance gate requires checking claims against that source.

| WP | Scope | Size | Verified vs |
|----|-------|------|-------------|
| **WP-0** | Immediate fixes + metadata standard | S | — |
| **WP-1** | Reference manual: layout/overflow remediation | M | build only |
| **WP-2** | Reference manual: content audit | L | code/config ✅ |
| **WP-3** | User guide: content audit (targeted) | M | code/config ✅ |
| **WP-4** | Brochure: verify & close | S | benchmarks/code ✅ |
| **WP-5** | Operator markdown docs | L | code/config/Make ✅ |
| **WP-6** | Reference/schema docs | M | code/config ✅ |
| **WP-7** | Runbooks (46) — in batches | XL | code/scripts ✅ |
| **WP-8** | Security docs (18) | L | code/config ✅ |
| **WP-9** | ADRs (33) — validate, annotate | M | decisions still hold |
| **WP-10** | Standards/process + cross-doc coherence sweep | M | all docs ✅ |

### WP-0 — Immediate fixes & documentation metadata standard
*The approved quick wins from this session, plus the standard everything else inherits.*

- Author name: `Sean O'Riordain` → **`Seán Ó Ríordáin`** (`user-guide/chapters/preface.tex:87`; check all signatures/`\author`/PDF metadata). UTF-8 + T1 fontenc already present, so it renders directly.
- Versioning: replace `Edition 1.0` / `\date{Edition 1.0 \the\year}` / back-cover "Edition 1.0" with **Version 2.0.0** + a **last-reviewed date** via the new `\docversion`/`\lastreviewed` macros.
- Add the markdown `version:`/`last_reviewed:` frontmatter convention (documented in `docs/DOCUMENTATION_STANDARDS.md`).
- Back-cover index link `docs/INDEX.md` → `docs/README.md` — **already fixed** (commit `92eca436`), rebuild the other two PDFs to match.
- **Acceptance:** all 3 PDFs rebuild clean; name correct; version/date macros render a content date; standard documented.

### WP-1 — Reference manual layout remediation
- Fix the **113 overfull-hbox** warnings (scope decision: **tables + code/URLs**).
  - Tables: `tabularx`/`L{}R{}` column sizing, `\small`, wrap or abbreviate over-wide cells.
  - Code/URLs: `\seqsplit`, `\url{}`, breakable `listings`/`minted`, or hard wraps.
- **Acceptance:** `pdflatex` build reports **zero** overfull hboxes wider than 2pt; visual spot-check of every previously-overflowing page.

### WP-2 — Reference manual content audit
- Chapter-by-chapter verification of every technical claim (config keys, Redis keys, metric names, pipeline behaviour, ports, CLI) against `internal/`, `cmd/`, `config/proxy.yml`.
- **Acceptance:** a per-chapter claims ledger (claim → source location → ok/fixed); no contradictions remain.

### WP-3 — User guide content audit (targeted)
- Remove POC framing (`user-guide.tex`, `preface.tex`); correct stale commands/architecture against current code; align with the Go deploy path. Deeper rewrites flagged as follow-ups rather than blocking.
- **Acceptance:** no POC framing in operator guidance; all cited commands/flags/ports verified; claims ledger for changed chapters.

### WP-4 — Brochure verify & close
- Confirm the session's rewrite (throughput ~2,500 cps, binary names, deploy path, heap-alloc figures) against the code/benchmarks; apply the new metadata standard.
- **Messaging rework pending discussion.** The user finds the current brochure
  "odd" and unconvincing — it reads like an engineering changelog, not a buyer
  pitch (no clear persona, cost-of-inaction, or credibility framing). Fact-verify
  now; do **not** polish prose until a dedicated positioning discussion has
  happened. This WP does not close until that rework lands.
- **Acceptance:** every brochure claim traces to a verified source; metadata applied; messaging reworked per the agreed positioning.

### WP-5 — Operator markdown docs
- `GETTING_STARTED`, `OPERATIONS_GUIDE`, `POC_QUICKSTART`, `DEPLOYMENT_OPTIONS`, `DEPLOYMENT_SECURITY_MODEL`, `SCALING_GUIDE`, `UPGRADE_PATH`, `DMZ_READINESS`, `FAQ`, `ONBOARDING`, `EVALUATION_CHECKLIST`, `TCO_AND_LICENSING`, `WHY_JA4PROXY`.
- **Acceptance:** commands/targets/ports/architecture verified vs code, Makefile, and compose; `last_reviewed` bumped per file actually checked.

### WP-6 — Reference/schema docs
- `REDIS_SCHEMA` (every key vs code), `OBSERVABILITY_STANDARDS` (metric names vs `internal/metrics`), `MAKEFILE_TARGETS`/`SERVICE_TARGETS`/`SCRIPTS` (vs Makefile/scripts), `config/proxy.yml` inline docs.
- **Acceptance:** every documented key/metric/target/script exists; orphans removed; missing ones added.

### WP-7 — Runbooks (46) — batched
- Verify each runbook's procedures/commands run against the current system. Ship in batches (~8–10 runbooks per PR) to keep chunks reviewable.
- **Acceptance:** per-batch claims ledger; dead procedures fixed or retired.

### WP-8 — Security docs (18)
- Reconcile claims with the implementation and with the code-scanning closeouts ([[PHASE_304]], [[PHASE_305]], [[PHASE_308]]).
- **Acceptance:** no security claim contradicts the code; cross-refs to the relevant phases where relevant.

### WP-9 — ADRs (33) — validate & annotate
- Confirm each decision still holds in v2.0.0; append dated "Superseded by …" notes where it does not. **No rewriting of original rationale.**
- **Acceptance:** every ADR carries a current-status line; superseded ones link forward.

### WP-10 — Standards/process docs, information architecture & cross-doc coherence
- `STYLE_GUIDE`, `DOCUMENTATION_STANDARDS`, `TESTING_STRATEGY`, `HOW_WE_WORK`, `QUALITY_PLAN`, `PHASE_LIFECYCLE`.
- **Information architecture (the "all over the place" problem).** Per-file
  fact-fixing does not fix structure. A prior cull reduced volume; this step goes
  further: group the 39 top-level `docs/*.md` by audience into subdirectories
  (building on the role-based layout `docs/README.md` already implies), collapse
  overlapping docs to **one authoritative doc per topic** with "see also" links,
  and retire/redirect the rest. Candidate overlaps to resolve:
  `DEPLOYMENT_OPTIONS` / `DEPLOYMENT_SECURITY_MODEL` / `DMZ_READINESS`;
  `WHY_JA4PROXY` / `SCOPE_AND_LIMITATIONS` / `FAQ`;
  `OPERATIONS_GUIDE` / `OPERATIONS_MAPPING` / runbooks. Propose the target tree
  for the user's sign-off before moving files (links/`make sync` must follow).
- Final sweep: consistent product/binary naming, single version string (2.0.0), working cross-references, glossary, and a repo-wide link check.
- **Acceptance:** target IA agreed and applied; coherence checklist passes; link check clean; `make sync` clean.

## Test / verification strategy

- **PDF docs:** `pdflatex` builds with zero overfull hboxes > 2pt; title/cover show version 2.0.0 + last-reviewed date; visual spot-check.
- **Markdown:** existing doc lint (`make lint-docs-all`), repo link checker, and `make sync` all clean; doc-CI gates (e.g. `tests/test_attack_mapping.py`) green.
- **Per-WP claims ledger:** a table committed with each PR — `claim → source-of-truth file:line → verdict (ok | fixed)` — so the audit is auditable.
- **Coherence checklist (WP-10):** naming, version, cross-refs, glossary.

## Acceptance criteria (parent phase)

- [ ] Every document carries **Version 2.0.0** and a **content `last_reviewed` date**.
- [ ] Every operator-facing command/flag/port/key/metric/target cited in docs is verified to exist in the current code/config, or corrected.
- [ ] No production guidance references the experimental Python proxy.
- [ ] All three PDFs build clean (no overfull hboxes > 2pt) and render the new metadata.
- [ ] Author name is `Seán Ó Ríordáin` everywhere it appears.
- [ ] Repo-wide link check and `make sync` pass; relevant doc-CI gates green.
- [ ] `CHANGELOG.md` entry + `manifest.yaml` marked COMPLETE; each WP recorded.

## Out of scope

- Rewriting ADR history (only annotate).
- Product **code/config changes**, except trivial doc-driving fixes already
  covered elsewhere; this is a **docs-only** phase.
- Net-new documentation beyond filling gaps surfaced by the audit.
- Translation / localization.
- The brochure rewrite already merged this session (WP-4 only *verifies* it).

## Execution notes

- Each WP is a separate branch `phase-309-wpN-<slug>` and PR; the parent
  `PHASE_309.md` tracks WP status. WP-7 (runbooks) is itself batched.
- WP-0 establishes the metadata macros/conventions that WP-1…WP-10 apply, so it
  runs first.
- Suggested first deliverable on approval: **WP-0 + WP-1** together (the
  user's flagged immediate items: name, version/date, and the reference-manual
  overflow remediation).
