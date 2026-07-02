# Phase 516 — Documentation Sync: Decision Cache (Phase 515)

## Status: OPEN

## Summary

Phase 515 fixed the Go proxy's decision cache to match ADR-003: keyed per client
(`clientIP|JA4`), asymmetric ALLOW/BLOCK TTLs enforced on read, and a new
hot-reloadable `decision_cache:` config block. This phase syncs the operator- and
reference-facing documentation to that change — chiefly the offline PDF reference
manual, which enumerates every config block and defines the cache in its glossary.

Note the direction of the drift: the existing docs already described the
*intended* ADR-003 behaviour (per-IP decision, ALLOW 30 min / BLOCK 30 s). It was
the **code** that had diverged, not the docs. So this phase is additive
(document the new config block) plus a small precision fix (the cache key is the
client IP *and* its JA4, not the IP alone) — not a correction of wrong prose.

---

## Why Now?

The `decision_cache:` block is new operator-facing configuration with security-
and-performance-relevant TTLs. The reference manual documents every other tunable
block (`proxy`, `dial`, `security_policy`, `geoip`, `abuseipdb`, `rdap`,
`spamhaus`, `redis`); omitting `decision_cache` would leave operators unable to
tune (or even discover) the ALLOW/BLOCK cache TTLs, and the "Hot Reload Behaviour"
table would be incomplete. The PDFs are the offline deliverables operators use, so
they must build cleanly with the new content.

---

## Scope

### In scope
- `docs/pdf/reference-manual/chapters/ch03-configuration-ref.tex`
  - Add a `decision_cache` section (key/type/default/description table for
    `allow_ttl_seconds`, `block_ttl_seconds`, `max_entries`) mirroring the other
    config-block sections.
  - Add a `decision_cache` row to the "Hot-reload support" table (Yes — TTLs apply
    to new decisions; cross-reference ADR-003).
  - Add the block to the "Complete Configuration Example" YAML if that example is
    intended to be exhaustive.
- `docs/pdf/reference-manual/chapters/glossary.tex`
  - Tighten the "Warm cache" / "Cold cache" entries: the cache is keyed on the
    client (its IP **and** JA4 fingerprint), not the IP alone. Keep the correct
    asymmetric-TTL wording (ALLOW 30 min / BLOCK 30 s).
- `docs/pdf/reference-manual/chapters/ch02-pipeline.tex`
  - If it describes the decision cache / fast path, note the per-client
    (IP + JA4) key so the "cached, fast path" row is precise.
- Rebuild the affected PDF(s): `make -C docs/pdf reference-manual` (and `all` if
  shared front-matter changed), commit the regenerated `.pdf`.
- Cross-check other prose docs that mention the decision cache
  (`docs/design/README.md`, runbooks) — update only if they state the key or TTLs
  and are now imprecise. Do not rewrite unrelated caching prose.

### Out of scope
- The code fix itself (Phase 515).
- The deferred hot-reload worker-lifecycle fix (JA4PROXY-2026-0089, Phase 517).
- Brochure/user-guide chapters that don't discuss the decision cache.
- Re-documenting `config/proxy.yml` — it is self-documenting and was updated in
  Phase 515.

---

## Acceptance Criteria

- [ ] `decision_cache` documented as its own section in the reference-manual
      config chapter, with the three keys, types, defaults, and per-client keying
      + asymmetric-TTL semantics (ADR-003 cross-reference).
- [ ] `decision_cache` appears in the hot-reload support table (Yes).
- [ ] Glossary "warm/cold cache" entries say the key is client IP + JA4, not IP
      alone; TTL wording retained.
- [ ] No prose doc claims the decision cache is keyed on JA4 alone.
- [ ] Affected PDF(s) rebuild with zero LaTeX errors (`make -C docs/pdf
      reference-manual`), and the regenerated `.pdf` is committed.
- [ ] News fragment `docs/fragments/phase-516-decision-cache-docs.md`.
- [ ] `manifest.yaml` set to COMPLETE at close-out.

---

## Implementation Notes

- Follow the LaTeX conventions already in each file (`\code{}`, `yamlcode`,
  `\section`/`\subsection`, the `tabular` table style used by the other config
  sections).
- Build: `make -C docs/pdf reference-manual` (host `pdflatex` is available). If the
  build touches shared front-matter, run `make -C docs/pdf all`.
- The `.pdf` files are committed artifacts — `git add` the regenerated PDF with
  the `.tex` changes in the same commit.

---

## Effort Estimate

- ch03 config section + hot-reload row: ~40 min
- glossary + pipeline precision edits: ~20 min
- PDF build + visual check: ~20 min

**Total: ~1.5 hours.**
