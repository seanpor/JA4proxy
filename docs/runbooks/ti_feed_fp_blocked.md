<!--
title: "TI feed FP corpus block Runbook"
audience: oncall, sre, security
last_reviewed: 2026-04-26
phase: 101
-->

# Runbook — TIFeedFPBlocked

**Alert:** `TIFeedFPBlocked`
**Source:** `deploy/monitoring/alertmanager/rules/ti_feed.yml`
**Severity:** warning
**Phase:** 101 (cross-phase deferred-review register, sub-phase 101c C6)

## Symptom

`rate(ja4proxy_ti_feed_fp_blocked_total{feed_id="<id>"}[15m]) > 0` sustained
for 15 minutes.

A TI feed attempted to add a JA4 fingerprint that matches the local FP
(false-positive) corpus at `fixtures/ti_feeds/ja4_fp_corpus.txt`. The block
was refused — no Management API blocklist entry was created — but **the
attempt itself is suspicious** and warrants investigation.

## Why this is high signal

The FP corpus contains JA4 fingerprints of **known legitimate browsers**
(Chrome, Firefox, Safari, Edge, mobile Safari). A TI feed should never
suggest blocking these. If a feed does, exactly one of these is true:

1. **The upstream is corrupted or poisoned.** A vendor's threat database has
   bad entries, or someone has injected entries via their submission API.
2. **The FP corpus is stale.** A new browser version has shipped a JA4 that
   isn't in our corpus yet, and a real malicious tool happens to share that
   fingerprint. (Genuine collision is possible but rare.)

## Immediate action

1. Identify which feed attempted the FP block:
   ```
   curl -s http://analytics:9100/metrics \
     | grep ja4proxy_ti_feed_fp_blocked_total
   ```
2. Pull the offending JA4(s) from the runner logs:
   ```
   docker logs ja4proxy-analytics 2>&1 \
     | grep -E "fp_blocked|seed_entry_fp_blocked" | tail -50
   ```
3. Cross-check the JA4 against the FP corpus:
   ```
   grep "<ja4>" fixtures/ti_feeds/ja4_fp_corpus.txt
   ```
4. If the JA4 is a legitimate browser fingerprint that appears in your own
   traffic mix (check `ja4proxy_ja4_observed_total{ja4="<ja4>"}` from the
   live proxy), the upstream is publishing a known-bad indicator.
   **Pause the feed.**

## Common causes

| Cause | Indicator | Fix |
|---|---|---|
| Vendor false positive | One-off entry, rest of feed is sane | File ticket with vendor; keep feed running (block is refused) |
| Compromised vendor account | Many FP entries in a single poll | Pause feed, rotate credentials, contact vendor security |
| Stale corpus | JA4 looks like a new browser version | Update `fixtures/ti_feeds/ja4_fp_corpus.txt` and redeploy |
| New TI feed of unknown quality | First few polls all hit FP | Treat as red flag — deeply review the source before re-enabling |

## Recovery

- If you updated the FP corpus, redeploy the analytics container so
  `ja4_safe_to_block` reloads.
- If you paused the feed, `TIFeedStale` will eventually fire — this is the
  correct trade-off.
- The metric is monotonically increasing, so the alert clears 15 minutes
  after the last FP attempt.

## Escalation

- Multiple feeds firing simultaneously → suspect a coordinated supply-chain
  attack on multiple TI vendors. **Page security on-call immediately.**
- A single feed firing on a JA4 that matches your own production browser
  traffic → security incident; investigate as a poisoning attempt.

## Related

- `docs/phases/complete/PHASE_101.md` §C6 — FP corpus check spec
- `fixtures/ti_feeds/ja4_fp_corpus.txt` — the corpus itself
- `src/analytics/ti_feeds/ja4_safety.py` — `ja4_safe_to_block`
- `docs/runbooks/ti_feed_caps_hit.md`
