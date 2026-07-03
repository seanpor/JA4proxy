# Phase 524 — Documentation Consistency Audit + SecOps "Bots Filling My Forms" Use Case

> **For the implementing engineer (a junior, assumed new to this repo):** this
> phase fixes documentation, not code. Every issue below gives the exact file,
> the exact current text, *why it's wrong* (with the code that proves it), and
> the exact replacement text. Do them in order. When a fix touches a claim about
> behaviour, open the cited code file and confirm the behaviour yourself before
> writing — that habit is the whole point of this phase.

## Status: OPEN

## Summary

A review of the user-facing docs against **each other** and against **the actual
code** turned up one load-bearing inconsistency and several smaller ones, and
confirmed that the product's headline use case — *"a SecOps engineer whose web
forms are being filled by bots"* — is stated in the README title but **never
actually developed**, and is described in a way that the shipped default config
contradicts.

The big one: the README and `CLAUDE.md` promise that real-browser (h2/h1 ALPN)
traffic **can never be blocked** — "an architectural guarantee, not a heuristic."
But the shipped config **disables** that bypass by default
(`alpn_browser_bypass: enabled: false`, `JA4PROXY-2026-0004`) precisely because a
bot can spoof `ALPN=h2`. So the guarantee as written is **false for the default
deployment**, and the reason it was turned off is *exactly* the forms-bot use
case. Fixing the docs and writing the use case honestly are the same job.

---

## How to work this phase (read first)

1. **No code changes.** Only `.md`, `.tex`, and `config/proxy.yml` **comments**.
2. **Verify every behavioural claim against code before you write it.** Key files
   you will need to open:
   - `config/proxy.yml` — the shipped defaults (this is the source of truth for
     "what does it do out of the box").
   - `internal/security/pipeline.go` — `checkBypasses()` shows the ALPN bypass is
     gated on `cfg.ALPNBrowserBypass`; `buildPipelineConfig` (in
     `cmd/ja4pd/main.go`) maps it from `security_policy.alpn_browser_bypass`.
   - `CLAUDE.md` — the agent/architecture master plan (also needs fixing).
3. **Build the PDFs after `.tex` edits.** `pdflatex` is available;
   `make -C docs/pdf all` (or a single guide). The `.pdf` files are committed —
   `git add` the regenerated PDF with its `.tex` change.
4. **Definition of done:** every issue below fixed, the consistency `grep` checks
   in each finding return clean, PDFs rebuild with zero LaTeX errors, and the new
   use-case section reads correctly to someone who has never seen the product.
5. **Ask if unsure whether a claim is true.** When code and a doc disagree, the
   **code is the source of truth** — fix the doc, and if the *code* looks wrong,
   stop and raise it (do not "fix" code in this phase).

---

## Finding D1 (MAJOR) — "real browsers can never be blocked" contradicts the shipped default

### The contradiction

- **Code / config (source of truth):** `config/proxy.yml`:
  ```yaml
  alpn_browser_bypass:
    enabled: false          # Default: false (JA4PROXY-2026-0004).
                            # ALPN is an attacker-controlled field in the
                            # ClientHello — any bot can set ALPN=h2 and
                            # bypass the entire pipeline.
  ```
  With this default, `pipeline.go` `checkBypasses()` does **not** allow-bypass h2/h1
  traffic. Real browsers are **scored** like everything else. They are only
  protected from blocking by (a) **monitor mode** (`dial: 0` default → nothing is
  ever blocked), (b) **fail-open**, (c) an operator adding browser JA4s to the
  **JA4 whitelist** (`ja4_whitelist_bypass: true`, but the list is empty by
  default), and (d) conservative thresholds.
- **Docs (wrong):**
  - `README.md` ~lines 34-36, guarantee #2: *"Real browsers can't be blocked …
    These connections bypass all scoring — they cannot be blocked by any rule,
    threshold, or misconfiguration. This is an architectural guarantee, not a
    heuristic."*
  - `CLAUDE.md` line ~151: *"`h2`/`h1` ALPN browser traffic bypasses everything —
    it can never be blocked."*
  - `CLAUDE.md` line ~116 pipeline diagram: `h2 / h1 ALPN? → ALLOW immediately`.

The doc describes the behaviour **before** `JA4PROXY-2026-0004` flipped the default
off. It is now stale and materially misleading in both directions: an operator
either (a) trusts a guarantee that isn't in force and is surprised when a raised
dial blocks a real browser, or (b) leaves the bypass off thinking bots can't look
like browsers — the opposite of why it was disabled.

### The fix

1. **`README.md` guarantee #2 — rewrite** to describe the *actual* safety model.
   Replacement text (adapt tone to the surrounding section):
   > **2. Safe by default, and you control the pace.** On first deploy the dial is
   > at 0 (monitor mode) — every connection is scored but **nothing is blocked**,
   > so you can see what *would* happen before enforcing. You can also whitelist
   > the JA4 fingerprints of the browsers you care about so they bypass scoring
   > entirely. Note: the automatic "any h2/h1 connection is a browser" bypass is
   > **off by default** — because a bot can trivially set `ALPN=h2` to impersonate
   > a browser (`JA4PROXY-2026-0004`) — so browser-*looking* traffic is scored,
   > not waved through. If you want the old unconditional browser bypass, enable
   > `security_policy.alpn_browser_bypass` (and understand that bots can then use
   > it).
2. **`CLAUDE.md` line ~151** — replace the invariant bullet:
   > - `h2`/`h1` ALPN browser bypass is **configurable and off by default**
   >   (`JA4PROXY-2026-0004`): ALPN is attacker-controlled, so a bot can set
   >   `ALPN=h2`. When the bypass is *enabled*, h2/h1 traffic is allowed without
   >   scoring; when disabled (default), it is scored like any other connection.
   >   FP-safety comes from monitor-mode (dial=0) + fail-open + the JA4 whitelist,
   >   not from an unconditional ALPN bypass.
3. **`CLAUDE.md` pipeline diagram (line ~116)** — annotate the ALPN step so it is
   not read as unconditional:
   `├── h2 / h1 ALPN?  → ALLOW immediately   (only if alpn_browser_bypass enabled; OFF by default)`
   Apply the same annotation to the identical diagram in the other `CLAUDE.md`
   copy if present (`grep -rn "h2 / h1 ALPN" .`).
4. **Reconcile the two `CLAUDE.md` files** — there are two (`/CLAUDE.md` and
   `JA4proxy/CLAUDE.md`, per the repo layout). Fix both, or confirm one is a
   symlink/duplicate. `grep -rn "can never be blocked" .` must return nothing
   after this fix.

### Verify (consistency checks — must all be clean after the fix)
```bash
grep -rniE "can never be blocked|cannot be blocked by any|architectural guarantee" README.md CLAUDE.md docs/
grep -rn "alpn_browser_bypass" config/proxy.yml   # confirm default is still false
```

---

## Finding D2 (MAJOR) — the performance docs benchmark the deleted Python proxy

### The contradiction
`docs/reports/PERFORMANCE_BENCHMARK.md` states the throughput ceiling is
"**~210 connections/second**" and that "the bottleneck is the **single Python
asyncio event loop**." But the **Python proxy was deleted** — the production
proxy is Go (`cmd/ja4pd`, `internal/`); see `CLAUDE.md`'s "The proxy is Go-only"
banner. So the headline numbers and the stated bottleneck describe an
implementation that no longer ships. `README.md` (~line 207) links to this
document as "measured results," propagating the stale figure.

### The fix
1. Add a prominent banner at the top of `docs/reports/PERFORMANCE_BENCHMARK.md`:
   > **⚠ These figures are from the retired Python prototype proxy (removed in the
   > Go rewrite, Phase 15). The production proxy is Go and its throughput is
   > materially higher and single-thread-bound no longer. Treat the numbers below
   > as historical.**
2. Re-measure the Go proxy (this is the real fix, not just a banner). A Go
   benchmark harness already exists — `internal/test/bench/` and `make bench-all`.
   Run it, and either (a) replace the numbers with measured Go figures, or (b) if
   a full load test is out of scope, keep the banner and open a follow-up ticket
   to re-benchmark. State clearly which you did.
3. `README.md` ~line 207: soften "measured results" to point at the (now
   correctly-labelled) document, and remove any specific stale conn/s number if
   one is quoted in the README itself (`grep -n "conn/s\|210" README.md`).

### Verify
```bash
grep -rniE "python asyncio|asyncio (event )?loop|single.thread" docs/reports/PERFORMANCE_BENCHMARK.md README.md
# after fix: only appears inside the "historical" banner/section, never as current fact
```

---

## Finding D3 (MINOR) — inconsistent credentials & loopback-URL guidance

### The contradictions
- `docs/operations/POC_QUICKSTART.md` line ~71: "Open **http://localhost:3000**
  (admin / password printed by `./start-all.sh` …)". Port 3000 is **Grafana**,
  not the management UI (8090/8444); the credential guidance here reads as if it
  is the app login. And `localhost` (not `127.0.0.1`) reintroduces the
  corporate-proxy-intercept problem that Phase 511/512 deliberately fixed
  elsewhere.
- `docs/operations/EMERGENCY_DEPLOY.md` line ~92 gives the management password as
  `changeme`; the README gives `admin / changeme`. Make the guidance consistent
  and unambiguous about *which* service each credential is for.

### The fix
1. In `POC_QUICKSTART.md`: label the `:3000` line explicitly as **Grafana** and
   give Grafana's own credential source; separately state the **management UI**
   URL (`http://127.0.0.1:8090` / `https://127.0.0.1:8444`) and its `admin`
   credential source. Change `localhost` → `127.0.0.1`.
2. Ensure every doc that names the default admin password says the same thing and
   points to the same env var (`MANAGEMENT_ADMIN_PASSWORD`, default `changeme` in
   the quickstart) **and** reminds the reader to change it — cross-reference the
   related `JA4PROXY-2026-0096` finding about the weak default secret.
3. Sweep for stray `localhost` in operator docs:
   `grep -rn "http://localhost" docs/operations/ README.md`.

### Verify
```bash
grep -rn "localhost:3000\|http://localhost" docs/operations/POC_QUICKSTART.md
grep -rniE "changeme|admin ?/ ?" README.md docs/operations/EMERGENCY_DEPLOY.md docs/operations/POC_QUICKSTART.md
```

---

## Finding D4 (THE REQUESTED USE CASE) — write the "bots are filling my forms" SecOps story, honestly

### Why it's needed
The README title is "Bot Protection" and its first line is "If bots are filling
out your forms…", but there is **no section that walks the desperate SecOps
engineer from that problem to a working, tuned deployment** — and, given D1, the
docs currently imply browser-looking traffic is untouchable, which is the wrong
mental model for exactly this person. This use case is also where the product's
honest limits must be stated so the engineer isn't misled.

### What to add
A new use-case section — put it in `docs/operations/` (e.g.
`USE_CASE_FORM_ABUSE.md`) and link it from the README "Start by role" area and
from the user-guide PDF (`docs/pdf/user-guide/chapters/ch01-introduction.tex` or
ch07 incident response). Write it for a stressed on-call engineer. It **must**
contain all of the following, and every claim must match the code/config:

1. **The scenario (1 paragraph).** "Your signup / login / contact form is being
   hammered by automated submissions. You need to cut the bot traffic without
   blocking real customers, today."
2. **What JA4proxy catches out of the box.** Bots using **non-browser TLS
   stacks** (curl, Python `requests`, Go `net/http`, custom scanners, many
   commodity bot frameworks) have distinctive JA4 fingerprints and no/odd ALPN —
   they score high and, once you raise the dial, are rate-limited → tarpitted →
   banned. Because `alpn_browser_bypass` is **off by default**, a bot that merely
   *claims* `ALPN=h2` does **not** get a free pass — it is still scored (this is
   the honest, correct version of the old "browsers can't be faked" claim).
3. **The honest limit — bots that drive a *real* browser.** Headless Chrome /
   Playwright / Puppeteer / a real browser under automation produce a **genuine
   browser JA4 and real h2**, indistinguishable *at the TLS layer* from a human's
   Chrome. JA4 alone will **not** separate them. State this plainly. Then give the
   levers that *do* help for that traffic: per-IP / per-JA4 **rate limiting**,
   **beaconing** detection (regular timing), **ASN/datacenter** classification
   (form bots often run from cloud IPs), **AbuseIPDB** reputation, and the
   **analytics** signals — none of which depend on the TLS stack looking non-browser.
4. **The step-by-step playbook** (commands must be real — verify against
   `EMERGENCY_DEPLOY.md` and the CLI):
   - Deploy in **monitor mode** (dial 0) and watch the decision log / dashboard to
     see which fingerprints and IPs are hitting the form.
   - Block the obvious non-browser bot JA4s immediately (`ja4-admin.sh block-ja4 …`
     — verify the exact command).
   - Raise the **dial** gradually and watch the false-positive rate.
   - For cloud-hosted browser bots, enable/tune **datacenter policy** and
     **rate limiting**; consider AbuseIPDB.
   - Note the tradeoff of enabling `alpn_browser_bypass` (don't, for this use
     case — you *want* browser-looking traffic scored).
5. **Expectation-setting.** JA4proxy is a **pre-TLS metadata** filter: it is
   excellent against non-browser and spoofing bots and a strong *signal source*
   against browser-driven bots, but it is **not** a CAPTCHA or a full
   application-layer bot manager and never inspects the form contents. Say so.

### Acceptance criteria for D4
- [ ] A dedicated use-case doc exists, linked from README and the user-guide PDF.
- [ ] It distinguishes non-browser bots (caught) from real-browser-driven bots
      (signal-only, not caught by JA4 alone) — **honestly**.
- [ ] Every command/config key in it is verified against the code/CLI.
- [ ] It is readable by a non-expert on-call engineer (no undefined jargon).

---

## Overall acceptance criteria
- [ ] D1–D3 fixed; all "Verify" `grep` checks return clean.
- [ ] D4 use-case doc written and linked.
- [ ] Affected PDFs rebuild with zero LaTeX errors (`make -C docs/pdf all`).
- [ ] `make ci-verify` / `lint-phases` green; markdown link-check passes
      (`make link-check` if available).
- [ ] News fragment `docs/fragments/phase-524-docs-consistency.md`.
- [ ] `manifest.yaml` 524 → COMPLETE at close-out.

---

## Critical review of this phase doc (self-audit)

**Suitable for a junior with little codebase knowledge?** Yes — each finding names
the file, quotes the current text, cites the code that proves the doc wrong, and
gives replacement wording; the use case has a required-contents checklist so the
junior isn't asked to invent product truth. Pitfalls pre-empted:
- *"How do I know the ALPN default is really false?"* — open `config/proxy.yml`
  and read the `alpn_browser_bypass` block; the grep in D1 confirms it.
- *"Do I need to re-run a benchmark?"* — D2 gives both a minimum (banner) and the
  real fix (run `make bench-all`) and says to state which you did.
- *"Where does the use-case doc go?"* — D4 names the file and the two link sites.

**Did the requester's ask get fully covered?** The three asks map to: *consistent
with themselves* → D3 + the cross-doc greps; *consistent with the code* → D1
(ALPN default) + D2 (Python-vs-Go); *sensible* → D2 banner + D1 reframing;
*the desperate-SecOps-forms-bot use case* → D4; *written for a junior* → the whole
doc's format + this review.

**Other similar issues elsewhere (tell the junior to sweep):**
- The architecture/pipeline diagrams appear in several places (`README.md`,
  `CLAUDE.md`, the reference-manual PDF ch02). Any that show `ALPN → ALLOW`
  unconditionally need the D1 annotation: `grep -rn "ALPN" docs/pdf/ README.md CLAUDE.md`.
- Anywhere the docs still say "Python" for the *proxy* (not the management API /
  analytics, which **are** Python) is likely stale post-Go-rewrite:
  `grep -rniE "python.*proxy|proxy.*python" docs/ README.md` — triage each hit.
- Default-credential / default-secret guidance intersects `JA4PROXY-2026-0096`
  (Phase 522) — keep the wording consistent with that finding's fix.

## Out of scope
- Code changes (docs/config-comments only).
- Re-running a full production load test if D2's banner + a follow-up ticket is
  chosen instead (state the choice).
