<!--
title: "Phase 246 — Discovery, Onboarding & First-5-Minutes Experience"
audience: developer
last_reviewed: 2026-06-25
phase: 246
-->

# Phase 246 — Discovery, Onboarding & First-5-Minutes Experience

## Status: COMPLETE

All five sub-phases (246.1–246.5) shipped in #269 (`cd55a96d`): GitHub repo
description/topics, README rewrite, management dashboard in
`docker-compose.yml`, the "First 5 minutes" guide, and the integration
quick-reference table. The `246` roll-up entry in `manifest.yaml` was still
`IN_PROGRESS` despite every sub-phase being `COMPLETE` — corrected here.

## Problem Statement

JA4proxy has strong product documentation (WHY_JA4PROXY.md), solid deployment
guides, and a capable management UI — but the front door (README, GitHub
description, first-run experience) speaks to engineers, not to the website
owners who need it most.

A website owner whose forms are being hammered by bots lands on the GitHub repo
and sees: badges, "Enterprise-Grade Go Runtime", "TLS-aware passthrough",
"ClientHello metadata". They bounce before reaching the content that would
actually help them.

The product's unique value — identifying bots by *how their software connects*,
which cannot be faked — is buried. The "will this break my site?" reassurance
(monitor mode, ALPN browser bypass) is an aside instead of the headline. The
emergency deploy path ends at terminal logs instead of a dashboard. The GitHub
repo has no description that matches what people search for and zero topics.

## Goals

1. Someone googling "open source bot protection" or "stop bots self-hosted"
   can find this repo and understand what it does in 30 seconds.
2. After emergency deploy, the user sees a live dashboard showing traffic
   scoring within 60 seconds — not just terminal logs.
3. The README answers "will this break my site?" before the user has to ask.
4. The GitHub repo description and topics reflect what this product does in
   words real people use.

## Sub-phases

### 246.1 — GitHub Repo Description & Topics
**Size:** SMALL | **Dependencies:** none

Update the GitHub repo description and add discoverable topics.

**Description:** A short, searchable sentence that leads with the problem.

**Topics:** bot-protection, anti-bot, tls-fingerprinting, reverse-proxy,
web-security, ja4, self-hosted, open-source, waf-alternative,
bot-mitigation, credential-stuffing, scraping-protection

**Acceptance criteria:**
- [x] `gh repo edit` updates description and topics
- [x] Description is under 250 chars and contains "bot", "protection", "open source"
      (verified 2026-07-03; description was 252 chars, trimmed to 220)

### 246.2 — README Rewrite for Humans
**Size:** MEDIUM | **Dependencies:** none

Restructure the README so the first screen answers three questions:
1. What problem does this solve? (bots, scrapers, credential stuffing)
2. How does it work? (one-paragraph plain English, no jargon)
3. Will it break my site? (no — monitor mode, browser bypass)

Then progressive disclosure: quick start, architecture, badges, compliance.

**Acceptance criteria:**
- [x] First paragraph mentions bots/scrapers/form spam — not TLS internals
- [x] "How it works" uses an analogy a non-engineer can follow (bouncer/fake ID)
- [x] "Will this break my site?" section exists above the fold
- [x] Badges moved below the intro (still present, just not leading)
- [x] Emergency banner preserved at top
- [x] "Start by role" table preserved
- [x] Quick start references both `docker compose` and pre-built image
- [x] Architecture section preserved (moved lower)

### 246.3 — Management UI in Minimal Docker Compose
**Size:** SMALL | **Dependencies:** none

Add the management UI service to `docker-compose.yml` so emergency deployers
get a dashboard at `http://localhost:8090` immediately.

**Acceptance criteria:**
- [x] `docker-compose.yml` includes management service on port 8090
- [x] EMERGENCY_DEPLOY.md updated with "Open http://localhost:8090 to see your traffic"
- [x] Dashboard link appears in `docker compose up` output or README quick start

### 246.4 — "What To Do Next" First-Run Guide
**Size:** SMALL | **Dependencies:** 246.2

A new section in the README or a linked doc that walks through the first 5
minutes after deploy:
1. Open the dashboard — see traffic being scored
2. Look at the top fingerprints — which are bots?
3. Block one fingerprint — see it take effect
4. Raise the dial from 0 to 25 — let the proxy start auto-blocking
5. Monitor for a day before going higher

**Acceptance criteria:**
- [x] Step-by-step guide with expected output at each step
- [x] Links to incident response doc for deeper actions
- [x] Covers the "oh shit I blocked everything" recovery (set dial back to 0)

### 246.5 — Integration Quick-Reference Cards
**Size:** MEDIUM | **Dependencies:** 246.2

Add a "How do I point my traffic here?" section to the README with 4
one-paragraph integration summaries (nginx, Cloudflare, AWS, bare metal)
that each link to the full DEPLOYMENT_MODES.md section.

**Acceptance criteria:**
- [x] README section with 4 integration paths
- [x] Each path is 3-4 lines max with a link to full instructions
- [x] Covers: nginx, Cloudflare, AWS NLB, direct (no LB)

## Out of Scope

- GitHub Pages / marketing site (future phase)
- Pre-built image publishing changes (already exists in CI)
- Changes to the proxy binary or Go code
- Changes to the management UI code (just wiring it into compose)
