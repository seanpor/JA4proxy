### Phase 246 — Discovery, Onboarding & First-5-Minutes Experience

- **GitHub repo description** rewritten to lead with "bot protection" — now
  discoverable by people searching for anti-bot solutions. Added 13 topics
  (bot-protection, anti-bot, self-hosted, tls-fingerprinting, etc.).
- **README rewritten for website owners**, not just engineers. Opens with the
  problem (bots, scrapers, credential stuffing), explains how it works in
  plain English, and answers "will this break my site?" above the fold.
  Badges and supply-chain governance moved to the bottom.
- **Management dashboard** added to the minimal `docker-compose.yml` — new
  deployers now get a live UI at `localhost:8090` showing traffic, risk
  scores, and one-click blocking out of the box.
- **First-5-minutes guide** in README walks new users from deploy through
  their first block and dial adjustment, including recovery from accidental
  over-blocking.
- **Integration quick-reference** added to README with nginx, Cloudflare,
  AWS NLB, and direct-mode paths linking to full deployment guides.
