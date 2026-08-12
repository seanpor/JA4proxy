- **Close out superseded Phase 251; add Phase 251a plan**: Phase 251 (pipeline
  lifecycle & memory safety) was leased but never landed — two of its three
  findings were since fixed on main (`internal/security/blocklists.go:198`;
  Phase 515 / JA4PROXY-2026-0090). Its WIP is preserved as
  `docs/phases/complete/PHASE_251_WIP.patch` (design reference only), and the
  one surviving OPEN finding (JA4PROXY-2026-0089 — ReplaceConfig orphaning
  DNS/AbuseIPDB/RDAP/feed enrichment workers on hot reload) is re-scoped
  against current code as Phase 251a (`docs/phases/PHASE_251a.md`).
