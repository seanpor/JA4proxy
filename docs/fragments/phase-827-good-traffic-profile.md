- **The good-traffic profile, and the CGNAT false positive it exposed (Phase 827)**:
  `CLAUDE.md` says a blocked real user costs far more than a missed bot, but
  "real user" had never been written down, so the detectors were tuned against
  attack traffic alone. `docs/reference/GOOD_TRAFFIC_PROFILE.md` defines the
  reference deployment's legitimate traffic — an Irish consumer filling in a web
  form — and `tests/fp_corpus/test_good_traffic_profile.py` executes it as
  acceptance criteria. Writing it down immediately surfaced a live defect.
  `SlowScanDetector` convicted on shape alone: **>=20 unique IPs in a /24
  averaging <=3 requests each**, which is a verbatim description of a busy five
  minutes on a CGNAT'd mobile ISP subnet where unrelated real people each load
  the form once. Not cosmetic: the finding writes `analytics:slowscan:<subnet>`
  with a **30-minute TTL**, which `internal/security/analytics_signals.go` reads
  back as **+30 on the risk score of every connection from that /24** (thresholds
  flag 20 / rate_limit 35 / tarpit 55) — and the TTL is the length of the form
  session, so the penalty outlives the interaction it interrupts. The fix is
  corroboration rather than a looser shape test: a slow scan now also requires
  the group to agree on a **client-identity** dimension (JA4/JA4T/JA4X/UA) above
  `slow_scan.min_shared_share`, default 0.80, hot-reloadable, 0 to disable. ASN,
  country, SNI, ALPN and TLS version are deliberately excluded — within one
  subnet, all visiting one site, those are uniform for legitimate traffic too
  and would reopen the FP. Twenty real people are twenty-ish browsers; twenty
  scanner IPs are one tool. Two existing fixtures gave every event its own
  synthetic fingerprint (the signature of unrelated real users, not of a scan)
  and now share one, as a real scan does.
- **ASN provenance reaches the connection event (Phase 827)**: `ASNClassifier`
  resolved the ASN number and organisation on every connection and discarded
  both, so `correlation.py` declared `asn`/`asn_org` dimensions nothing could
  populate and no detector could tell a consumer ISP /24 from a hosting provider
  /24. `ClassifyAndLookup()` now returns them from the same traversal (one DB
  read, `Classify()` kept as a wrapper), `ConnectionContext` carries them, and
  `cmd/ja4pd` emits `client.as.number` / `client.as.organization.name`.
  Provenance is recorded on the paths that produce **no** signal — residential
  and mobile, i.e. exactly the traffic most worth identifying — while an
  unavailable lookup stays a zero value rather than a guess.
- **Redis connection logs no longer carry anything password-derived (Phase 827)**:
  CodeQL alert #100 (`py/clear-text-logging-sensitive-data`, high) traced
  `REDIS_PASSWORD` into the management API's connection logs via
  `_redact_redis_url`. The redaction was correct, but taint analysis cannot
  verify a hand-rolled sanitiser and the guarantee rested on every future edit
  preserving a property no tool checks. `_redis_endpoint()` reads only
  `hostname` and `port` off the parse result — fields that structurally cannot
  hold credentials — so the secret never reaches the logger to be cleaned. The
  failure path logs the exception **type**, never `str(exc)`, which embedded the
  raw URL. The logs lost nothing: they existed to say which Redis was reached.
- **`make` stopped warning about the root-owned Trivy cache (Phase 827)**:
  `SHELL_SCRIPTS` is expanded at parse time, so its `find` ran on every
  invocation and hit container-created root-owned dirs under `.local/`. The
  resulting "Permission denied" printed before any target started, making
  `make clean` look like it had failed when it had not begun.
- **`make lint-pylint` is clean again (Phase 827)**: it was reporting five
  errors, all false. `weasyprint` is an optional dependency imported under
  `try/except` (now in `ignored-modules`), and pylint intermittently anchored on
  `api` rather than `management` as the source root because `management/` is a
  PEP 420 namespace package (now pinned via `source-roots`).
