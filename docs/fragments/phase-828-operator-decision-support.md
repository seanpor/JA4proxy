- **The console explains its decisions (Phase 828b)**: fingerprint pages now
  show a "Why this score" panel listing every contributing signal, its
  contribution and the human-readable reason the scoring module wrote, plus a
  "what would happen at another dial" strip. Previously the page showed a
  number and nothing else.
- **The live feed stopped discarding two thirds of each event (Phase 828b)**:
  rows now carry `ja4proxy.bypass_reason`, country and ASN organisation. The
  bypass reason matters most — a connection blocked by an explicit list entry
  and one blocked by its risk score rendered identically as "block / 100",
  despite calling for opposite responses. All row values are HTML-escaped;
  they originate from the network.
- **"How many times has this signature been seen at this IP" is answerable
  (Phase 828c)**: IP pages show a per-`(ip, ja4)` breakdown and a shape verdict
  — `single-client`, `shared-egress` or `mixed`. One fingerprint dominating an
  address is an automated client; many fingerprints with none dominant is a
  shared egress such as CGNAT, carrying real users. The verdict describes an
  observed distribution and deliberately carries no action.
- **"Unknown" location replaced with an honest status (Phase 828d)**: the IP
  profile returned a hardcoded `{"country": "Unknown", "asn": "Unknown"}` for
  every address. It now reports `resolved`, `not-routable` (private, CGNAT or
  reserved — no owner exists), `lookup-failed` (GeoIP database absent, with the
  runbook linked) or `unallocated`. Those are four different situations calling
  for different actions and were previously one word.
- **Advisory suggestions with a blast radius (Phase 828d)**: each IP page
  proposes a next step and states what acting on it would cost. A shared egress
  can never produce a ban suggestion no matter how much of its traffic is
  blocked — banning one CGNAT address can remove several hundred real
  subscribers. The route is read-only and nothing auto-applies.
- **The async scoring path publishes its result (Phase 828)**: `Process()`
  returns a stub `{allow, 0}` and queues the real work, so the score, signals
  and counterfactuals were computed after the telemetry event had already been
  written and never left the process — the first connection from any
  `(IP, JA4)` pair was published as "score 0, no explanation". The proxy now
  emits a second event when the worker finishes. Both carry
  `ja4proxy.connection_id`; `ja4proxy.event_phase` marks `provisional` versus
  `final`, and the analytics node and console skip provisional entries so
  nothing double-counts.
- **New metric `ja4proxy_analytics_events_skipped_total{reason}` (Phase 828)**:
  deliberate non-processing, kept out of the rejection counter so the
  `AnalyticsEventsRejectedHMAC` alert stays meaningful.
