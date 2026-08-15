- **Go 1.26.5 → 1.26.6, clearing eight CVEs from our own images (Phase 822)**:
  bumped the five digest-pinned `golang:*-alpine` builders (`go-proxy`,
  `ja4-tap`, `cli`, `mockbackend`, `security-scan`), `go.mod`, and seven CI
  `go-version` pins. `ja4proxy:2.0.0` now scans **completely clean with no
  ignorefile at all** — previously it carried `CVE-2026-39821` and
  `CVE-2026-46600`, plus the six-CVE Go stdlib batch (`CVE-2026-33818`,
  `-56853`, `-56858`, `-56859`, `-56860`, `-56862`) that a Trivy DB update
  surfaced on 2026-08-15 and which had turned `make scan-images` red on `main`.
- **Split `.trivyignore` into first-party and third-party scopes (Phase 822)**:
  `Makefile` passed the *same* ignorefile to both `scan-images` and
  `scan-first-party`, and Trivy's ignorefile has no per-image scoping — so
  every waiver granted to an abandoned monitoring sidecar also suppressed the
  same finding in the proxy we ship. This was not hypothetical:
  `CVE-2026-39821` and `CVE-2026-46600` were waived with justifications written
  entirely about Grafana/Promtail/Alertmanager/cAdvisor — *"they consume
  metrics/logs or serve authenticated admin UIs only"* — while both were live
  in an internet-facing TLS proxy, and both were fixable by a one-line Go bump.
  Now `.trivyignore.first-party` (**4 entries**, all genuinely unfixable by any
  rebuild we can perform — pip's own vendored `msgpack`/`setuptools`, `protobuf`
  in the CI-only test image, `python-ecdsa` in management) and
  `.trivyignore.third-party` (**55**). The two files also carry *different
  rules*: first-party forbids waiving anything a rebuild can fix; third-party
  requires only that no fix be reachable without replacing the image — which is
  the honest criterion the old single file's header claimed but could not
  enforce (70 of its 73 entries carried a non-empty `FixedVersion`).
- **Keep the split from silently re-merging (Phase 822)**:
  `tests/unit/test_trivyignore_split.py` asserts the two scan targets reference
  *different* ignorefiles, that no CVE appears in both files, that the retired
  single `.trivyignore` has not reappeared, and that the Go-bump-fixed CVEs are
  never waived first-party. One test specifically guards the mis-edit made while
  implementing this phase — a single `sed` over both occurrences pointed
  `scan-first-party` at the third-party file, which would have restored the
  original bug while looking like the fix. Also updated
  `scripts/renew_trivyignore.py` and the weekly renewal workflow to walk **both**
  files: left pointing at the retired path, the automation would have become a
  silent no-op, which is exactly the failure Phase 812 existed to fix.
