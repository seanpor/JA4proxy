- **Stop TruffleHog failing on 2670 false positives (issue #405)**: Lob API
  *test* keys begin with `test_`, so TruffleHog's Lob detector matched every
  pytest function name in the repository — and its verifier reported them as
  **verified**. Measured on `tests/unit` alone: 2670 verified "secrets", none
  real. That is what produced exit code 183 and failed the weekly scheduled run
  repeatedly; GitHub caps check annotations at around ten, which hid the scale
  and made it look like a handful of genuine leaks. The detector is now excluded
  via `--exclude-detectors=Lob`, which is safe because the project has no Lob
  integration at all (no `lob.com`, no `LOB_KEY`, no client library). The two
  `PrivateKey` hits were also checked: both are local dev TLS keys, untracked and
  covered by `*.key` in `.gitignore`, so they never reach a CI checkout.
