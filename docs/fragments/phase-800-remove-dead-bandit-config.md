- **Delete the inert `.bandit` file (Phase 800)**: it was a Python script, not
  bandit's INI config format, referenced by nothing and never loaded (`profile
  exclude tests: None`). Verified by scanning a probe file using `hashlib.md5`
  (B324) and `yaml.load` (B506) — both in its skip string — with and without the
  file present: byte-identical output, both issues reported either way. Of its 17
  IDs, `B410`/`B417` no longer exist in bandit 1.8 and `B905`/`B906` are ruff
  codes. Removed because making it *work* would have silently disabled
  hardcoded-password, SQL-injection and unsafe-YAML-load detection. Corrects the
  `.bandit` row in `docs/phases/complete/PHASE_802.md`.
