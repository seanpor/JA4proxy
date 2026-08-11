- **Make scheduled CI reproducible on demand (issue #405)**: `ci.yml` gained
  `workflow_dispatch`. A scheduled-run failure previously could not be
  re-triggered without waiting up to a week for the next Monday, which is why
  #405 sat open with its secrets-scan failure undiagnosed.
- **Fix TruffleHog scan scope on non-push events (issue #405)**: the config
  claimed the weekly schedule "falls through to a full HEAD scan". It did not —
  `github.event.before` is populated only for `push`, so on `schedule` the base
  resolved to an empty string while head was set, giving an unintended and
  undocumented scan scope. `base`/`head` are now set explicitly for `schedule`
  and `workflow_dispatch`, so the full-history scan is what the config says it is.
- **Add `--seccomp-required` to `ja4-tap` (issue #244, F-400-02)**: the sensor
  logs a warning and runs unconfined when the seccomp profile cannot be loaded.
  That fail-open default is deliberate — the BPF filter is linux/amd64 only, so
  failing closed everywhere would refuse to start on other architectures — but it
  means the hardening can be absent while the sensor looks healthy. The new flag
  (default `false`, no behaviour change) lets a deployment opt into failing
  closed instead.
