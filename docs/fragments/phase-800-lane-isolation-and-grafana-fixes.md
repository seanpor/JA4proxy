- **Restore multi-lane isolation for the monitoring stack (Phase 800)**: lane
  assignment (`scripts/lane-env.sh`) worked for the poc/prod stacks but not for
  monitoring, for two independent reasons. `docker-compose.monitoring.yml` pinned
  ten `container_name:` values, and Docker container names are globally unique
  per host — so a second lane's monitoring stack could not start at all
  ("container name /ja4proxy-grafana is already in use"). And
  `HOST_PORT_ALERTMANAGER` was absent from `lane-env.sh`'s port map while the
  compose published `${HOST_PORT_ALERTMANAGER:-9093}`, so every lane fell back to
  the same host port. Both fixed: containers are now named per
  `COMPOSE_PROJECT_NAME` like the other stacks, and alertmanager is lane-offset.
  Prometheus/Grafana references switched from container names to compose **service**
  names, which are lane-independent (the Grafana datasource `uid:` values are
  identifiers referenced by dashboards, not hostnames, and are unchanged).
- **Fix three Grafana config bugs (Phase 800)**: the container was crash-looping
  (13 restarts). `GF_SERVER_KEY_FILE` matches no Grafana setting — the override
  for `[server] cert_key` is `GF_SERVER_CERT_KEY` — so `cert_key` stayed empty and
  startup failed with "cert_key cannot be empty when using HTTPS". Reproduced on
  both 13.0.4 and 13.0.6, so this was never version-specific. Two further bugs in
  its healthcheck, masked by the crash-loop: it probed `http://` against an
  HTTPS-only server, and used `wget`, which the image does not contain (probe exit
  code -1 — it never ran). Now `curl -fsk https://…`; container reports healthy.
- **Generate the PoC stack's secrets (Phase 800)**: `docker-compose.poc.yml`
  bind-mounts five secret files that nothing in the repo created, so `make
  bench-all` died at `perf-test` with a bare Docker bind-mount error before
  `test-go-perf`, `load-test` and `measure-mttr` ever ran. New
  `scripts/ensure-poc-secrets.sh` derives the names from the compose file (rather
  than a hand-maintained list, which is what drifted before), generates only what
  is missing at 0600, and never overwrites. `perf-test` now depends on it.
