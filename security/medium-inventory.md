# MEDIUM vulnerability inventory (MEDIUM)

Recorded: 2026-10-23 — produced by `scripts/medium_inventory.py`. The numbers below are the script's output, not a hand-written summary.

## Headline

- **79** unwaived MEDIUM finding(s) across **18** surface(s)
- **48** of them have a **published fix** for the same package (31 have none published)
- **1** are on a surface that publishes a host port; **78** are on a surface that does not
- **4** on images this repository builds, **75** on third-party images

The decision this measurement informed, and the reasoning behind it, are recorded in `docs/phases/PHASE_847e.md`.

## By kind — how a fix could arrive

| Kind | Findings | A fix arrives when… |
|------|----------|---------------------|
| Go (standard library or module) | 26 | the upstream project rebuilds its image with a newer Go toolchain |
| Python (a distribution we install) | 3 | we rebuild our own image |
| OS or base-image package | 50 | the upstream project rebuilds its image on a newer base |

## Reachability

- **75** of the 79 findings are inside third-party images, whose binaries and packages have **no static reachability signal available to us** — their source is not ours to analyse, and the operating-system packages in them are not linked against anything we can call.
- **4** are in images this repository builds.
- Nothing here is recorded as *unreachable*. A reachability claim without a check behind it is the one thing this programme is not allowed to make: Phase 847f is what turns a claim into an assertion, and until then the honest answer for every one of these findings is **unknown**.

## Per surface

| Surface | Scope | Exposure | Findings | With a published fix | Top packages |
|---------|-------|----------|----------|----------------------|--------------|
| `image:grafana/alloy` | third-party | no published host port | 16 | 1 | libgnutls30t64×6, libpcre2-8-0×3, dash×2 |
| `image:grafana/grafana` | third-party | no published host port | 31 | 15 | libgnutls30t64×6, stdlib×5, golang.org/x/net×4 |
| `image:grafana/loki` | third-party | no published host port | 0 | 0 |  |
| `image:haproxy` | third-party | published | 1 | 1 | zlib×1 |
| `image:ja4proxy` | first-party | no published host port | 0 | 0 |  |
| `image:ja4proxy-analytics` | first-party | no published host port | 0 | 0 |  |
| `image:ja4proxy-management` | first-party | not deployed in compose | 0 | 0 |  |
| `image:ja4proxy-mockbackend` | first-party | not deployed in compose | 0 | 0 |  |
| `image:ja4proxy-tap` | first-party | no published host port | 0 | 0 |  |
| `image:ja4proxy-tarpit` | first-party | no published host port | 1 | 1 | pip×1 |
| `image:ja4proxy-test` | first-party | not deployed in compose | 2 | 2 | mcp×1, opentelemetry-api×1 |
| `image:ja4proxy-trafficgen` | first-party | not deployed in compose | 1 | 1 | pip×1 |
| `image:oliver006/redis_exporter` | third-party | no published host port | 0 | 0 |  |
| `image:prom/alertmanager` | third-party | no published host port | 11 | 11 | stdlib×5, golang.org/x/net×4, golang.org/x/crypto×2 |
| `image:prom/prometheus` | third-party | no published host port | 0 | 0 |  |
| `image:redis` | third-party | no published host port | 9 | 9 | libcrypto3×8, zlib×1 |
| `image:tecnativa/docker-socket-proxy` | third-party | no published host port | 7 | 7 | libcrypto3×3, pcre2×3, zlib×1 |
| `pypi` | python | n/a | 0 | 0 |  |

## Notes

- **requirements.txt**: pip-audit reports no severity — its JSON carries id, aliases, fix_versions and description only. The existing gate therefore treats every pip-audit finding as gating (HIGH). There is no MEDIUM band to measure on this surface, and none is invented here.
