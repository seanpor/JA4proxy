# ADR-202c: Explicit UID 1000 in `Dockerfile.go-proxy`

**Status:** Accepted
**Date:** 2026-04-15
**Phase:** 202 (CI supply chain hardening) — sub-phase 202c

---

## Context

`deploy/docker/Dockerfile.go-proxy` already runs the proxy as a non-root
user (`USER ja4proxy`, added in an earlier phase). However, the user is
created with busybox `adduser -S` which assigns a **random system UID in the
range 100–999**. Two concrete operational problems follow:

1. **Kubernetes Pod Security Admission `restricted` profile** checks the
   **numeric** UID (`runAsUser`, `runAsNonRoot` with the `!= 0` check plus
   the "must-run-as-non-root" validator). Many installations hard-code
   `runAsUser: 1000` in their pod spec or `PodSecurityContext`. An image
   that resolves `USER ja4proxy` to UID 487 (or whatever busybox picked on
   the build day) then fails to start with
   `container has runAsNonRoot and image has non-numeric user (ja4proxy)`
   on some kubelet versions, or with UID-mismatch errors on others.

2. **Host volume bind-mounts** (e.g. for development or sidecar log
   shipping) conventionally expect container UID 1000 — the first
   non-system UID on most Linux hosts. An unpredictable build-time UID
   means `chown` scripts and documented permissions break per-rebuild.

Phase 202c pins the UID (and GID) to `1000:1000` explicitly, and sets
`USER 1000:1000` numerically rather than by name.

---

## Options

### Option A — Keep `USER ja4proxy` and random UID (status quo)

Rejected. Breaks PSA `restricted` and makes volume ownership unpredictable
(documented above).

### Option B — Pin to UID `1000:1000` explicitly

```dockerfile
RUN addgroup -g 1000 -S ja4proxy && adduser -u 1000 -S -G ja4proxy ja4proxy
USER 1000:1000
```

Chosen. `1000` is the de-facto industry standard for the first non-privileged
user on Linux — it aligns with `nginx`, `postgres`, most Bitnami images, and
the `nobody`-alternative convention for non-system service accounts.
Numeric `USER` lets kubelet's `runAsNonRoot` validator accept the image
without reading `/etc/passwd`.

### Option C — Pin to a "high" UID like `65532` (distroless `nonroot`)

Distroless's `nonroot` user is `65532`. Considered but rejected for this
phase: our base image is alpine, not distroless; adopting the distroless
convention without adopting distroless itself would be cosmetic and
surprising to operators whose other alpine-based images use 1000. If a
future phase migrates the runtime image to distroless, revisit under a
superseding ADR.

---

## Decision

Use **Option B**: explicit `-u 1000` / `-g 1000` in `adduser`/`addgroup`,
and `USER 1000:1000` (numeric) in the Dockerfile.

---

## Consequences

**Positive**
- PSA `restricted` profile compatible out-of-box; Helm chart can set
  `runAsUser: 1000` without further image changes.
- Predictable file ownership for bind-mounts and volume-mount `chown`
  documentation.
- Numeric UID enables kubelet `mustRunAsNonRoot` validation without
  `/etc/passwd` lookups.

**Negative / tradeoffs**
- **Possible UID collision with host users.** On a host where UID 1000
  is a named human user, a bind-mounted host directory writable by that
  user is now ALSO writable by the container process. Mitigation: for
  production deployments use Docker named volumes (not bind-mounts to
  host home directories) — already the default in
  `deploy/docker/docker-compose.poc.yml`. Dev-laptop bind mounts are an
  acknowledged corner case.
- **Migration.** Any existing persistent volume created by a previous
  image version (random UID) will not be writable by the new UID 1000
  process until `chown -R 1000:1000` is run. Volumes in-scope for this
  project (Redis, Grafana, Prometheus) are owned by their own service
  containers, not by `ja4proxy-go`, so no migration is needed.
  Confirmed against `deploy/docker/docker-compose.poc.yml` at 2026-04-15:
  the `ja4proxy-go` service declares no persistent volume mounts.

**Not done here**
- Rootless-container mode (userns-remap). Out of scope; Docker/Kubernetes
  cluster-level concern, not image-level.
- `seccomp` / `AppArmor` profile for the image — covered separately in the
  TAP-mode seccomp work (Phase 20).

## Revisit if...

- We move to a distroless runtime image (revisit the `1000` vs `65532`
  question).
- A future phase adopts userns-remap and the effective UID on the host
  becomes `100000 + 1000`, which would reopen the host-UID collision
  analysis.

## Implementation notes

- File: `deploy/docker/Dockerfile.go-proxy`.
  - Line 39: four-attribute `LABEL` block
    (`org.opencontainers.image.{source,title,description,licenses}`),
    placed immediately after `FROM alpine:3.19` on line 36.
  - Line 47: `RUN addgroup -g 1000 -S ja4proxy && adduser -u 1000 -S -G ja4proxy ja4proxy`.
  - Line 59: `USER 1000:1000` (numeric, per kubelet `runAsNonRoot`
    validation requirements).
- Verification commands:
  ```
  docker build -f deploy/docker/Dockerfile.go-proxy -t ja4proxy-go:test .
  docker inspect --format='{{ .Config.User }}' ja4proxy-go:test     # → 1000:1000
  docker inspect --format='{{index .Config.Labels "org.opencontainers.image.source"}}' ja4proxy-go:test
  docker run --rm --entrypoint /bin/sh ja4proxy-go:test -c 'id -u && id -g'  # → 1000 / 1000
  hadolint deploy/docker/Dockerfile.go-proxy
  ```
- Live CI verification of the built image (digest, signature, label
  inspection on GHCR) is deferred to the first green run of
  `.github/workflows/go-proxy-image.yml` after merge; see
  `PHASE_202_notes.md`.
