# Phase 76: Enterprise RHEL Production Deployment Strategy

> **Scope:** Multi-host automated deployment of JA4proxy to Red Hat Enterprise Linux
> (RHEL 8/9) nodes that sit inline between load balancers and protected web-servers.
> This document covers the full decision framework, tooling choices, security hardening,
> operator experience, and day-2 reliability requirements.

---

## 1. Overview and Constraints

### 1.1 Network Position

Every deployment decision flows from a single hard constraint: **JA4proxy is inline**.
It sits in the real data path:

```
Internet → Enterprise LB (F5 / ALB / HAProxy / NGINX Plus)
                         → JA4proxy RHEL node (:8080)
                                             → Protected backend (:443)
```

This is not a typical stateless web application. Patterns that are fine for application
containers — auto-updates, uncoordinated rolling restarts, CNI overlay networking — carry
disproportionate risk here. Every tool and process choice must be filtered through:

- A container restart without LB drain causes in-flight connections to be RST.
- An incorrect deployment that passes the health check but has a scoring regression will
  silently make wrong allow/block decisions until noticed.
- The blast radius of an unreviewed automatic update is asymmetric and large.

### 1.2 Hard Rules for All Deployments

| Rule | Rationale |
|------|-----------|
| No compilers, build tools, or source code on production hosts | Minimal attack surface |
| Images built in CI only, never on hosts | Reproducibility, provenance |
| Every production deployment requires a change ticket reference | Audit trail |
| No auto-update tools on the proxy container | Inline path requires coordinated drain |
| Previous image tag kept locally for instant rollback | RTO < 60 seconds |
| SELinux must be Enforcing — hard fail pre-flight if not | Non-negotiable compliance |
| Secrets never in Ansible vars files or git | See §10 |

---

## 2. Deployment Model Decision Framework

Use this flowchart before choosing an orchestration approach:

```
Do you have an existing OpenShift or Kubernetes cluster already in production?
├── Yes → §5.3 (Kubernetes / OpenShift path)
└── No
    ├── Do you use HashiCorp Nomad + Consul already?
    │   ├── Yes → §5.4 (Nomad path)
    │   └── No
    │       ├── < 10 RHEL proxy nodes?
    │       │   └── Yes → §5.1 (Bare Podman + Quadlets + Ansible) ← DEFAULT
    │       └── ≥ 10 nodes OR GitOps maturity exists?
    │           └── Consider §5.3 or stay with §5.1 + AAP
```

**The default recommendation for most deployments is §5.1: Podman + Systemd Quadlets
managed by Ansible.** It has fewer moving parts, full RHEL-native support, and is the
right tool for a fixed set of inline proxy nodes. Do not introduce Kubernetes complexity
to justify it from scratch for this workload alone.

---

## 3. Container Runtime — Podman, Not Docker

### 3.1 Why Docker Is Wrong for Enterprise RHEL

**Daemon-as-root.** The Docker daemon runs as root. Every container operation is mediated
through a single privileged long-lived process. A container escape or daemon exploit grants
immediate root on the host. For an inline security proxy that is itself a target, this is
unacceptable.

**Licensing.** Docker Desktop requires a paid commercial subscription for organisations
with > 250 employees or > $10M revenue (2022 terms). Docker Engine on Linux is open
source, but `containerd` and `runc` are the actual OCI runtimes underneath — Docker is
a management wrapper you pay for. On RHEL the runtime you want is Podman.

**SELinux friction.** RHEL ships with SELinux enforcing by default. Docker's volume mount
labelling (`z`/`Z` flags) and custom SELinux policies frequently conflict with RHEL's
targeted policy, causing teams to either disable SELinux or maintain a parallel diverging
policy set. Podman integrates natively with SELinux through user-namespaces and the
existing `container_t` type enforcement.

### 3.2 Podman + Systemd Quadlets

Podman is daemonless — each container is a child process of the calling user or systemd.
There is no persistent privileged process to attack.

**Systemd Quadlets** (Podman ≥ 4.4, backported to RHEL 9.2) are INI-format unit files in
`/etc/containers/systemd/` that systemd's generator transpiles into full `.service` units
at boot. Benefits:

- Container lifecycle owned by systemd: `systemctl start ja4proxy-proxy.service` works
  identically to `systemctl start nginx`.
- Native restart policies, dependencies, and `After=network-online.target` ordering.
- `journald` captures all container stdout/stderr — `journalctl -u ja4proxy-proxy -f` works.
- SELinux labels declared at unit file level, not as ad-hoc flags.
- `systemd-creds` can inject secrets at start time with no credential file on disk.

**Reference Quadlet unit:**

```ini
# /etc/containers/systemd/ja4proxy-proxy.container
[Unit]
Description=JA4proxy Go Proxy
After=network-online.target
Wants=network-online.target

[Container]
Image=registry.internal.example.com/ja4proxy/go-proxy:1.2.3
Network=host
PublishPort=127.0.0.1:9090:9090
Volume=/etc/ja4proxy/config:/app/config:ro,z
Volume=/etc/ja4proxy/tls:/app/tls:ro,z
Secret=redis_password,type=env,target=REDIS_PASSWORD
AddCapability=NET_BIND_SERVICE
DropCapability=ALL
NoNewPrivileges=true
ReadOnly=true
Tmpfs=/tmp:rw,noexec,nosuid,size=64m
Tmpfs=/run:rw,noexec,nosuid,size=16m
SecurityLabelType=container_t

[Service]
Restart=on-failure
RestartSec=5s
StartLimitBurst=3
StartLimitIntervalSec=60s
WatchdogSec=30s
NotifyAccess=main

[Install]
WantedBy=multi-user.target
```

**`podman-compose` as a transitional tool.** If existing `docker-compose.*.yml` files
represent significant investment, `podman-compose` provides a migration path — it
translates Compose YAML to `podman run` invocations with no Docker daemon. Use it for
development and CI validation only. Production target state is always Quadlets.

**Anti-pattern:** Running `podman system service` as a persistent service in production
to keep using docker-compose tooling. This recreates a daemon-style attack surface.

---

## 4. Image Build Pipeline — CI Only, Never on Production Hosts

### 4.1 The Rule

No compiler toolchain, no `gcc`, no `go`, no `pip install` with build dependencies, no
Podman daemon in write mode on production hosts. Production hosts **pull and run**
pre-built, signed OCI images. They never build.

### 4.2 What the CI Pipeline Produces

For each tagged release, CI produces a bundle of artifacts that travel together:

| Artifact | Tool | Purpose |
|----------|------|---------|
| OCI image tar (multi-arch) | `docker buildx` / `podman manifest` | The deployable image |
| SBOM (CycloneDX format) | `syft` | Enumerate every package in the image |
| CVE scan report | `grype` against SBOM | Gate on CRITICAL CVEs |
| Cosign signature | `cosign sign` with KMS or keyless OIDC | Provenance — who built this, when, from which commit |
| SLSA provenance attestation | `cosign attest` | Supply chain integrity |

The CI pipeline **must fail and not push** to the registry if any of these fail:

- Any unpatched CRITICAL CVE in the final runtime image
- Cosign signing step fails
- SBOM generation fails

### 4.3 Multi-Stage Dockerfile — Correct Structure

The current `Dockerfile.go-proxy` includes `gcc` in the runtime image and uses
`CGO_ENABLED=0`. Both must be fixed:

```dockerfile
# Stage 1: Build — FIPS-capable Go toolchain
FROM registry.access.redhat.com/ubi9/go-toolset:1.23 AS builder

ENV CGO_ENABLED=1
ENV GOEXPERIMENT=boringcrypto
ARG SOURCE_DATE_EPOCH=0

RUN go build \
    -tags fips \
    -trimpath \
    -ldflags="-s -w -buildid= -extldflags '-static'" \
    -o /ja4proxy ./cmd/proxy

# Stage 2: Runtime — UBI9-minimal (no compiler, no gcc, no shell)
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.4

COPY --from=builder /ja4proxy /usr/local/bin/ja4proxy
USER 9999:9999
ENTRYPOINT ["/usr/local/bin/ja4proxy"]
```

Key points:
- `CGO_ENABLED=1` + `GOEXPERIMENT=boringcrypto` = FIPS-validated crypto (see §9).
- `-trimpath` + `-buildid=` = reproducible binary byte-for-byte.
- `FROM ubi9-minimal` replaces `alpine:3.19` — Red Hat errata, FIPS crypto provider.
- `gcc` and build tools exist only in the builder stage, never in the runtime image.

### 4.4 Multi-Architecture Builds

Build `linux/amd64` and `linux/arm64` manifests if RHEL ARM hosts exist (AWS Graviton,
Ampere). Use `docker buildx` with `--platform linux/amd64,linux/arm64` — a multi-arch
manifest index is pushed as a single tag; `podman pull` selects the correct variant
automatically.

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --file docker/Dockerfile.go-proxy \
  --tag $REGISTRY/ja4proxy/go-proxy:$TAG \
  --provenance=true \
  --sbom=true \
  --push .
```

The Python analytics container is `linux/amd64` only unless there is a concrete ARM
deployment requirement.

### 4.5 Image Flow: CI to Registry to Host

```
git tag v1.2.3
    │
    ▼
CI: multi-stage build (ubi9-minimal, boringcrypto)
CI: syft → SBOM (CycloneDX) → grype (gate: no CRITICAL CVEs)
CI: cosign sign → attach SBOM attestation → push to registry
    │
    ▼
Internal registry (Harbor / Quay)
    │  Registry re-scans on push; blocks promotion if CRITICAL unpatched
    ▼
Ansible deployment playbook triggered by human (push-based)
    │
    ├── podman pull $REGISTRY/ja4proxy/go-proxy:v1.2.3
    ├── cosign verify $REGISTRY/ja4proxy/go-proxy:v1.2.3  ← must pass, abort if fails
    ├── LB drain
    ├── systemctl restart ja4proxy-proxy.service
    ├── health gate passes
    └── LB undrain
```

**Auto-update tools (Watchtower, Flux `imageUpdateAutomation`, Renovate auto-merge)
are prohibited for the proxy container.** They restart without coordination, without
maintenance windows, without LB drain, and without human review. They are appropriate
for stateless monitoring sidecars with human approval gates — never for the inline proxy.

---

## 5. Orchestration Options

### 5.1 Bare Podman + Quadlets + Ansible (Default)

For most JA4proxy deployments (< 10 hosts, no existing K8s cluster), this is the
correct answer. Quadlets + Ansible provides:

- Systemd manages process lifecycle (restart, dependencies, ordering)
- Ansible handles multi-host orchestration (rolling restart, health-check gating, LB drain)
- No additional orchestration daemon to operate or maintain
- Full integration with RHEL audit subsystem

This is not a simplification — it is the right tool for the problem. A stateful inline
proxy on a fixed set of RHEL nodes is not a complex orchestration problem.

### 5.2 Ansible Automation Platform (AAP / AWX)

When deployment scale or governance requirements demand it, layer AAP on top of §5.1:

- **Job templates**: one per action — `deploy-proxy`, `deploy-analytics`, `preflight-check`,
  `rollback`, `cert-renew`. Never a single monolithic template with survey flags.
- **Surveys**: cover only `image_tag` and `target_limit`. Keep surveys narrow.
- **Approval gates**: AAP's approval node in a workflow for production promotion.
  Workflow: run `preflight-check` → deploy staging → integration test node →
  manual approval gate (SecOps sign-off) → deploy production.
- **Webhook triggers**: CI launches the staging workflow via AAP API. The production
  workflow is approval-gated and **never** triggered automatically from CI.
- **Credential management**: AAP's native Vault credential type — AAP authenticates to
  Vault, fetches secrets, injects into the job environment. Never logged.

### 5.3 Kubernetes / OpenShift

Use Kubernetes when: your organisation already operates a cluster, has GitOps tooling,
and JA4proxy needs to scale across dozens of nodes.

**Use a DaemonSet topology.** JA4proxy must run on every node that handles traffic —
one pod per node, not a replicated Deployment on arbitrary nodes.

**Use `hostNetwork: true`.** Mandatory for real client IP visibility. With an overlay CNI
(Calico, Cilium, Flannel), the source IP seen by the container is the overlay network IP,
not the client IP. `hostNetwork: true` bypasses the CNI and gives the pod the host's
network namespace — correct behaviour for an inline proxy.

```yaml
spec:
  hostNetwork: true
  dnsPolicy: ClusterFirstWithHostNet
  nodeSelector:
    role: ja4proxy
  containers:
    - name: proxy
      securityContext:
        capabilities:
          add: ["NET_BIND_SERVICE"]
          drop: ["ALL"]
        runAsNonRoot: true
        runAsUser: 9999
        readOnlyRootFilesystem: true
        seccompProfile:
          type: Localhost
          localhostProfile: ja4proxy-proxy.json
```

**TAP mode on Kubernetes** requires `CAP_NET_RAW` for AF_PACKET. On OpenShift, this
requires a custom SCC — the default `restricted-v2` will reject it. Plan for this before
attempting TAP mode on OpenShift.

**eBPF/XDP caution:** Cilium in XDP mode can cause packets to bypass `hostNetwork` pods.
Test carefully and consider disabling XDP acceleration on nodes running JA4proxy.

**OpenShift** is the correct RHEL-native K8s distribution if you are going to use
Kubernetes at all. It ships with Quay integration, SELinux policies that work with
containers, and OpenShift GitOps (ArgoCD) for declarative deployments.

**When bare Podman is better than K8s:** fewer than 10 nodes, no existing cluster,
security-critical path requiring minimal moving parts. Every additional layer between bare
metal and the running process is a layer that can fail, be misconfigured, or add latency.
Do not justify Kubernetes adoption solely for this workload.

### 5.4 HashiCorp Nomad

Legitimate alternative if your organisation already uses HashiCorp tooling (Vault, Consul).
Nomad's `task_driver = "podman"` is production-ready. Consul service mesh provides mTLS
between services without a CNI. For shops not already on HashiCorp, adoption cost is
comparable to Kubernetes with less community investment.

### 5.5 Bare Systemd (Quadlets Only, No Ansible)

For very small deployments (1-3 hosts) with infrequent updates, Quadlets alone with manual
`systemctl` management is viable. This eliminates Ansible as a moving part. Not recommended
beyond 3 hosts — coordinated rolling updates become error-prone manually.

---

## 6. Internal OCI Registry

### 6.1 Recommendation

| Scenario | Registry |
|----------|----------|
| Already on OpenShift or Red Hat subscription | **Red Hat Quay** — native Cosign/Sigstore enforcement, Clair v4 scanning |
| Vendor-neutral, self-hosted | **Harbor** (CNCF graduated) — Trivy scanning, Cosign policy enforcement, OIDC auth |
| Already using JFrog for all artifacts | JFrog Artifactory — acceptable if consolidating artifact management |
| Hosts in AWS | AWS ECR Private — only if all hosts are in AWS; no Cosign enforcement at pull time |

### 6.2 Non-Negotiable Registry Features

| Feature | Why |
|---------|-----|
| Cosign signature verification at pull time | Block unsigned images from reaching hosts |
| CVE block policy | CRITICAL CVE in proxy image = direct attack surface |
| Immutable tags | Tag `1.2.3` must never be overwritten |
| Pull-through cache for upstream images | No direct internet egress from CI |
| Multi-DC replication | Images built in DC-A available in DC-B |
| Robot accounts with per-repo scope | CI push credentials must not have fleet-wide write access |

**Immutable tags are non-negotiable** for inline security infrastructure. A tag rewrite is
indistinguishable from a supply-chain compromise.

### 6.3 Host Pull Policy

`/etc/containers/policy.json` on every RHEL host must enforce signature verification:

```json
{
  "default": [{"type": "reject"}],
  "transports": {
    "docker": {
      "registry.internal.example.com/ja4proxy": [{
        "type": "sigstoreSigned",
        "rekorURL": "https://rekor.sigstore.dev",
        "fulcio": {
          "oidcIssuer": "https://token.actions.githubusercontent.com",
          "subjectEmail": "ja4proxy-ci@your-org.github"
        }
      }]
    }
  }
}
```

Any `podman pull` of a JA4proxy image without a valid Sigstore signature is rejected
before a single byte of the image is written to disk.

---

## 7. Ansible Deployment Architecture

### 7.1 Inventory Design

Use **hybrid inventory**: `inventory/hosts.yml` as the authoritative host list in version
control, with group membership organised across three independent dimensions:

```
inventory/
  hosts.yml           # flat list of all hosts
  group_vars/
    proxy_tier/       # Go proxy container — inline, serial:1 deployments
    analytics_tier/   # Python sidecar — not inline, serial:100% acceptable
    env_prod/
    env_staging/
    env_dev/
    dc_iad/           # datacenter/AZ grouping
    dc_dub/
```

**Never** put proxy and analytics nodes in the same play with the same serial. Use
separate plays in the same playbook:

```yaml
- name: Deploy Go proxy (inline — rolling serial:1)
  hosts: proxy_tier:&env_prod
  serial: 1
  any_errors_fatal: true
  ...

- name: Deploy Python analytics (not inline — parallel)
  hosts: analytics_tier:&env_prod
  serial: "100%"
  ...
```

Host variables carry AZ-specific LB API endpoints so drain/undrain tasks can call the
right LB without conditional logic in the play body.

**Anti-pattern:** a single flat group `ja4proxy_hosts` with environment encoded in a
variable — this makes `--limit env_prod` unsafe because it relies on variable filtering
rather than group membership.

### 7.2 Rolling Deployment Pattern

Use `serial: 1` for the production proxy tier. `serial: "25%"` is appropriate for
staging and analytics tier only.

Rationale: at `serial: "25%"` on an 8-node ring, two hosts are simultaneously drained and
upgrading. On a busy site, 25% capacity loss during the window is measurable. `serial: 1`
is slower but the blast radius of a bad image is a single host.

**Failure handling:** Set `any_errors_fatal: true` at the play level. When host 3 of 8
fails, Ansible halts — it does not silently continue to hosts 4-8. The rollback playbook
(see §8.3) targets the failed host by `--limit`. Do not use `block/rescue` for rollback
logic inside rolling plays — it creates hard-to-reason-about partial states.

### 7.3 Idempotency

Three layers — the playbook must be a no-op on already-up-to-date hosts:

**Image digest comparison:**
```yaml
- name: Get digest of running container
  command: podman inspect --format '{{ "{{" }}.ImageDigest{{ "}}" }}' ja4proxy-proxy
  register: running_digest
  ignore_errors: true

- name: Pull new image
  containers.podman.podman_image:
    name: "{{ ja4proxy_image }}"
  register: pull_result

- name: Restart only if digest changed
  systemd: name=ja4proxy-proxy state=restarted
  when: pull_result.image.Digest != running_digest.stdout
```

Never use image tags as the idempotency key — `latest` is not a version.

**Config checksum:** Use Ansible's `template` module; gate the `systemd reload` task on
`config_template.changed`. Store checksum in `/etc/ja4proxy/.config_checksum` for
`--check` mode accuracy.

**Systemd state:** use `state=started enabled=yes` not `state=restarted`. The former is
idempotent; the latter restarts on every play run, causing unnecessary drain/undrain cycles.

### 7.4 Post-Deploy Verification (in `post_tasks`)

Run before undrain, with `any_errors_fatal: true`:

```yaml
post_tasks:
  - name: Wait for health endpoint
    uri:
      url: http://127.0.0.1:8080/health
      status_code: 200
    retries: 12
    delay: 5

  - name: Check readiness endpoint (Phase 41)
    uri:
      url: http://127.0.0.1:8080/ready
      status_code: 200
    retries: 6
    delay: 5

  - name: Verify Prometheus metrics present
    uri:
      url: http://127.0.0.1:9090/metrics
      return_content: true
    register: metrics_page
    failed_when: >
      'ja4proxy_active_connections' not in metrics_page.content or
      'ja4proxy_dial_setting' not in metrics_page.content

  - name: Verify startup log event
    command: >
      journalctl -u ja4proxy-proxy.service --since "2 minutes ago" --no-pager
    register: journal_output
    failed_when: '"event":"startup_complete"' not in journal_output.stdout

  - name: Synthetic TLS connection test
    command: >
      openssl s_client -connect 127.0.0.1:8080 -brief </dev/null
    register: tls_test
    failed_when: tls_test.rc != 0
```

### 7.5 Config Drift Detection

Run `ansible-playbook --check` on a schedule (every 4 hours) against all tiers. A
non-zero changed count triggers a monitoring alert. Define a remediation SLA: 24 hours
for proxy tier config drift, 72 hours for analytics tier.

**Do not introduce Puppet or Chef alongside Ansible.** Two configuration management
systems on the same host create conflict over file ownership and service restart authority.
If the organisation already runs Puppet/Chef fleet-wide, integrate JA4proxy into that
system and use Ansible only for the deployment ceremony (drain/undrain, ordered restart).
Define the boundary explicitly and document it in the runbook.

---

## 8. Pre-Deployment Preflight Checks

Run as a dedicated `preflight.yml` play before any deployment task. Hard-fail conditions
abort the entire run. Soft-fail conditions skip the individual host with an alert.

### 8.1 Disk Space

| Path | Minimum Free | Action if Fails |
|------|-------------|-----------------|
| `/var/lib/containers` | 4 GB | **Abort entire run** — partial image pull corrupts the layer cache |
| `/etc/ja4proxy` | 50 MB | Abort entire run |
| `/var/log` | 500 MB | Abort entire run |

```yaml
- name: Assert container storage headroom
  assert:
    that: >
      (ansible_mounts
       | selectattr('mount', 'equalto', '/var/lib/containers')
       | map(attribute='size_available')
       | first) > 4294967296
    fail_msg: "Insufficient disk on {{ inventory_hostname }}: /var/lib/containers needs 4GB free"
```

### 8.2 Memory

Assert `ansible_memfree_mb >= 512`. Additionally, check if the running container's
cgroup `memory.usage_in_bytes` is within 20% of its configured limit — a near-OOM
container will likely OOM-kill during the brief window where both old and new containers
exist. If near-OOM: skip this host, page oncall, do not continue.

### 8.3 CPU

Reject deployment on any host where the 5-minute load average exceeds `2 × CPU count`
(`ansible_processor_vcpus`). A deployment under sustained load risks missed health-check
timeouts causing false rollbacks.

### 8.4 Network Connectivity

Check all before pulling the image — discovering a connectivity failure mid-pull wastes
drain time:

```yaml
- name: OCI registry reachable
  uri:
    url: "https://{{ oci_registry }}/v2/"
    status_code: [200, 401]   # 401 = auth required = registry is alive
    timeout: 10

- name: Redis cluster reachable
  wait_for:
    host: "{{ redis_host }}"
    port: 6379
    timeout: 5

- name: LB API reachable
  uri:
    url: "{{ lb_api_health_url }}"
    timeout: 10
```

### 8.5 System State Checks

| Check | Minimum | Action |
|-------|---------|--------|
| Podman version | ≥ 4.4.0 | Hard-abort this host |
| SELinux mode | Enforcing | Hard-abort — never deploy to an unconfined host |
| RHEL subscription | `subscription-manager status` exit=0 | Warn; abort if strict mode |
| Existing service health | `/health` returns 200 | Abort this host + alert — do not upgrade a broken node |
| `nf_conntrack` module | `modinfo nf_conntrack` exits 0 | Hard-abort |
| firewalld ports open | 8080/tcp, 9090/tcp | Hard-abort |

### 8.6 Image Signature Pre-Verification

Verify the Cosign signature before committing to the deployment run:

```bash
cosign verify \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  {{ image_ref }}
```

A signature failure is a supply chain event, not a configuration error. Abort the entire
run and page the security team.

---

## 9. Rolling Deployment and Canary-First Pattern

### 9.1 Canary-First Gate

The inventory must define a `canary` group (single host, ideally a lower-traffic node in
the LB pool) and a `fleet` group (remaining hosts). The deployment has a hard dependency:

```
canary play → 5-minute observation window → automated gate → fleet play
```

The automated gate evaluates all of these (all must pass):

- `GET /health` returns 200 for 60 consecutive seconds
- `ja4proxy_request_duration_seconds{quantile="0.99"}` within 20% of pre-deploy baseline
- `ja4proxy_errors_total` rate ≤ 0.1% over the 5-minute window
- `ja4proxy_active_connections` gauge is non-zero (traffic is actually flowing)
- JA4 fingerprint cardinality has not dropped > 10% (a silent traffic-drop signal)

If any check fails: automatic rollback of the canary host, abort fleet deployment,
page oncall with the specific failing metric name in the alert body.

### 9.2 LB Drain/Undrain Integration

Implement a single `lb_drain.yml` role with a `provider` variable. All four major LB
types are supported:

**F5 iControl REST:**
```yaml
- uri:
    url: "https://{{ lb_host }}/mgmt/tm/ltm/pool/~Common~ja4proxy_pool/members/~Common~{{ host }}:8080"
    method: PATCH
    body: '{"session": "user-disabled"}'
    headers:
      X-F5-Auth-Token: "{{ f5_token }}"
- uri:
    url: "https://{{ lb_host }}/mgmt/tm/ltm/pool/~Common~ja4proxy_pool/members/~Common~{{ host }}:8080"
    return_content: true
    headers:
      X-F5-Auth-Token: "{{ f5_token }}"
  register: f5_status
  until: f5_status.json.monitorStatus == "unchecked"
  retries: 60
  delay: 5
```

**HAProxy stats socket** (fastest, ~100ms):
```yaml
- command: >
    echo "disable server ja4proxy_backend/{{ inventory_hostname }}" |
    socat stdio /run/haproxy/admin.sock
```

**AWS ALB** (note: override deregistration delay to 30s in Terraform, not the default 300s):
```yaml
- command: >
    aws elbv2 deregister-targets
    --target-group-arn {{ alb_tg_arn }}
    --targets Id={{ host_ip }},Port=8080
- command: >
    aws elbv2 describe-target-health
    --target-group-arn {{ alb_tg_arn }}
  register: target_health
  until: target_health.stdout | from_json | json_query('TargetHealthDescriptions[?TargetHealth.State==`unused`]') | length > 0
  retries: 60
  delay: 5
```

**NGINX Plus API:**
```yaml
- uri:
    url: "http://{{ nginx_host }}/api/9/http/upstreams/ja4proxy/servers/{{ server_id }}"
    method: DELETE
    headers:
      Authorization: "Bearer {{ nginx_api_token }}"
```

Note: NGINX Plus upstream must be in a `zone` (shared memory zone) for API management.
Fail fast if the upstream is static — API management is impossible on static upstreams.

---

## 10. Rollback Strategy

### 10.1 Image Pinning (Mandatory)

Before every upgrade, tag the current image:

```bash
podman tag ja4proxy:current ja4proxy:previous
```

This tag is **never** removed by automated prune jobs. Enforce in all `podman image prune`
invocations:

```bash
podman image prune \
  --filter "until=168h" \
  --filter "reference!=ja4proxy:current" \
  --filter "reference!=ja4proxy:previous"
```

Never run `podman system prune -a` in automation — it deletes the rollback image.

### 10.2 Rollback Playbook

A separate `rollback.yml` that accepts `--limit hostname` for surgical single-host rollback:

1. Drain the host from the LB (same role as forward deployment)
2. `systemctl stop ja4proxy-proxy.service`
3. `podman tag ja4proxy:previous ja4proxy:current`
4. Regenerate the Quadlet unit from the previous tag
5. `systemctl start ja4proxy-proxy.service`
6. Run full health gate (same criteria as canary gate)
7. Undrain from LB only if health gate passes

**RTO target: < 60 seconds.** With HAProxy stats socket and a 5-second drain, end-to-end
rollback completes in 15-20 seconds. With AWS ALB at the default 300-second deregistration
delay you will miss this target — mandate 30s in Terraform.

### 10.3 Configuration Rollback

Config changes are separate from image changes (see §11). Config rollback is:
`git revert` the config commit → re-run the config playbook → `SIGHUP` is sent →
proxy hot-reloads without restart or drain.

---

## 11. Configuration Management Safety

### 11.1 Strict Pipeline Separation

Config changes and image changes are **separate pipelines**. Never combine them in a
single deployment run. Mixed changes make incident diagnosis nearly impossible.

| Change type | Pipeline | LB drain needed? | Approval gate? |
|-------------|----------|-----------------|----------------|
| Image version bump | `deploy.yml` | Yes | Yes (prod) |
| Config change | `config.yml` | No — SIGHUP only | No (staging), Yes (prod for security_policy changes) |
| TLS cert rotation | `cert-renew.yml` | No — inotify watch | No |

### 11.2 Config Validation Before Apply

Run `--validate-config` inside a throwaway container **before** writing new config:

```bash
podman run --rm \
  -v /tmp/new-proxy.yml:/config/proxy.yml:ro \
  ja4proxy:current --validate-config /config/proxy.yml
```

Exit code non-zero = abort, do not write to disk, do not send SIGHUP.

### 11.3 Cross-Host Config Sync Detection

After SIGHUP, each host writes its loaded config checksum to Redis key
`config:checksum:{hostname}`. A monitoring job polls all `config:checksum:*` keys every
60 seconds and alerts if any host diverges from the fleet-wide expected checksum. This
catches silent SIGHUP failures (config rejected at runtime despite passing validate).

---

## 12. Deployer Experience

### 12.1 Single Makefile Entry Point

```makefile
## ── Deployment targets ──────────────────────────────────────────────────────

deploy:                     ## Deploy to ENV (required). Usage: make deploy ENV=prod VERSION=v1.2.3 TICKET=CHG0001234
	@test -n "$(ENV)"    || (echo "ENV is required"; exit 1)
	@test -n "$(VERSION)" || (echo "VERSION is required"; exit 1)
	@test -n "$(TICKET)" || (echo "TICKET is required (change management ref)"; exit 1)
	ansible-playbook -i inventories/$(ENV) deploy.yml \
	  -e version=$(VERSION) \
	  -e itsm_ticket=$(TICKET)

deploy-check:               ## Dry-run: preflight + --check --diff without changing anything
	@test -n "$(ENV)" || (echo "ENV is required"; exit 1)
	ansible-playbook -i inventories/$(ENV) deploy.yml \
	  -e version=$(VERSION) --check --diff

rollback:                   ## Rollback a single host. Usage: make rollback ENV=prod HOST=ja4proxy-prod-03
	@test -n "$(HOST)" || (echo "HOST is required"; exit 1)
	ansible-playbook -i inventories/$(ENV) rollback.yml --limit $(HOST)

preflight:                  ## Run preflight checks only (no changes)
	ansible-playbook -i inventories/$(ENV) preflight.yml
```

### 12.2 Deployment Manifest

`deploy/manifest.yml` checked into git is the version-of-record:

```yaml
# deploy/manifest.yml
version: v1.2.3
environments:
  prod:
    image: registry.internal.example.com/ja4proxy/go-proxy:v1.2.3
    canary_host: ja4proxy-prod-01
    maintenance_window: "Sat 02:00-06:00 UTC"
    lb_provider: f5
  staging:
    image: registry.internal.example.com/ja4proxy/go-proxy:v1.2.3
    canary_host: ja4proxy-staging-01
    maintenance_window: "*"
    lb_provider: haproxy
```

### 12.3 Approval Workflow

Production deployments require an AWX/AAP workflow with a manual approval node between
the canary play and the fleet play. The approval gate records the approver's username and
ITSM ticket in job extra vars — this is the audit trail.

The playbook enforces change ticket presence:

```yaml
- name: Enforce change ticket reference
  assert:
    that:
      - itsm_ticket is defined
      - itsm_ticket | regex_search('^CHG[0-9]{7}$')
    fail_msg: "Production deployment requires a valid change ticket (format: CHG0000000)"

- name: Log deployment to ITSM
  uri:
    url: "https://itsm.example.com/api/deployments"
    method: POST
    body_format: json
    body:
      ticket: "{{ itsm_ticket }}"
      host: "{{ inventory_hostname }}"
      image: "{{ ja4proxy_image_tag }}"
      deployer: "{{ lookup('env','USER') }}"
      timestamp: "{{ ansible_date_time.iso8601 }}"
    headers:
      Authorization: "Bearer {{ itsm_api_token }}"
```

---

## 13. Observability During Deployment

### 13.1 Deployment Event Metric

Emit a `ja4proxy_deployment_info` gauge (value=1) with labels:

```
ja4proxy_deployment_info{version="v1.2.3", host="ja4proxy-prod-03",
                          deployer="jsmith", itsm_ticket="CHG0001234",
                          environment="prod"} 1
```

This persists in Prometheus and makes it trivial to correlate a latency regression with
the exact deployment event on the exact host.

### 13.2 Change Window Enforcement

The playbook checks current UTC time against `maintenance_window` in `deploy/manifest.yml`.
If outside the window, the playbook pauses and requires `--extra-vars force_outside_window=true`.
This generates a Datadog/Splunk event tagged `change_risk:high` that auto-resolves on
successful completion within 15 minutes.

### 13.3 Deployment Duration SLO

Post-deployment task records start/end timestamps. Alerts:
- > 600 seconds: low-urgency alert — deployment stalling
- > 1200 seconds: high-urgency — probable stall with LB in inconsistent drain state → incident

---

## 14. Day-2 Operations Reliability

### 14.1 Systemd Watchdog

The proxy process must call `sd_notify("WATCHDOG=1\n")` every ≤ 15 seconds on the hot
path. If it does not (deadlock, hung goroutine), systemd kills and restarts it. The
`WatchdogSec=30` in the Quadlet unit file enables this. `StartLimitBurst=3` stops
thrashing after 3 rapid crashes — after that systemd stops trying and oncall is paged
by the monitoring stack.

### 14.2 Disk Hygiene

- Alert at 80% `/var/lib/containers` utilisation (Prometheus `node_filesystem_avail_bytes` rule).
- Automated weekly prune (systemd timer, not cron):
  ```bash
  podman image prune --filter "until=168h" \
    --filter "reference!=ja4proxy:current" \
    --filter "reference!=ja4proxy:previous"
  ```
- journald cap (`/etc/systemd/journald.conf.d/ja4proxy.conf`):
  ```ini
  SystemMaxUse=2G
  MaxRetentionSec=30day
  ```
  Without this, a chatty proxy under attack conditions will fill `/var/log/journal`
  and take down the host.

---

## 15. Security Hardening

### 15.1 FIPS 140-2/3 Compliance

**Enable FIPS at the host level, not inside containers.** The FIPS policy propagates into
containers automatically through the shared kernel:

```bash
fips-mode-setup --enable && reboot
# Verify: cat /proc/sys/crypto/fips_enabled  # must be "1"
```

**Go binary FIPS (boringcrypto):**

The standard Go crypto library is not FIPS-validated. Use `GOEXPERIMENT=boringcrypto`
and `CGO_ENABLED=1` to link against BoringSSL-backed implementations (FIPS 140-2 cert
#3678). The current `Dockerfile.go-proxy` uses `CGO_ENABLED=0` — this silently falls
back to non-FIPS crypto. Verify at runtime:

```bash
go tool nm /usr/local/bin/ja4proxy | grep -i boring
# Must print boring symbols; absence means non-FIPS build
```

**Python FIPS:**
`python:3.14.0-slim` (Debian) does not use the RHEL FIPS provider. Migrate to
`registry.access.redhat.com/ubi9/python-312` pending UBI9 Python 3.14 availability.
Audit for `hashlib.md5()` use anywhere in analytics code — MD5 is not FIPS-approved.

**Redis TLS ciphers** — remove `ChaCha20-Poly1305` (not FIPS 140-3 approved):
```
tls-ciphersuites "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
```

**JA4 fingerprinting:** No FIPS issue — JA4 uses SHA-256, which is FIPS-approved.

### 15.2 SELinux

SELinux must remain `Enforcing`. Never use `--privileged`.

- All config volumes mounted with the `:z` or `:Z` label option (relabels to `container_file_t`).
- Run containers with explicit SELinux type: `--security-opt label=type:container_t`
- For TAP mode (requires `CAP_NET_RAW`), use the targeted boolean:
  ```bash
  setsebool -P container_use_raw_sockets 1
  ```

### 15.3 Rootless Podman Under a Dedicated System User

```bash
useradd --system --uid 9999 --no-create-home \
        --shell /sbin/nologin \
        --comment "JA4proxy service account" \
        --password '!' \
        ja4proxy
loginctl enable-linger ja4proxy
```

The proxy container needs to bind port 8080 (not port 443 directly). Keep JA4proxy on
port 8080 behind HAProxy (which binds :443 as root or via `CAP_NET_BIND_SERVICE`) — this
is the prescribed topology and it keeps the proxy container rootless.

The analytics container does not need host network. Give it a dedicated Podman network:

```bash
podman network create ja4proxy-internal --internal
```

### 15.4 Seccomp

Two profiles are required:

- `config/seccomp_proxy.json` — proxy container: no `AF_PACKET` socket domain, no `setuid`/`setgid`.
- `config/seccomp_tap.json` — TAP container only: includes `AF_PACKET`.

Reference in Ansible container deployment:

```yaml
security_opts:
  - "no-new-privileges:true"
  - "seccomp=/etc/ja4proxy/seccomp_proxy.json"
```

### 15.5 Read-Only Filesystem

The existing Ansible role sets `read_only: true`. Ensure explicit tmpfs mounts are scoped:

```yaml
tmpfs:
  /tmp: "size=64m,noexec,nosuid,nodev,mode=1777"
  /run: "size=16m,noexec,nosuid,nodev"
```

Logs flow to stdout → journald → log shipper. No writable log volume is ever mounted
into the proxy container.

---

## 16. Enterprise Secrets Manager Integration

JA4proxy requires the following secrets at runtime: Redis password, Redis mTLS client
certificate + key, AbuseIPDB API key, RDAP service tokens. None of these may appear in
Ansible vars files, git repositories, or be visible via `podman inspect`.

### 16.1 Platform Selection

Use this matrix to choose the right platform. Multiple systems can co-exist at different
layers (see §16.8 for dual-platform boundaries).

| Platform | RHEL/Podman fit | Ansible quality | Rotation w/o restart | FIPS | SOC audit | Best for |
|----------|----------------|-----------------|----------------------|------|-----------|---------|
| **HashiCorp Vault** | ★★★★★ | ★★★★★ | Yes (Agent+SIGHUP) | Yes (Enterprise+HSM) | ★★★★★ | On-prem or multi-cloud, DevSecOps-mature |
| **CyberArk AAM/CCP + Conjur** | ★★★★☆ | ★★★★☆ | Yes (Conjur+SIGHUP) | Yes | ★★★★★ | Enterprise mandating CyberArk PAM |
| **Azure Key Vault** | ★★★☆☆ (Azure VMs) / ★★☆☆☆ (on-prem) | ★★★★☆ | Partial (Event Grid) | Yes (Gov cloud) | ★★★★☆ | Azure-native infrastructure |
| **AWS Secrets Manager** | ★★★☆☆ (EC2) / ★★☆☆☆ (on-prem) | ★★★★☆ | Yes (Lambda rotation) | Yes (GovCloud) | ★★★★☆ | AWS-native infrastructure |
| **Delinea DSV** | ★★☆☆☆ | ★★☆☆☆ | Partial | Partial | ★★★☆☆ | Orgs mandating Delinea; use DSV not Secret Server |
| **BeyondTrust Password Safe** | ★★☆☆☆ | ★☆☆☆☆ | No (checkout model) | Partial | ★★★☆☆ | Wrong tool — see §16.6 |
| **1Password Secrets Automation** | ★☆☆☆☆ | ★★☆☆☆ | Partial | No | ★★☆☆☆ | Wrong tool for STIG/CIS infrastructure |
| **systemd-creds (RHEL-native)** | ★★★★★ | N/A | Yes (SIGHUP) | Yes (kernel) | ★★★☆☆ | Air-gapped; no external vault available |

**Default recommendation:** HashiCorp Vault for any on-prem or multi-cloud deployment.
Azure Key Vault if hosts are Azure VMs and your org is EntraID-native. AWS Secrets Manager
if hosts are EC2 instances. CyberArk if enterprise PAM policy mandates it.

### 16.2 HashiCorp Vault

#### 16.2.1 Authentication — AppRole vs JWT/OIDC

**AppRole** (classic CI pattern): pre-create a role with a `role_id` (non-secret, can be
in inventory) and a wrapped `secret_id` (rotated per pipeline run via response-wrapping).
Use when Ansible runs from traditional CI (Jenkins, GitLab Runner) without OIDC federation.

**JWT/OIDC** (modern AAP pattern): AWX issues a short-lived JWT bound to the job execution
context; Vault validates the signature and grants a token. No `secret_id` to bootstrap.
Use when AAP/AWX is the control plane and is configured as an OIDC provider.

Decision rule: fewer than 50 managed hosts or no AAP → AppRole. Large org with AAP at
the centre → JWT/OIDC, eliminating the `secret_id` bootstrap problem entirely.

#### 16.2.2 Vault Agent on RHEL — The Production Pattern

Vault Agent runs as a systemd unit on each proxy host. It authenticates once, caches the
token, renders secrets via Go templates, and sends SIGHUP when secrets change. It is not
inside any container — it writes to a tmpfs directory that the Quadlet reads.

```
/run/vault-agent/              (tmpfs, mode 0750, vault-agent:ja4proxy)
├── ja4proxy.env               (mode 0640 — EnvironmentFile for Quadlet)
├── token                      (mode 0600 — Vault token cache)
└── tls/
    ├── redis-client.crt       (mode 0640)
    └── redis-client.key       (mode 0640)
```

`/etc/vault-agent/config.hcl` (key sections):

```hcl
auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = "/etc/vault-agent/role_id"
      secret_id_file_path = "/etc/vault-agent/secret_id"
    }
  }
  sink "file" {
    config = { path = "/run/vault-agent/token" }
  }
}

template {
  source      = "/etc/vault-agent/templates/proxy-env.ctmpl"
  destination = "/run/vault-agent/ja4proxy.env"
  perms       = "0640"
  # Trigger SIGHUP on the proxy whenever this file is re-rendered:
  command     = "systemctl kill --signal=SIGHUP ja4proxy-proxy.service"
}

template {
  source      = "/etc/vault-agent/templates/redis-client.crt.ctmpl"
  destination = "/run/vault-agent/tls/redis-client.crt"
  perms       = "0640"
  command     = "systemctl kill --signal=SIGHUP ja4proxy-proxy.service"
}
```

Template `proxy-env.ctmpl`:

```
{{- with secret "secret/ja4proxy/production" -}}
REDIS_PASSWORD={{ .Data.data.redis_password }}
ABUSEIPDB_API_KEY={{ .Data.data.abuseipdb_api_key }}
RDAP_TOKEN={{ .Data.data.rdap_token }}
{{- end -}}
```

The Quadlet unit wires it together:

```ini
[Unit]
After=vault-agent.service
Requires=vault-agent.service

[Container]
EnvironmentFile=/run/vault-agent/ja4proxy.env
Volume=/run/vault-agent/tls:/app/tls:ro,Z

[Service]
ExecReload=/bin/kill -HUP $MAINPID
```

`podman inspect ja4proxy-proxy` shows the `EnvironmentFile` path but never the values.
Verify with `podman inspect ja4proxy-proxy | python3 -m json.tool | grep REDIS_PASSWORD`
— must return empty.

#### 16.2.3 Dynamic Redis Credentials (Database Secrets Engine)

Per-instance, time-bounded Redis ACL users via Vault's database secrets engine:

```bash
vault write database/roles/ja4proxy-proxy \
    db_name=ja4proxy-redis \
    creation_statements='["SET","{{username}}","{{password}}","~ja4:*","+@read","+@write","+ping"]' \
    default_ttl=1h \
    max_ttl=24h
```

Vault Agent automatically renews the lease before expiry and re-renders the template,
triggering SIGHUP. **This requires extending the SIGHUP handler in `src/config/loader.py`
to call `_reinit_redis()` — the hook exists, only the Redis pool reinitialisation is
missing.**

#### 16.2.4 PKI Secrets Engine for TLS Certificates

90-day Redis client/server certs with automatic renewal via Vault Agent templates:

```bash
vault write pki_int/roles/ja4proxy-redis \
    allowed_domains="redis.dmz.corp.internal" \
    allow_subdomains=true \
    max_ttl=2160h \
    key_type=rsa \
    key_bits=4096
```

Template issues a new cert as expiry approaches — Vault Agent detects TTL and re-renders,
triggering the proxy's FSNotify cert-reload path (Phase 42).

#### 16.2.5 Namespace Strategy

Use **separate Vault namespaces per environment** (`vault/dev`, `vault/staging`,
`vault/prod`), not separate KV mount paths within one namespace. Namespaces provide
administrative isolation — a compromised staging token cannot traverse namespace
boundaries. Policy misconfiguration within one namespace cannot grant cross-namespace
access. For community Vault (no namespaces), use separate Vault clusters per environment.

#### 16.2.6 Audit Device

```bash
vault audit enable file file_path=/var/log/vault/audit.log
```

Every secret read is a structured JSON line. Token and secret values are always
HMAC-hashed in the audit log — the SOC sees who read what and when, but cannot
reconstruct the credential value from the log.

### 16.3 CyberArk (AAM/CCP + Conjur)

#### 16.3.1 Product Selection

| Product | Use case for JA4proxy |
|---------|----------------------|
| CyberArk PAM (EPV/Digital Vault) | Human privileged access, break-glass, SSH keys — NOT for direct application integration |
| CyberArk AAM/CCP | Ansible deployment-time credential fetch — the correct integration surface |
| CyberArk Conjur Enterprise | Container runtime secret refresh, JWT workload identity for AAP/AWX |
| CyberArk Conjur Cloud | SaaS Conjur — for greenfield cloud; use on-premises Conjur for air-gapped RHEL |

Do not integrate JA4proxy directly against the PAM vault API. CCP is the correct
application-facing layer.

#### 16.3.2 Ansible + CCP Integration

CCP exposes a REST endpoint; the caller presents a client certificate (preferred) or
AppID to prove identity — no password required.

```yaml
# Certificate-based auth (preferred over AppID-only)
- name: Fetch Redis password from CyberArk CCP
  cyberark.pas.cyberark_credential:
    api_base_url: "{{ cyberark_ccp_url }}"
    app_id: "{{ cyberark_app_id }}"
    safe: "JA4proxy-Production"
    object: "JA4proxy-Redis-Password"
    client_cert: "/etc/ansible/certs/ansible-deployer.pem"
    client_key: "/etc/ansible/certs/ansible-deployer-key.pem"
    validate_certs: true
  register: _redis_cred
  no_log: true
  delegate_to: localhost   # CCP call from control node, not the target host

- name: Write EnvironmentFile (tmpfs, mode 0600)
  ansible.builtin.template:
    src: secrets.env.j2
    dest: /run/ja4proxy/secrets.env
    owner: ja4proxy
    group: ja4proxy
    mode: "0600"
  no_log: true
  vars:
    redis_password: "{{ _redis_cred.result.Content }}"
```

Every CCP fetch is audited in PAM's Audit Log: AppID, Safe, Object, source IP, timestamp,
result. The SOC sees: `AppID=ja4proxy-ansible-deployer fetched JA4proxy-Redis-Password
from Safe=JA4proxy-Production at 2026-04-04T14:23Z from 10.1.2.3`. Baseline high-frequency
expected fetches to prevent false-positive alerts.

#### 16.3.3 Conjur for Container Runtime Secret Refresh

Conjur supports JWT workload identity for AAP/AWX — AWX presents a job-scoped JWT,
Conjur validates the signature, no pre-shared secret required.

Policy YAML (checked into a policy git repo, not Ansible inventory):

```yaml
- !policy
  id: ja4proxy
  body:
    - !group deployers
    - &secrets
      - !variable redis/password
      - !variable abuseipdb/api-key
      - !variable tls/redis-client-cert
    - !permit
      role: !group deployers
      privileges: [read, execute]
      resources: *secrets
```

For live container secret refresh, Conjur + SIGHUP mirrors the Vault Agent pattern:
a Conjur agent (or scheduled systemd timer calling `conjur variable get`) writes updated
secrets to `/run/ja4proxy/` and sends SIGHUP. The Conjur Enterprise webhook can trigger
this automatically when CyberArk CPM rotates the Redis password.

#### 16.3.4 CyberArk Secretless Broker for Redis

The Secretless Broker is the highest-security pattern — the proxy binary never holds the
Redis password at all. The broker runs as a Podman pod sidecar, listens on
`127.0.0.1:6380`, intercepts Redis connections, fetches the credential from Conjur, and
authenticates on behalf of the proxy. JA4proxy's Redis URL becomes `redis://127.0.0.1:6380`
with no password.

```ini
# /etc/containers/systemd/ja4proxy-secretless.container
[Unit]
Requires=ja4proxy-proxy.service

[Container]
Image=cyberark/secretless-broker:latest
Network=host
Volume=/etc/ja4proxy/secretless.yml:/etc/secretless.yml:ro,Z
```

`secretless.yml`:
```yaml
services:
  - name: redis-ja4proxy
    protocol: redis
    listenOn: tcp://127.0.0.1:6380
    credentials:
      - name: password
        from: conjur
        get: ja4proxy/redis/password
```

Recommended for deployments where credential exfiltration via memory dump is a threat
model concern.

### 16.4 Azure Key Vault

Use when hosts are Azure VMs (Managed Identity — zero credential management) or on-prem
with Azure Arc (Arc-issued managed identity token). For on-prem RHEL without Azure Arc,
Azure Key Vault adds complexity without commensurate benefit — use Vault instead.

```yaml
- name: Fetch Redis password from Azure Key Vault
  azure.azcollection.azure_rm_keyvaultsecret_info:
    vault_uri: "https://ja4proxy-prod.vault.azure.net/"
    name: redis-proxy-password
  register: kv_secret
  no_log: true

- name: Write EnvironmentFile to tmpfs
  ansible.builtin.copy:
    content: "REDIS_PASSWORD={{ kv_secret.secrets[0].secret_value }}\n"
    dest: /run/ja4proxy/secrets.env
    owner: ja4proxy
    mode: "0600"
  no_log: true
```

**Certificate rotation:** Key Vault emits a `Microsoft.KeyVault.CertificateNearExpiry`
event 30 days before expiry. Wire to an Azure Logic App/Function → AAP webhook → cert
renewal playbook. More plumbing than Vault's PKI engine; acceptable if Azure is your
primary secrets plane.

**There is no first-party Vault Agent equivalent for non-Azure RHEL hosts.** For on-prem
RHEL with Azure Key Vault, you must write a custom systemd oneshot + timer that calls the
Azure Key Vault SDK and writes to tmpfs. This is significant custom work — use Vault
instead unless Azure Key Vault is mandated.

### 16.5 AWS Secrets Manager

Use when hosts are EC2 instances (IAM instance profile — zero credential management).
For on-prem RHEL, use STS AssumeRole; require IMDSv2 (`ec2:MetadataHttpTokens=required`)
to prevent SSRF credential theft.

```yaml
- name: Fetch Redis password from Secrets Manager
  amazon.aws.aws_secret:
    name: "ja4proxy/production/redis-proxy-password"
    region: eu-west-1
  register: redis_secret
  no_log: true
```

**Rotation Lambda pattern:** AWS manages rotation via a Lambda function. For Redis, Lambda
calls `ACL SETUSER` with the new password while the old one remains valid (Redis 6+ ACL
supports two passwords per user), verifies connectivity, then revokes the old password.
The proxy handles the brief dual-credential window via Redis auth retry with backoff.

**Secrets Manager vs Parameter Store:**

| Secret type | Service | Reason |
|-------------|---------|--------|
| Redis password | Secrets Manager | Native rotation, versioning |
| AbuseIPDB API key | Parameter Store SecureString | No rotation needed; ~10× cheaper |
| RDAP tokens | Parameter Store SecureString | Low-churn config |
| TLS private keys | Secrets Manager | Rotation support required |

### 16.6 Delinea and BeyondTrust — Checkout Model Problem

Both Delinea Secret Server and BeyondTrust Password Safe use a human-oriented
Request → Approve → Check-Out → Use → Check-In model. **This model is architecturally
wrong for JA4proxy.** A persistent service cannot hold an exclusive checkout; multiple
instances cannot share a checked-out credential; automated deployment cannot wait for
human approval on each credential fetch.

**Delinea DSV** (DevOps Secrets Vault, distinct from Secret Server) avoids the checkout
model and is the correct Delinea product for this use case. REST-native, machine auth via
client credentials, no checkout required. Acceptable if Delinea is mandated by security
policy. Still inferior to Vault for RHEL/Podman integration depth.

**BeyondTrust Password Safe** — use the "API Registration" credential type to bypass the
approval workflow for the JA4proxy service account. Even then, rotation requires a
scheduled Ansible playbook rather than automatic TTL-based rotation. BeyondTrust is
genuinely excellent for human privileged access (jump sessions, session recording). Its
machine-to-machine API is functional but retrofitted. Use it only if enterprise policy
mandates it; escalate to Delinea DSV or Vault if there is a choice.

**1Password Secrets Automation** is the wrong tool for CIS/STIG-hardened RHEL
infrastructure. No FIPS-validated crypto module, no SOC-grade audit log integration,
no RHEL-native integration path. Appropriate for developer workstations and product
engineering CI — not for production security proxy infrastructure.

### 16.7 Universal Patterns (Platform-Agnostic)

These apply regardless of which platform is chosen.

#### The Write-to-File + SIGHUP Pattern

The canonical pattern for all platforms: a secrets agent writes rendered secrets to
a tmpfs file and signals the proxy to reload.

Quadlet `.service` override:
```ini
[Service]
ExecReload=/bin/kill -HUP $MAINPID
```

Go proxy SIGHUP handler (extend existing `src/config/loader.py` equivalent in Go):
```go
sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, syscall.SIGHUP)
go func() {
    for range sigCh {
        if err := cfg.Reload(); err != nil {
            log.Warn("config reload failed", "err", err)
            continue
        }
        redisPool.Reinit(cfg.Redis)  // re-connect with new credentials
    }
}()
```

#### EnvironmentFile, Not Inline Environment Variables

```ini
# Correct — values not visible in podman inspect:
EnvironmentFile=/run/ja4proxy/secrets.env

# Wrong — visible in podman inspect and process table:
Environment=REDIS_PASSWORD=s3cr3t
```

Verify: `podman inspect ja4proxy-proxy | python3 -m json.tool | grep REDIS_PASSWORD`
must return empty.

#### Secrets in tmpfs Only

`/run/` is a tmpfs on RHEL 8/9 — never written to disk, cleared on reboot.

```
/run/ja4proxy/               (tmpfs, RuntimeDirectory=ja4proxy, mode 0750)
├── secrets.env              (mode 0640 — EnvironmentFile target)
└── tls/
    ├── redis-client.crt     (mode 0640)
    └── redis-client.key     (mode 0640)
```

Enforce in Quadlet:
```ini
[Service]
RuntimeDirectory=ja4proxy
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=no    # cleared on service stop — important
```

Never write secret material to `/etc/ja4proxy/` or any persistent filesystem path.
Config files that reference secrets (`password: "${REDIS_PASSWORD}"`) belong in `/etc/`
— the interpolation happens at process start from the EnvironmentFile on tmpfs.

#### What Must Never Appear in Git

Enforce with a pre-commit hook:

```yaml
# .pre-commit-config.yaml
- repo: https://github.com/gitleaks/gitleaks
  hooks:
  - id: gitleaks
    args: ['--config=.gitleaks.toml']
```

Blocklist: Redis password, TLS private keys (`*.key`, `*.pem`, `*.p12`), AbuseIPDB API
key, RDAP tokens, Vault AppRole secret IDs, LUKS passphrase.

Verify history is clean: `git log --all --full-history -- vault.yml`

### 16.8 Dual-Platform Boundary (CyberArk + Vault)

Many enterprises have both CyberArk PAM (for privileged human access) and HashiCorp Vault
(for application secrets). The correct functional boundary:

| Secret type | Owner | Rationale |
|-------------|-------|-----------|
| Human privileged credentials, SSH keys | CyberArk PAM | Session recording, dual-control, compliance |
| Service account AD/LDAP passwords | CyberArk PAM | CPM auto-rotation, compliance |
| Ansible deployer client certificate | CyberArk PAM | Machine identity for CI/CD |
| Application runtime secrets (Redis, API keys) | HashiCorp Vault or Conjur | Dynamic TTL, lease-based, dev workflow |
| TLS certificates for services | Vault PKI or CyberArk CertManager | Depends on existing PKI investment |

Do not bridge them for the same secret. Vault's CyberArk secrets engine (Vault proxying
to CCP) adds a hop without adding security. Choose one system per secret type and own it.

**Rule for JA4proxy:** CyberArk PAM for *identity and access* (who deploys, who breaks
glass). Vault/Conjur for *runtime application secrets* (what the running container knows).

### 16.9 Minimum Viable Isolation (No Enterprise Vault)

If none of the above platforms are available, these baseline controls are mandatory:

1. **systemd-creds** (RHEL 9.3+): host-bound encryption, TPM-backed, secrets never
   on a persistent filesystem:
   ```bash
   systemd-creds encrypt --name=redis-password - /etc/credstore/redis-password.cred
   ```
   ```ini
   # In Quadlet unit:
   LoadCredential=redis-password:/etc/credstore/redis-password.cred
   # Available at /run/credentials/redis-password inside container
   ```

2. **Ansible Vault for bootstrap credentials only** (`ansible-vault encrypt vault.yml`).
   Application-layer secrets still live in EnvironmentFile on tmpfs, not in `vault.yml`.

3. **File mode enforcement**: `mode: "0600"`, `owner: ja4proxy`. Add a verification task
   that fails the playbook if any file under `/run/ja4proxy/` is group- or world-readable.

4. **Service UID isolation**: `ja4proxy` user — no login shell (`/sbin/nologin`), no
   home directory, no sudo access.

5. **`RuntimeDirectoryPreserve=no`**: secrets cleared when service stops. Use
   `After=vault-agent.service Requires=vault-agent.service` to enforce re-render before
   proxy starts.

---

## 17. Audit and Compliance

### 17.1 auditd Rules

Deploy via Ansible to `/etc/audit/rules.d/ja4proxy.rules`:

```
-w /etc/ja4proxy2/ -p rwxa -k ja4proxy-config
-a always,exit -F arch=b64 -F path=/usr/bin/podman -k container-lifecycle
-a always,exit -F arch=b64 -S execve -F cmdline="systemctl * ja4proxy*" -k ja4proxy-service
-a always,exit -F arch=b64 -S setuid -S setgid -k privilege-escalation
```

Ship auditd events to your SIEM via `audisp-remote` or `auditbeat`. Never rely solely on
local log files — a compromised host can tamper with `/var/log/audit/audit.log`.

### 17.2 AIDE Baseline

```bash
aide --init
cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```

AIDE config for JA4proxy paths (`/etc/aide/aide.conf.d/ja4proxy.conf`):

```
/etc/ja4proxy2/             FIPSR+acl+xattr
/usr/local/bin/ja4proxy     FIPSR
/etc/containers/policy.json FIPSR
```

### 17.3 CIS RHEL 9 Benchmark — Key Controls

| CIS Control | Action |
|-------------|--------|
| 1.1 Filesystem Configuration | Mount `/tmp`, `/var/log` with `noexec,nosuid,nodev` |
| 3.3 Network Parameters | Add `net.ipv4.conf.all.rp_filter=1`, `log_martians=1` to sysctl task |
| 4.1 Auditing | auditd enabled, ship to SIEM |
| 5.2 SSH Server | `PermitRootLogin no`, `AllowGroups ja4proxy-ops` |

DISA STIG for containers: most common failures — container running as root (mitigated:
UID 9999), writable filesystem (mitigated: `read_only: true`), elevated privileges
(mitigated: `no-new-privileges`, `cap_drop: ALL`).

---

## 18. Network Security

### 18.1 firewalld Configuration

Two-interface model: `eth0` = proxy traffic (DMZ zone); `eth1` = management (internal zone).

```bash
# Proxy traffic interface — DMZ zone
firewall-cmd --permanent --zone=dmz --add-interface=eth0
firewall-cmd --permanent --zone=dmz --add-port=8080/tcp
firewall-cmd --permanent --zone=dmz --remove-service=ssh

# Management interface — internal zone
firewall-cmd --permanent --zone=internal --add-interface=eth1
firewall-cmd --permanent --zone=internal --add-port=9090/tcp  # metrics (defence-in-depth)
firewall-cmd --permanent --zone=internal --add-service=ssh

firewall-cmd --permanent --set-default-zone=drop
firewall-cmd --reload
```

**Current gap:** Prometheus metrics bound to `0.0.0.0:9090` in `config/proxy.yml`.
Change to `127.0.0.1:9090`. The firewall rule is defence-in-depth; loopback binding is
the primary control.

### 18.2 Redis mTLS with Certificate Pinning

Do not add the system CA bundle to the Redis client TLS context. Pin to the specific
JA4proxy internal CA only:

```python
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.load_verify_locations('/etc/ja4proxy/tls/ca.crt')
ssl_context.load_cert_chain(
    '/run/credentials/redis-client.crt',
    '/run/credentials/redis-client.key'
)
ssl_context.verify_mode = ssl.CERT_REQUIRED
ssl_context.check_hostname = True
# Do NOT call ssl_context.load_default_certs()
```

This ensures that a rogue CA planted in the system trust store cannot facilitate a
man-in-the-middle attack on the Redis connection.

---

## 19. Image Vulnerability Management

### 19.1 Build-Time Scanning (CI Gate)

```bash
trivy image \
  --exit-code 1 \
  --severity CRITICAL,HIGH \
  --ignore-unfixed \
  --format sarif \
  --output trivy-results.sarif \
  $REGISTRY/ja4proxy/go-proxy:$TAG
```

`--ignore-unfixed` is essential — without it, inherited base image CVEs with no available
fix block every build, causing teams to disable scanning entirely.

### 19.2 Registry Scanning

Configure Harbor or Quay to scan on push and block image promotion from staging to
production repository if unresolved CRITICAL CVEs exist.

### 19.3 Runtime: Falco

Deploy Falco as a DaemonSet (Kubernetes) or systemd service on RHEL hosts:

```yaml
# falco_rules.d/ja4proxy.yaml
- rule: Unexpected outbound connection from ja4proxy
  condition: >
    container.name startswith "ja4proxy-proxy" and
    evt.type = connect and
    not fd.sip in (allowed_redis_ips, allowed_backend_ips)
  output: "Unexpected outbound connection (dest=%fd.rip:%fd.rport)"
  priority: WARNING

- rule: Write attempt in read-only ja4proxy container
  condition: >
    container.name startswith "ja4proxy-proxy" and
    evt.type in (open, openat) and
    evt.arg.flags contains O_WRONLY and
    not fd.name startswith /tmp and
    not fd.name startswith /run
  output: "Write in read-only container (file=%fd.name)"
  priority: CRITICAL
```

### 19.4 Base Image Update Cadence

A scheduled CI pipeline runs every 72 hours checking for UBI9 base image digest changes.
If changed, it triggers an image rebuild, ensuring CVE patches from Red Hat errata are
incorporated within 72 hours of publication.

---

## 20. Critical Gaps in Current Implementation

The following gaps were identified by audit of the current codebase and must be addressed
in this phase:

| # | Gap | Risk | Remediation |
|---|-----|------|-------------|
| 1 | Go binary built with `CGO_ENABLED=0` — boringcrypto impossible | FIPS non-compliance | Set `CGO_ENABLED=1`, `GOEXPERIMENT=boringcrypto` in `Dockerfile.go-proxy` |
| 2 | Python containers use `python:3.14.0-slim` (Debian) | FIPS non-compliance on RHEL FIPS hosts | Migrate to `ubi9/python-312`; track UBI9 Python 3.14 release |
| 3 | Redis `tls-ciphersuites` permits ChaCha20-Poly1305 | FIPS 140-3 non-compliant cipher | Remove from `redis.conf.j2` |
| 4 | Go runtime image uses `alpine:3.19` | No Red Hat errata, no FIPS crypto provider | Switch runtime stage to `ubi9-minimal:9.4` |
| 5 | No Cosign image signing in CI | Supply chain integrity gap | Add `cosign sign` step; enforce via `containers-policy.json` |
| 6 | Prometheus metrics bound to `0.0.0.0:9090` | Metrics reachable on proxy interface | Bind to `127.0.0.1` in `config/proxy.yml` |
| 7 | Self-signed Redis TLS certs with long TTL | Brittle rotation, no PKI governance | Issue via Vault PKI engine with 90-day TTL |
| 8 | No Falco runtime monitoring | No detection of container anomalies | Deploy Falco with custom JA4proxy ruleset |
| 9 | `gcc` present in Python runtime image | Attack surface; CVE exposure | Multi-stage build — remove all build tools from runtime layer |
| 10 | No ITSM ticket enforcement in deploy playbook | No deployment audit trail | Add `assert` task requiring `itsm_ticket` variable |

---

## 21. Acceptance Criteria

- [x] Ansible inventory separates `proxy_tier` and `analytics_tier` into independent play groups
- [x] Pre-flight playbook (`preflight.yml`) validates all §8 checks before any deployment task
- [x] Rolling deploy uses `serial: 1` on proxy tier with `any_errors_fatal: true`
- [x] Canary gate evaluates all five metrics criteria before fleet promotion
- [x] LB drain/undrain role implemented for at least the provider(s) in use
- [x] Rollback playbook achieves < 60-second RTO from trigger to traffic restored
- [x] Previous image tag preserved locally — `podman image prune` excludes `current` and `previous`
- [x] `make deploy ENV=prod VERSION=x.y.z TICKET=CHGxxxxxxx` is the single deployment entry point
- [x] Deployment manifest (`deploy/manifest.yml`) checked into git with version pin per environment
- [x] `ja4proxy_deployment_info` metric emitted on every deployment
- [x] Quadlet unit files include `WatchdogSec=30`, `StartLimitBurst=3`, `NoNewPrivileges=true`
- [x] Automatic weekly image prune job (systemd timer) excludes rollback image
- [x] journald cap configured — `SystemMaxUse=2G`, `MaxRetentionSec=30day`
- [x] FIPS: Go binary compiled with `GOEXPERIMENT=boringcrypto` and `CGO_ENABLED=1`
- [x] FIPS: Redis `tls-ciphersuites` removes ChaCha20-Poly1305
- [x] FIPS: Python containers use UBI9 base image
- [x] Go runtime image uses `ubi9-minimal` (not Alpine)
- [x] Cosign signature enforced via `containers-policy.json` on every host
- [x] gitleaks pre-commit hook blocks secret commits
- [x] Prometheus metrics bound to `127.0.0.1:9090`
- [x] SELinux `Enforcing` check is a hard pre-flight abort
- [x] auditd rules deployed watching `/etc/ja4proxy2/` and `podman` lifecycle
- [x] firewalld two-zone model: DMZ (proxy traffic), internal (management/metrics)
- [x] Redis TLS client pins to internal CA only — system CA bundle not loaded
- [x] Trivy CVE scan gate in CI — blocks push on unpatched CRITICAL CVEs
- [x] Falco rules deployed detecting unexpected outbound connections and write attempts
- [x] Base image update CI job runs every 72 hours
