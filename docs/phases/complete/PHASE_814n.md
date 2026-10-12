# Pentest: IaC, Deployment and Downstream-Consumer Egress

## Goal
Execute Phase 814n of the Phase 814 penetration testing campaign against Infrastructure as Code (Ansible, Terraform Provider, Helm, Compose), reverse-proxy edge configs (HAProxy, Caddy), and downstream-consumer egress integrations (Splunk TA, Splunk SOAR, XSOAR, ServiceNow, QRadar LEEF, Sentinel CEF, EDL feed, and Webhooks). Ensure security boundaries protect downstream systems from telemetry injection, prevent unauthenticated exposure of internal monitoring/stats endpoints, and safeguard deployment mechanisms against supply chain attacks.

## Scope
- Reverse-proxy edge configurations:
  - `deploy/haproxy/haproxy.cfg`: TLS termination, PROXY protocol v2 header injection, stats endpoint exposure.
  - `deploy/caddy/Caddyfile.management`: TLS cipher/protocol suites and reverse proxy directives.
- Infrastructure as Code (IaC) and automation:
  - `deploy/ansible/`: Secret handling in vaults, unverified remote downloads in `deploy_binary.yml`, `become` privilege escalation rules.
  - `deploy/terraform-provider/`: Credential storage, TLS validation in provider HTTP client, resource bounds.
  - `deploy/charts/ja4proxy/`: Kubernetes NetworkPolicy, RBAC, container security context.
- Downstream-consumer telemetry and egress integrations:
  - `deploy/integrations/servicenow/ja4proxy_snow_handler.py`: Downstream injection via unsanitized ECS event fields (`short_description`, `description`), CSV formula injection, and CR/LF delimiter injection.
  - `deploy/integrations/splunk-ta/`: Alert action execution, lookup CSV formula injection, TLS validation.
  - `deploy/integrations/splunk_soar/` and `deploy/integrations/xsoar/`: Parameter sanitization and HTTP client timeouts.
  - `deploy/integrations/qradar/JA4proxy-DSM.xml` and Sentinel CEF: Log delimiter and header injection resilience.
  - `management/api/routes/edl.py` & `management/api/routes/webhooks.py`: Ingress/egress SSRF, DNS rebinding, and cache poisoning.

## Findings Summary
1. **JA4PROXY-2026-0130 (HIGH, CVSS 7.5)**: HAProxy stats dashboard exposed without authentication.
   - **File**: `deploy/haproxy/haproxy.cfg`
   - **Vulnerability**: `frontend stats` binds to `*:8404` with `stats enable`, `stats uri /stats`, and Prometheus metrics on `/metrics` with no `stats auth` directive configured.
   - **Remediation**: Add `stats auth` credential protection with environment variable fallback / strong credentials (`stats auth admin:${HAPROXY_STATS_PASSWORD:-admin}`) or restrict Prometheus/stats access appropriately.
2. **JA4PROXY-2026-0131 (HIGH, CVSS 7.5)**: Unverified remote binary download in Ansible ja4proxy role.
   - **File**: `deploy/ansible/roles/ja4proxy/tasks/deploy_binary.yml`
   - **Vulnerability**: `ansible.builtin.get_url` downloads `ja4proxy_binary_src` without specifying a `checksum` argument, allowing MITM or tampered binary execution as root.
   - **Remediation**: Require `checksum: "{{ ja4proxy_binary_checksum }}"` on `get_url`, and validate that `ja4proxy_binary_checksum` is defined when `ja4proxy_binary_src` is an HTTP/HTTPS URL.
3. **JA4PROXY-2026-0132 (MEDIUM, CVSS 5.4)**: Downstream telemetry injection in ServiceNow SIR incident integration.
   - **File**: `deploy/integrations/servicenow/ja4proxy_snow_handler.py`
   - **Vulnerability**: `ecs_to_sir()` formats `short_description` and `description` with raw, unescaped `source.ip` and `signals` text. Crafting inputs with newlines, control characters, or spreadsheet formula injection prefixes (`=`, `+`, `-`, `@`) can inject malicious payloads into ServiceNow records and analyst CSV exports.
   - **Remediation**: Sanitize strings in `ecs_to_sir()` by stripping newlines/control characters and escaping spreadsheet formula injection prefixes.

## Implementation Plan
1. **Register Findings**:
   - Register `JA4PROXY-2026-0130`, `JA4PROXY-2026-0131`, and `JA4PROXY-2026-0132` in `docs/security/findings.yaml` and update `docs/security/FINDINGS_REGISTER.md`.
2. **Remediate Code**:
   - Update `deploy/haproxy/haproxy.cfg` to enforce `stats auth`.
   - Update `deploy/ansible/roles/ja4proxy/tasks/deploy_binary.yml` and `defaults/main.yml` to enforce `checksum: "{{ ja4proxy_binary_checksum }}"`.
   - Update `deploy/integrations/servicenow/ja4proxy_snow_handler.py` with sanitization against CR/LF and CSV/spreadsheet formula injection.
3. **Write Regression Tests**:
   - `tests/unit/test_pentest_haproxy_stats_auth_regression.py` for JA4PROXY-2026-0130.
   - `tests/unit/test_pentest_ansible_checksum_regression.py` for JA4PROXY-2026-0131.
   - `tests/unit/test_pentest_servicenow_injection_regression.py` for JA4PROXY-2026-0132.
4. **Verification**:
   - Run `scripts/verify_revert.sh` for each finding to prove two-state revert compliance (failing pre-fix, passing post-fix).
   - Run `make preflight` and containerized test gates.
5. **Parallel Expert Reviews**:
   - Security, Concurrency, and Code Quality expert subagents must all APPROVE.
6. **Close-Out**:
   - Update `docs/phases/manifest.yaml` (set `814n` to `COMPLETE`), create news fragment `docs/fragments/phase-814n-pentest-iac-egress.md`, move plan to `docs/phases/complete/PHASE_814n.md`, and execute `bash scripts/close-phase.sh`.

## Acceptance Criteria
- All 3 findings registered and validated with zero schema violations.
- Regression tests pass 100% and demonstrate sensitivity to reverts.
- `make preflight` is 100% green.
- All three expert reviews approve.
