<!--
title: "Scope and Limitations: What JA4proxy Is and Is Not"
audience: product
last_reviewed: 2026-04-25
phase: 105
-->

# Scope and Limitations

JA4proxy is a **TLS-aware passthrough security proxy** that makes allow / block
/ rate-limit / tarpit / ban decisions based on plaintext metadata visible
**before** and **during** the TLS handshake — JA4 fingerprints, SNI, ALPN,
TCP options, ASN, and curated reputation feeds. It never decrypts traffic, holds
TLS keys, or inspects HTTP application data.

This document is the canonical "what JA4proxy does NOT do" reference. Architects
evaluating the product should pair every non-goal below with the named
complementary control category in the section that follows.

---

## Non-Goals

Each non-goal is a **deliberate scope boundary**, not a backlog item. Pursuing
any of these would compromise the asymmetric "fail open on real users" design
documented in `CLAUDE.md` and `docs/security/threat-model.md`.

### 1. JA4proxy is NOT a Web Application Firewall (WAF)

It does not parse HTTP, has no rule language for application semantics, and
makes no per-URL or per-method decisions. Pair with a WAF (ModSecurity,
Cloudflare, AWS WAF) for OWASP Top 10 coverage.

### 2. JA4proxy does NOT decrypt TLS

There is no TLS termination, no MITM, no inspection of the encrypted record
layer. Plaintext bodies, headers, cookies, and tokens are never visible to the
proxy. This is a privacy and compliance feature, not a limitation to fix.

### 3. JA4proxy does NOT re-encrypt or re-sign traffic

Allowed connections are forwarded byte-for-byte unchanged. Operators do not
need to provision certificates for JA4proxy; backend TLS sessions remain
end-to-end between the client and the origin server.

### 4. JA4proxy does NOT inspect HTTP request or response bodies

No payload scanning, no content classification, no DLP. If a credential or PII
appears in a request body, JA4proxy never sees it. Body inspection requires a
WAF or API gateway in addition.

### 5. JA4proxy does NOT prevent SQL injection, XSS, CSRF, SSRF, or RCE

These are application-layer concerns. JA4proxy operates at the TLS-handshake
and connection-metadata layer; an attacker hand-crafting an injection payload
inside an otherwise-normal browser session is invisible to the fingerprint
scorer. Defence-in-depth requires a WAF and secure application code.

### 6. JA4proxy does NOT detect insider threats

The threat model assumes the attacker is **outside** the trust boundary. Users
who already hold valid credentials or mTLS client certificates explicitly
**bypass** scoring (see `docs/security/threat-model.md` §"Bypass Rules").
Insider-threat detection requires UEBA (user and entity behaviour analytics),
endpoint monitoring, and access-pattern auditing.

### 7. JA4proxy does NOT replace endpoint security or EDR

It cannot detect a compromised host whose TLS stack still produces a
legitimate-looking JA4 fingerprint. Malware that uses the system browser's TLS
implementation will share that browser's fingerprint. Endpoint detection and
response (EDR) is required to identify host-level compromise.

### 8. JA4proxy does NOT scan files, attachments, or uploads for malware

The proxy never sees file contents (see non-goal #4). Malware scanning of
uploaded artefacts requires a separate sandbox, AV engine, or upload-gateway
service downstream of the application.

### 9. JA4proxy is NOT an authentication or identity provider

It does not issue, validate, or revoke user sessions, JWTs, OAuth tokens, or
SAML assertions. mTLS client certificates are accepted as a **bypass signal**
(allow), not as a primary authentication mechanism. Identity decisions remain
the responsibility of the application or upstream IdP.

### 10. JA4proxy does NOT guarantee detection of every malicious bot

Sophisticated adversaries can mimic browser JA4 fingerprints, randomise
inter-arrival jitter, and rotate IPs. The composite scorer is designed to make
evasion **expensive** across multiple signals, not to be unforgeable. False
negatives are accepted by design (see the asymmetry rule in `CLAUDE.md`).

### 11. JA4proxy is NOT a substitute for DDoS scrubbing at the network edge

Volumetric L3/L4 attacks (UDP flood, amplification, SYN flood at line rate)
must be absorbed by an upstream provider (Cloudflare, AWS Shield, scrubbing
centre). JA4proxy operates at L4/L7 metadata; it cannot defend against
saturation of its own ingress link.

### 12. JA4proxy does NOT provide forensic packet capture

Connection metadata is logged in ECS format (see `docs/api/ecs_extension.md`),
but full packet captures are not retained. Pair with `tcpdump`, Zeek, or a
network-recorder appliance for incident-response forensics.

---

## Complementary Controls

JA4proxy is one layer of a defence-in-depth stack. A typical enterprise
deployment combines it with the categories below.

### Web Application Firewall (WAF)

Inspects HTTP semantics: SQL injection, XSS, CSRF, request-rate per endpoint,
custom rule sets. Examples: ModSecurity, Cloudflare WAF, AWS WAF, F5 ASM.
Deploys **alongside** or **upstream** of JA4proxy. The two are complementary —
JA4proxy handles fingerprint and reputation; the WAF handles payload semantics.

### Endpoint Detection and Response (EDR)

Detects compromise on user devices and servers: process behaviour, file
integrity, lateral movement. Examples: CrowdStrike Falcon, SentinelOne,
Microsoft Defender for Endpoint, Elastic Security. Required to detect
insider-threat and host-compromise scenarios that JA4proxy explicitly does not
cover (non-goals #6, #7).

### Security Information and Event Management (SIEM)

Aggregates and correlates events from JA4proxy and every other security
control. Examples: Splunk, Microsoft Sentinel, IBM QRadar, Wazuh, Elastic
Security. JA4proxy emits ECS-formatted events designed for direct SIEM
ingestion — see `SIEM_INTEGRATION.md`.

### Security Orchestration, Automation, and Response (SOAR)

Automates incident-response playbooks across multiple tools. Examples: Splunk
SOAR, Palo Alto Cortex XSOAR, Microsoft Sentinel Playbooks, Tines. JA4proxy's
webhook dispatcher (`internal/webhook/delivery.go`) and EDL (External Dynamic
List) endpoint are the integration surfaces for SOAR-driven enforcement.

### Identity and Access Management (IAM)

Authentication, authorisation, MFA, session management. Examples: Okta, Auth0,
Microsoft Entra ID, Keycloak. JA4proxy's mTLS bypass integrates with
certificate-based IAM but does not replace it.

### DDoS Mitigation Service

Network-edge volumetric defence. Examples: Cloudflare, Akamai Prolexic, AWS
Shield Advanced. Required to keep JA4proxy's ingress link from being saturated
(non-goal #11).

### Container and Kubernetes Security

Runtime monitoring, admission control, pod-security policies. Examples: Falco,
Sysdig Secure, Aqua, Prisma Cloud. JA4proxy's container hardening (read-only
filesystem, dropped capabilities, non-root user) is necessary but not
sufficient on its own; runtime monitoring closes the gap on supply-chain and
escape attacks.

---

## Where JA4proxy Adds Unique Value

The complement of "what it doesn't do" is the focused set of attacks that
JA4proxy makes materially harder:

- **Credential-stuffing and form-abuse bots** that use TLS stacks distinct
  from real browsers (curl, requests, headless variants without a real browser
  fingerprint).
- **C2 beaconing** with regular inter-arrival timing patterns (Phase 9
  beaconing detector).
- **Datacenter-origin scrapers** without legitimate mTLS or
  whitelist-justification (Phase 6 ASN classification).
- **Reputation-known malicious IPs** at the connection-establishment layer,
  before any application logic runs (Phase 10 AbuseIPDB, Phase 8 Spamhaus
  DROP/EDROP).
- **Connection-establishment-stage TLS-anomaly attacks** (TLS 1.0/1.1, weak
  ciphers, malformed ClientHello — Phase 3 TLS enforcer).

For the full signal catalogue, see the canonical phase documentation in
`docs/phases/` and the threat-model linked from
`README.md`.

---

## Related Reading

- `docs/security/threat-model.md` — full STRIDE analysis and asset model
- `docs/compliance/SECURITY_CONTROLS_MAPPING.md` — ISO 27001 control coverage
- `docs/security/DEPLOYMENT_SECURITY_MODEL.md` — trust boundaries and OS user model
- `SIEM_INTEGRATION.md` — log forwarding to your SIEM
- `EVALUATION_CHECKLIST.md` — POC and 30-day evaluation
