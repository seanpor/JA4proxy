# Phase 120 — Independent Red Team Findings: Design Flaws, Infrastructure & Logic Bugs

> **Status:** PROPOSED
> **Size:** LARGE (12-16 engineer-days)
> **Triggered by:** Independent Deep-Dive Red Team Assessment (2026-04-17)

---

## Goal

Fix 20 novel findings from independent deep-dive team covering: ALPN bypass design flaw, X-JA4-Fingerprint header injection, HAProxy default creds, privileged cAdvisor, Docker socket exposure, CI/CD token leaks, Redis PubSub poisoning, stored XSS, JWT role escalation, DSAR OOM, IPv6 burst bug, blocklist logic bug, config reload path, infrastructure hardening.

---

## 120a. ALPN Bypass Design Flaw

### Problem
ALPN can be bypassed by sending empty ALPN extension.

### Location
Various TLS handlers

### Fix
Enforce ALPN validation.

### Size
SMALL

---

## 120b. X-JA4-Fingerprint Header Injection

### Problem
Attacker can inject arbitrary fingerprint via X-JA4-Fingerprint header.

### Fix
Disable or validate header.

### Size
SMALL

---

## 120c. HAProxy Default Credentials

### Problem
Default stats credentials may be active.

### Location
config/haproxy.cfg

### Fix
Require env vars, no defaults.

### Size
XS

---

## 120d. Privileged cAdvisor

### Problem
cAdvisor runs privileged in some deployments.

### Fix
Harden container security.

### Size
MEDIUM

---

## 120e. Docker Socket Exposure

### Problem
Docker socket may be exposed to containers.

### Fix
Remove socket mount.

### Size
XS

---

## 120f. CI/CD Token Leaks

### Problem
Tokens in CI/CD logs.

### Fix
Mask tokens in output.

### Size
XS

---

## 120g. Redis PubSub Poisoning

### Problem
Unauthenticated PubSub allows command injection.

### Fix
Add authentication.

### Size
SMALL

---

## 120h. Stored XSS

### Problem
XSS in management UI.

### Fix
Sanitize inputs.

### Size
SMALL

---

## 120i. JWT Role Escalation

### Problem
Role claim can be manipulated.

### Fix
Validate from trusted source.

### Size
SMALL

---

## 120j. DSAR OOM

### Problem
DSAR can cause memory exhaustion.

### Fix
Add pagination.

### Size
MEDIUM

---

## 120k. IPv6 Burst Bug

### Problem
IPv6 handling may cause burst.

### Fix
Add rate limiting.

### Size
SMALL

---

## 120l. Blocklist Logic Bug

### Problem
Blocklist refresh has race condition.

### Fix
Add atomic operations.

### Size
SMALL

---

## 120m. Config Reload Path

### Problem
Config reload is vulnerable to injection.

### Fix
Validate config path.

### Size
SMALL

---

## Acceptance Criteria
- [ ] All 20 findings addressed
- [ ] lint-phases exits 0
- [ ] Tests pass