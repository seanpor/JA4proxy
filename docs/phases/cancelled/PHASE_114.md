# Phase 114 — Supply Chain & Infrastructure Hygiene

> **Status:** PROPOSED
> **Size:** SMALL (2-3 engineer-days)
> **Triggered by:** Phase 108 Pentest Finding [L4-023], [L4-024], [L4-025]

---

## Goal

Harden the CI/CD pipeline, build scripts, and deployment logic against command injection and resource exhaustion.

---

## 114a. Secure Jenkins Pipeline Interpolation

### Problem
`Jenkinsfile` uses double-quoted Groovy strings with environment variable interpolation (`sh """..."""`), allowing command injection via `JA4PROXY_URL`.

### Fix
1.  In `deploy/jenkins/Jenkinsfile`, change the `sh` steps to use single-quoted strings (`sh '...'`) or map the environment variables into the shell environment using the `withEnv` block or similar.
2.  Alternatively, ensure the shell call uses the `env.` prefix within the single quotes so the shell resolves the variable, not Groovy.

---

## 114b. Makefile Input Validation

### Problem
The `Makefile` interpolates the `NAME` parameter into shell evaluation contexts without sanitization.

### Fix
1.  Add a guard check at the top of the `agent-up` and `agent-down` targets.
2.  Use a shell snippet to validate that `$(NAME)` contains only alphanumeric characters, underscores, or hyphens. If it contains shell metacharacters, `exit 1` immediately.

---

## 114c. Idempotent Cron Job Deployment

### Problem
`scripts/deploy.sh` appends to the crontab on every run, leading to duplicated jobs and massive resource contention.

### Fix
1.  Update the deployment script to write the backup cron job to a dedicated file in `/etc/cron.d/ja4proxy-backup`.
2.  Ensure this file is overwritten (or checked for existence) rather than appended to.

---

## Acceptance Criteria
- [ ] Test: Attempt `make agent-up NAME="test; touch EXPLOIT"`; verify the file `EXPLOIT` is NOT created.
- [ ] Test: Run `scripts/deploy.sh` three times; verify `/etc/cron.d/ja4proxy-backup` exists and contains only one instance of the backup command.
- [ ] Test: Verify Jenkins pipeline successfully applies policy using a URL containing complex characters (e.g., `-` or `_`) but fails securely if injection is attempted.
