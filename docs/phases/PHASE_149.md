# Phase 149: Guided Setup & Configuration Wizard

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Depends on:** Phase 147
> **Owner:** Gemini CLI

## Goal
Implement a guided "wizard" experience for first-time users to set up their `.env` and core configuration, catering to distinct scenarios from Proof-of-Concept to Production.

## Context
While `scripts/start-poc.sh` handles basic `.env` generation, it lacks interactivity and doesn't account for users who want to point to their own backend immediately or those preparing for a production-hardened deployment.

## Scope

### 1. The `ja4p init` Command
Implement a new subcommand for the Go binary to handle environment initialization:
- **Scenario: Proof of Concept (POC)**
    - Auto-generates all secrets (HMAC keys, Redis passwords).
    - Uses default mock-backend and tarpit services.
    - Minimal prompt: "Are you ready to start the JA4proxy demo?"
- **Scenario: Contributor / Dev**
    - Configures local development paths.
    - Enables verbose debug logging.
    - Sets up hot-reload listeners.
- **Scenario: Performance/Benchmarking (Audit Mode)**
    - Optimizes for high throughput (tunes worker counts, buffer sizes).
    - Sets up a "Performance Original" (minimal mock backend) to measure pure proxy overhead.
    - Disables non-essential heavy analytics to baseline core throughput.
    - Validates system \`ulimits\` (open files) and warns if the system is not tuned for 10k+ concurrent connections.\n- **Scenario: Production**
    - Interactively prompts for **Backend Host** and **Port**.
    - Configures Redis persistence and TLS settings.
    - Sets up production-grade security headers and log formats.
    - Validates provided inputs (connectivity check to backend).

### 2. Guided Configuration Options
The wizard should guide the user through optional high-value features:
- **Threat Intel (TI) Feeds**: Prompt for ja4db.com / AbuseIPDB API keys.
- **Observability**: Configure Slack/Discord webhooks for alerts.
- **Persistence**: Local volume paths vs. managed Redis.


### 4. Data Provisioning (Scenario Dependent)
The wizard should offer to bootstrap required datasets:
- **Performance Mode**: Offer to download the Tranco Top-10k SNI list and seed the Redis JA4 cache with 10,000 synthetic entries to simulate a realistic production workload.
- **Production Mode**: Offer to fetch the latest GeoIP and ja4db feeds immediately.

### 3. "Pre-Flight" Validation
- Integrate `make doctor` into the initialization flow to ensure the host machine is capable before writing the config.
- Test connection to the specified backend host during the wizard.

## Scenarios Matrix

| Feature | POC | Dev | Performance | Production |
| :--- | :--- | :--- | :--- | :--- |
| **Secrets** | Auto-random | Fixed/Local | Fixed/Test | Prompt or Secure-Auto |
| **Logging** | Info (Std) | Debug | Minimal (Fast) | JSON/Structured |
| **Backend** | Mock Service | Mock/Remote | Fast-Mock | Real Backend (Required) |
| **Persistence**| Volatile | Persistent | No-Op/In-Mem | Hardened/Encrypted |
| **Complexity** | 0 Prompts | 2 Prompts | 1 Prompt | 5-7 Prompts |

## Acceptance Criteria
- [ ] `ja4p init` provides a smooth, colorized interactive flow.
- [ ] All three scenarios (POC, Dev, Prod) produce a valid and verified `.env` file.
- [ ] Wizard correctly detects and warns about missing prerequisites (via Doctor integration).
- [ ] Documentation updated to recommend `make init` as the primary "Day 1" entry point.

---

## Strategic Intent
This phase eliminates the "Blank Page" problem for new users. By providing a guided path, we significantly reduce the barrier to entry for enterprise security teams and ensure that production deployments start from a "secure-by-default" configuration.
