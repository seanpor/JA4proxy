# Single-Host Setup Wizard & Deployment Simplification

## Goal
Simplify the enterprise deployment process of JA4proxy on a single, clean Linux host for SecOps personnel. Currently, manual prerequisites installation (Docker, Compose), config generation, and manual secret/TLS setups are error-prone. This phase proposes a single-command bootstrapping script and interactive CLI setup wizard that handles OS package dependencies, generates secure random keys, configures local firewall policies, mounts systemd units, configures logrotate, and verifies the deployment.

## Scope
- `scripts/bootstrap.sh` (New single-command installer and uninstall runner)
- `scripts/setup_wizard.py` (New interactive CLI wizard to configure `.env` and certificates)
- `docs/phases/manifest.yaml` (Proposed entry for Phase 231)
- `docs/PROJECT_STATUS.md` (Synced roadmap)
- `docs/phases/TODO.md` (Synced roadmap)

## Implementation Plan
1. **Prerequisites & Bootstrap Script (`bootstrap.sh`)**:
   - Implement an installer shell script that checks the OS (supports Ubuntu/Debian and RHEL/Rocky Linux).
   - Detect and install missing system packages (`curl`, `openssl`, `git`, `docker`, `docker-compose-plugin`) if they are absent, using the host package manager (`apt` or `dnf`).
   - Create the system user/group `ja4proxy` and establish correct ownership and permission states for directories (`/opt/ja4proxy`, `/var/log/ja4proxy`, `/backup/ja4proxy`).
2. **Interactive Configuration Wizard (`setup_wizard.py`)**:
   - Build a command-line setup wizard in Python.
   - Prompt the user interactively for:
     - Upstream backend host and port (e.g. `10.0.0.5:443`).
     - Admin username and password for the Management UI.
     - Binding IP address (default: `127.0.0.1` for local SSH tunneling, or custom IP/interface).
     - SSL option: Generate new self-signed certificates OR input paths to custom PEM certificate chain and private keys.
   - Generate strong cryptographically secure passwords for Redis, Grafana, HAProxy, and JWT tokens automatically.
   - Write output to the local `.env` and config files under `/opt/ja4proxy`.
3. **Hardened Firewall Setup**:
   - Automatically configure UFW or FirewallD to allow only public traffic on ports `80` and `443` (HAProxy ingress) while locking administrative interfaces (`8113`, `3023`, `9090`) to loopback or trusted networks.
4. **Daemon Integration & Logrotate**:
   - Generate and enable a systemd service unit `ja4proxy.service` to start/stop the compose services on system boot.
   - Set up standard `logrotate` rules for files in `/var/log/ja4proxy/`.
   - Install a cron backup script `ja4proxy-backup.sh` under `/usr/local/bin/` to run daily.
5. **Validation and Diagnostics**:
   - Add a diagnostic run (`bootstrap.sh --check`) that tests endpoint health, database connection, and logs any warning/error flags.
6. **Uninstaller Support**:
   - Implement a clean uninstall flag (`bootstrap.sh --uninstall`) that halts the stack, cleans systemd services, removes directories, and prompts before purging docker volumes.

## Test Strategy
- **VM Testing**: Boot clean virtual machines (e.g. Ubuntu 22.04 LTS and Rocky Linux 9) and run `bash scripts/bootstrap.sh` to verify end-to-end installation with zero prior dependencies.
- **CLI Wizard Input Validation**: Unit test `setup_wizard.py` to ensure it rejects invalid hostnames, empty passwords, or incorrect certificate paths.
- **Firewall Gating Test**: Verify from a remote client that port `8113` and `3023` are unreachable publicly, but port `443` successfully terminates TLS.
- **Uninstall Verification**: Run the uninstaller and check that no orphan volumes or configurations remain.

## Acceptance Criteria
- [ ] Running `bash scripts/bootstrap.sh` on a clean host installs Docker/Compose (if missing), generates secure secrets, and starts the JA4proxy stack.
- [ ] No manual editing of `.env` is required; all config parameters are entered via the interactive Python setup wizard.
- [ ] UFW/FirewallD configurations block access to administrative ports (`8113`, `3023`, `9091`) on external interfaces.
- [ ] The stack automatically restarts on server boot via systemd.
- [ ] Running the uninstaller leaves the VM clean.

## Out of Scope
- Deploying multi-node HA or Kubernetes clusters (handled separately via Helm charts).
- Managing domain registration or DNS record creation.
- Integrating external IDPs (OIDC/SAML) within the bootstrap wizard (these remain manual dashboard configurations).
