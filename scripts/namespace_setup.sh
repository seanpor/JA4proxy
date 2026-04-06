#!/usr/bin/env bash
# namespace_setup.sh — Namespace isolation helper for JA4proxy (Phase 56b-3)
#
# PURPOSE
# -------
# Documents how an operator would isolate the JA4proxy process into its own
# Linux network and PID namespace on a bare-metal RHEL host (outside Docker).
#
# WHY THIS IS NOT DONE INSIDE DOCKER
# ------------------------------------
# The JA4proxy Docker container drops ALL capabilities at startup:
#
#   cap_drop: [ALL]
#
# Creating a new user namespace with `unshare` requires CAP_SYS_ADMIN (for
# most namespace types) or a setuid `newuidmap`/`newgidmap` binary for user
# namespaces.  Because cap_drop: ALL removes CAP_SYS_ADMIN, the `unshare`
# syscall returns EPERM inside the container.
#
# The seccomp profile (config/seccomp/proxy.json) also denies `clone` with
# flags that would create new namespaces (CLONE_NEWNET, CLONE_NEWPID).
#
# For operators running JA4proxy directly on a bare-metal host (not in a
# container), the unshare-based approach below is the correct method.
#
# BARE-METAL RHEL 8/9 SETUP
# --------------------------
# Prerequisites:
#   - RHEL 8+ with kernel >= 3.8 (user namespaces) or root / CAP_SYS_ADMIN
#   - `unshare` from util-linux >= 2.27
#   - `ip` from iproute2 (for veth pair setup after namespace creation)
#
# Step 1: Create a new network + PID namespace and start the proxy inside it.
#
#   # As root or with CAP_SYS_ADMIN:
#   unshare --net --pid --mount-proc \
#     --fork \
#     -- /usr/bin/python3 /opt/ja4proxy/proxy.py
#
#   Flags explained:
#     --net        Create a new network namespace (process sees only lo initially)
#     --pid        Create a new PID namespace (process is PID 1 inside)
#     --mount-proc Re-mount /proc so `ps` inside the namespace is correct
#     --fork       Fork before exec (required with --pid)
#
# Step 2: Wire the new network namespace to the host network.
#
#   After `unshare` returns the child PID (e.g. 12345), create a veth pair:
#
#   # On the host:
#   ip link add veth-proxy type veth peer name veth-host
#   ip link set veth-proxy netns /proc/12345/ns/net
#   ip addr add 10.100.0.1/30 dev veth-host
#   ip link set veth-host up
#
#   # Inside the namespace (via nsenter):
#   nsenter --net=/proc/12345/ns/net -- ip addr add 10.100.0.2/30 dev veth-proxy
#   nsenter --net=/proc/12345/ns/net -- ip link set veth-proxy up
#   nsenter --net=/proc/12345/ns/net -- ip route add default via 10.100.0.1
#
# Step 3: Verify isolation.
#
#   # The proxy should only see its own loopback and veth-proxy:
#   nsenter --net=/proc/12345/ns/net -- ip addr show
#
#   # The proxy should see only its own PIDs:
#   nsenter --pid=/proc/12345/ns/pid -- ps aux
#
# SYSTEMD INTEGRATION (RHEL 8/9 with Quadlets)
# ----------------------------------------------
# For production Quadlet/systemd units, use systemd's built-in namespace
# directives instead of `unshare`:
#
#   [Service]
#   PrivateNetwork=yes      # New network namespace (requires systemd >= 233)
#   PrivatePIDs=yes         # New PID namespace (requires systemd >= 252)
#   PrivateTmp=yes          # New /tmp mount namespace
#   ProtectSystem=strict    # Read-only /usr and /boot
#   ProtectHome=yes         # Inaccessible /home /root /run/user
#   NoNewPrivileges=yes     # Equivalent to PR_SET_NO_NEW_PRIVS
#   SecureBits=noroot       # uid=0 has no special privileges
#
# See also: PHASE_76.md (Enterprise RHEL Production Deployment Strategy)
#
# DOCKER ALTERNATIVE
# -------------------
# Inside Docker, namespace isolation is achieved through:
#   - Docker's built-in network namespacing (each container has its own netns)
#   - cap_drop: [ALL] to prevent privilege escalation
#   - seccomp profiles (config/seccomp/proxy_runtime.json)
#   - read_only: true filesystem where possible
#
# These controls are already applied by docker-compose.poc.yml and
# docker-compose.yml.  No additional unshare is needed or possible.

set -euo pipefail

echo "namespace_setup.sh: This script documents namespace isolation for bare-metal RHEL deployments."
echo "It does not execute any commands automatically."
echo ""
echo "For Docker deployments, namespace isolation is provided by Docker itself."
echo "See config/seccomp/proxy_runtime.json for the seccomp profile applied at runtime."
echo "See docs/phases/PHASE_56.md for the full design rationale."
