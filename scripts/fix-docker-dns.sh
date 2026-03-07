#!/bin/bash
# Fix Docker container networking while keeping "iptables": false and UFW intact.
#
# Root causes:
#   1. UFW DEFAULT_FORWARD_POLICY=DROP blocks container packets from being forwarded
#   2. Containers inherit 127.0.0.53 (systemd-resolved) which is unreachable from inside
#
# This script:
#   - Sets DEFAULT_FORWARD_POLICY=ACCEPT so containers can route out (safe on a non-router host)
#   - Keeps the *nat MASQUERADE rule (already in before.rules from previous run)
#   - Keeps "iptables": false in daemon.json (UFW stays in control of iptables)
#   - Adds "dns": ["8.8.8.8", "1.1.1.1"] to daemon.json (already done)
#
# Run with: sudo bash scripts/fix-docker-dns.sh

set -e

# ── 1. daemon.json: keep iptables:false, keep explicit DNS ───────────────────

echo "==> Writing /etc/docker/daemon.json ..."
cat > /etc/docker/daemon.json << 'ENDJSON'
{
  "runtimes": {
    "nvidia": {
      "args": [],
      "path": "nvidia-container-runtime"
    }
  },
  "iptables": false,
  "dns": ["8.8.8.8", "1.1.1.1"]
}
ENDJSON
echo "    Done."

# ── 2. Ensure *nat MASQUERADE block is in before.rules ───────────────────────

BEFORE_RULES=/etc/ufw/before.rules

if grep -q "Docker NAT masquerade" "$BEFORE_RULES"; then
    echo "==> NAT MASQUERADE rule already present in before.rules."
else
    echo "==> Adding NAT MASQUERADE rule to before.rules ..."
    cp "$BEFORE_RULES" "${BEFORE_RULES}.bak.$(date +%Y%m%d%H%M%S)"
    # Prepend *nat block before the existing content
    {
        cat << 'NATBLOCK'
# -- Docker NAT masquerade (added by fix-docker-dns.sh) --
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
COMMIT

NATBLOCK
        cat "$BEFORE_RULES"
    } > "${BEFORE_RULES}.tmp"
    mv "${BEFORE_RULES}.tmp" "$BEFORE_RULES"
    echo "    Done."
fi

# ── 3. Enable IP forwarding in UFW ───────────────────────────────────────────

echo "==> Setting DEFAULT_FORWARD_POLICY=ACCEPT in /etc/default/ufw ..."
sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
grep DEFAULT_FORWARD_POLICY /etc/default/ufw
echo "    Done."

# ── 4. Enable kernel IP forwarding ───────────────────────────────────────────

echo "==> Enabling kernel IP forwarding ..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null
# Make it persist
if grep -q "net.ipv4.ip_forward" /etc/sysctl.conf; then
    sed -i 's/^#*net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
else
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
echo "    Done."

# ── 5. Reload UFW ────────────────────────────────────────────────────────────

echo "==> Reloading UFW ..."
ufw reload
echo "    Done."

# ── 6. Restart Docker ────────────────────────────────────────────────────────

echo "==> Restarting Docker ..."
systemctl restart docker
sleep 5

# ── 7. Test ──────────────────────────────────────────────────────────────────

echo ""
echo "==> Testing DNS in a container ..."
docker run --rm python:3.11-slim python -c "
import socket
ip = socket.gethostbyname('pypi.org')
print(f'DNS OK: pypi.org -> {ip}')
"

echo ""
echo "==> Testing pip install in a container ..."
docker run --rm python:3.11-slim pip install --quiet prometheus_client && echo "pip OK"

echo ""
echo "All done. Run 'make rebuild' to rebuild JA4proxy containers."
