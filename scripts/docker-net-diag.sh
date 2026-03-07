#!/bin/bash
# Diagnose Docker container networking
# Run with: sudo bash scripts/docker-net-diag.sh

echo "=== IP forwarding ==="
cat /proc/sys/net/ipv4/ip_forward

echo ""
echo "=== iptables nat POSTROUTING ==="
iptables -t nat -L POSTROUTING -n -v

echo ""
echo "=== iptables FORWARD chain ==="
iptables -L FORWARD -n -v | head -30

echo ""
echo "=== UFW default forward policy ==="
grep DEFAULT_FORWARD_POLICY /etc/default/ufw

echo ""
echo "=== before.rules nat section ==="
grep -A 10 "^\*nat" /etc/ufw/before.rules || echo "NO *nat SECTION FOUND"

echo ""
echo "=== before.rules Docker FORWARD rules ==="
grep -A 3 "Docker FORWARD" /etc/ufw/before.rules || echo "NO Docker FORWARD RULES FOUND"

echo ""
echo "=== Container /etc/resolv.conf ==="
docker run --rm python:3.11-slim cat /etc/resolv.conf

echo ""
echo "=== Can container reach 8.8.8.8 (ping) ==="
docker run --rm python:3.11-slim sh -c "apt-get install -y -qq iputils-ping 2>/dev/null; ping -c 2 -W 3 8.8.8.8 || echo PING FAILED"
