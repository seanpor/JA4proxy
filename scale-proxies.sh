#!/bin/bash
set -euo pipefail

# Scale JA4proxy to N proxy instances behind HAProxy
# Usage: ./scale-proxies.sh [N]   (default: 1, i.e. reset to POC default)

N=${1:-1}
COMPOSE_FILE="docker-compose.poc.yml"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Scaling JA4proxy to ${N} instance(s)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$N" -eq 1 ]; then
    # Reset to default POC config
    echo "▶ Restoring single-proxy POC configuration..."
    docker compose -f "$COMPOSE_FILE" up -d proxy 2>/dev/null
    docker cp "$(pwd)/ha-config/haproxy.cfg" ja4proxy-haproxy:/usr/local/etc/haproxy/haproxy.cfg
    docker kill -s HUP ja4proxy-haproxy 2>/dev/null || docker restart ja4proxy-haproxy
    echo -e "${GREEN}✓ Running 1 proxy instance (POC default)${NC}"
    exit 0
fi

# For N>1, we need to remove the container_name constraint
# Create a temporary override that clears it
OVERRIDE_FILE=$(mktemp /tmp/ja4proxy-scale-XXXXX.yml)
cat > "$OVERRIDE_FILE" << EOF
services:
  proxy:
    container_name: ""
    ports: []
    deploy:
      replicas: ${N}
EOF

echo "▶ Scaling proxy to ${N} instances..."
docker compose -f "$COMPOSE_FILE" -f "$OVERRIDE_FILE" up -d --remove-orphans proxy 2>/dev/null

sleep 3

# Discover proxy container IPs
echo "▶ Discovering proxy instances..."
PROXY_IPS=$(docker compose -f "$COMPOSE_FILE" -f "$OVERRIDE_FILE" ps -q proxy | \
    xargs -I{} docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {} 2>/dev/null)

if [ -z "$PROXY_IPS" ]; then
    echo "✗ No proxy instances found. Is the stack running?"
    rm -f "$OVERRIDE_FILE"
    exit 1
fi

# Generate HAProxy config with all backends
echo "▶ Generating HAProxy config for ${N} backends..."
HAPROXY_CFG=$(mktemp /tmp/haproxy-scaled-XXXXX.cfg)

cat > "$HAPROXY_CFG" << 'HAEOF'
global
    log stdout format raw local0
    maxconn 4096
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-default-bind-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
    ssl-default-server-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull
    timeout connect 5s
    timeout client  30s
    timeout server  30s
    retries 3

frontend tls_in
    bind *:443
    default_backend ja4proxy_backend
    option tcplog

frontend http_in
    bind *:80
    mode http
    acl is_health path /haproxy-health
    http-request return status 200 content-type text/plain string "OK" if is_health
    default_backend ja4proxy_backend_http

backend ja4proxy_backend
HAEOF

i=1
for ip in $PROXY_IPS; do
    echo "    server proxy${i} ${ip}:8080 send-proxy-v2 check" >> "$HAPROXY_CFG"
    echo "  proxy${i}: ${ip}"
    i=$((i+1))
done

cat >> "$HAPROXY_CFG" << 'HAEOF'

backend ja4proxy_backend_http
    mode http
HAEOF

i=1
for ip in $PROXY_IPS; do
    echo "    server proxy${i} ${ip}:8080 check" >> "$HAPROXY_CFG"
    i=$((i+1))
done

cat >> "$HAPROXY_CFG" << 'HAEOF'

frontend stats
    bind *:8404
    mode http
    stats enable
    stats uri /stats
    stats refresh 5s
    stats show-legends
    stats show-node
HAEOF

# Apply to HAProxy
docker cp "$HAPROXY_CFG" ja4proxy-haproxy:/usr/local/etc/haproxy/haproxy.cfg
docker kill -s HUP ja4proxy-haproxy 2>/dev/null || docker restart ja4proxy-haproxy

# Cleanup temp files
rm -f "$OVERRIDE_FILE" "$HAPROXY_CFG"

echo ""
echo -e "${GREEN}✓ Running ${N} proxy instances behind HAProxy${NC}"
echo "  HAProxy stats: http://localhost:8404/stats"
echo "  Est. throughput: ~$((N * 210)) conn/s"
echo ""
echo "To reset to single proxy:  ./scale-proxies.sh 1"
