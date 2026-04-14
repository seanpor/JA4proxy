#!/bin/bash
# Phase 43 — Blue/Green Deployment Tooling
# 
# Handles zero-downtime rollouts by running parallel stacks and 
# swapping HAProxy backends after health verification.

set -euo pipefail

# Configuration
COMPOSE_PROD="deploy/docker/docker-compose.prod.yml"
HAPROXY_CFG="config/haproxy.cfg"
HEALTH_PORT=9090
CHECK_INTERVAL=2
MAX_RETRIES=30

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    echo "Usage: $0 [deploy|rollback|status]"
    echo ""
    echo "Commands:"
    echo "  deploy    Perform a blue/green rollout"
    echo "  rollback  Instantly switch HAProxy back to the previous stack"
    echo "  status    Show which stack is currently active"
    exit 1
}

get_active_color() {
    # Check HAProxy config to see which workers are active
    if grep -q "proxy-worker-green" "$HAPROXY_CFG"; then
        echo "green"
    else
        echo "blue"
    fi
}

wait_for_health() {
    local color=$1
    local project="ja4proxy-$color"
    log_info "Waiting for $color stack to become healthy..."
    
    # Get container IPs for the new stack
    local ips=$(docker compose -p "$project" -f "$COMPOSE_PROD" ps -q proxy | \
                xargs -I{} docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {})
    
    if [ -z "$ips" ]; then
        log_error "No containers found for $color stack."
        return 1
    fi

    for ip in $ips; do
        local retries=0
        local healthy=false
        while [ $retries -lt $MAX_RETRIES ]; do
            if curl -s "http://$ip:$HEALTH_PORT/health" | grep -q '"status": "healthy"'; then
                log_info "Container $ip is HEALTHY."
                healthy=true
                break
            fi
            retries=$((retries + 1))
            sleep $CHECK_INTERVAL
        done
        
        if [ "$healthy" = false ]; then
            log_error "Container $ip failed health check after $MAX_RETRIES retries."
            return 1
        fi
    done
    return 0
}

update_haproxy() {
    local new_color=$1
    local old_color=$2
    log_info "Switching HAProxy traffic from $old_color to $new_color..."
    
    # Create a temporary config
    local tmp_cfg=$(mktemp)
    cp "$HAPROXY_CFG" "$tmp_cfg"
    
    # Replace worker hostnames in the backend
    # This assumes hostnames are proxy-worker-blue-1 etc or similar
    # In a real environment, we'd use IP addresses or discoverable names.
    # For this implementation, we will update the config to use the new color's names.
    sed -i "s/proxy-worker-$old_color/proxy-worker-$new_color/g" "$tmp_cfg"
    
    # Move to production path
    mv "$tmp_cfg" "$HAPROXY_CFG"
    
    # Hot-reload HAProxy (Phase 42 mechanism)
    log_info "Reloading HAProxy..."
    docker kill -s HUP ja4proxy-haproxy 2>/dev/null || docker restart ja4proxy-haproxy
}

do_deploy() {
    local active=$(get_active_color)
    local next="green"
    if [ "$active" == "green" ]; then next="blue"; fi
    
    log_info "Active stack: $active. Deploying to: $next."
    
    # 1. Start the next stack
    log_info "Starting $next stack..."
    docker compose -p "ja4proxy-$next" -f "$COMPOSE_PROD" up -d --scale proxy=4
    
    # 2. Wait for health
    if ! wait_for_health "$next"; then
        log_error "Deployment failed: $next stack is unhealthy. Rolling back..."
        docker compose -p "ja4proxy-$next" -f "$COMPOSE_PROD" down
        exit 1
    fi
    
    # 3. Swap traffic
    update_haproxy "$next" "$active"
    
    # 4. Success - keep old stack for 60s to finish active connections, then stop
    log_info "Deployment successful. Traffic shifted to $next."
    log_info "Draining $active stack for 60s..."
    sleep 60
    docker compose -p "ja4proxy-$active" -f "$COMPOSE_PROD" stop
    log_info "Stopped $active stack."
}

do_rollback() {
    local active=$(get_active_color)
    local prev="green"
    if [ "$active" == "green" ]; then prev="blue"; fi
    
    log_info "Rolling back from $active to $prev..."
    
    # 1. Ensure previous stack is running
    docker compose -p "ja4proxy-$prev" -f "$COMPOSE_PROD" start || \
    docker compose -p "ja4proxy-$prev" -f "$COMPOSE_PROD" up -d --scale proxy=4
    
    # 2. Wait for health
    if ! wait_for_health "$prev"; then
        log_error "Rollback failed: $prev stack is unhealthy."
        exit 1
    fi
    
    # 3. Swap traffic
    update_haproxy "$prev" "$active"
    
    log_info "Rollback complete. Active stack: $prev."
}

if [ $# -lt 1 ]; then usage; fi

case "$1" in
    deploy)   do_deploy ;;
    rollback) do_rollback ;;
    status)   echo "Active stack: $(get_active_color)" ;;
    *)        usage ;;
esac
