#!/bin/bash
# Manually create Docker iptables chains
# This fixes the "No chain/target/match by that name" error

echo "Creating Docker iptables chains manually..."

# Create chains in filter table
sudo iptables -t filter -N DOCKER 2>/dev/null || echo "DOCKER chain exists"
sudo iptables -t filter -N DOCKER-ISOLATION-STAGE-1 2>/dev/null || echo "DOCKER-ISOLATION-STAGE-1 exists"
sudo iptables -t filter -N DOCKER-ISOLATION-STAGE-2 2>/dev/null || echo "DOCKER-ISOLATION-STAGE-2 exists"
sudo iptables -t filter -N DOCKER-USER 2>/dev/null || echo "DOCKER-USER exists"

# Create chains in nat table
sudo iptables -t nat -N DOCKER 2>/dev/null || echo "DOCKER nat chain exists"

# Add basic rules
sudo iptables -t filter -A DOCKER-ISOLATION-STAGE-1 -j RETURN 2>/dev/null || true
sudo iptables -t filter -A DOCKER-ISOLATION-STAGE-2 -j RETURN 2>/dev/null || true
sudo iptables -t filter -A DOCKER-USER -j RETURN 2>/dev/null || true

echo ""
echo "Docker chains created. Now restart Docker:"
echo "  sudo systemctl restart docker"
echo ""
echo "Then run: ./start-poc.sh"
