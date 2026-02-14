#!/bin/bash
# Nuclear option: Completely reset Docker networking
# Use this if fix-docker.sh doesn't work

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=========================================="
echo "Docker Nuclear Reset"
echo "=========================================="
echo ""
echo -e "${RED}WARNING: This will completely reset Docker networking${NC}"
echo "This will:"
echo "  1. Stop all containers"
echo "  2. Remove all networks"
echo "  3. Flush all iptables/nftables rules"
echo "  4. Restart Docker"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 0
fi

echo ""
echo "Stopping all Docker containers..."
docker ps -aq | xargs -r docker stop

echo "Removing all Docker containers..."
docker ps -aq | xargs -r docker rm

echo "Removing all Docker networks..."
docker network ls -q | grep -v bridge | grep -v host | grep -v none | xargs -r docker network rm 2>/dev/null || true

echo "Stopping Docker..."
sudo systemctl stop docker

echo "Flushing nftables..."
sudo nft flush ruleset 2>/dev/null || true

echo "Flushing iptables..."
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X

echo "Starting Docker..."
sudo systemctl start docker

echo "Waiting for Docker to initialize..."
sleep 5

echo ""
echo -e "${GREEN}Docker has been reset!${NC}"
echo ""
echo "Now run: ./start-poc.sh"
