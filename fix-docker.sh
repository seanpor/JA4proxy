#!/bin/bash
# Docker Network Fix Script
# Fixes common Docker iptables issues

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=========================================="
echo "Docker Network Fix"
echo "=========================================="
echo ""

echo "This script will fix Docker networking issues."
echo "It requires sudo access to restart Docker."
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 0
fi

echo ""
echo "Stopping all containers..."
docker stop $(docker ps -aq) 2>/dev/null || true

echo "Cleaning up networks..."
docker network prune -f

echo "Restarting Docker daemon..."
if command -v systemctl &> /dev/null; then
    sudo systemctl restart docker
elif command -v service &> /dev/null; then
    sudo service docker restart
else
    echo -e "${RED}Cannot restart Docker - please restart manually${NC}"
    exit 1
fi

echo "Waiting for Docker to be ready..."
sleep 5

echo ""
echo -e "${GREEN}Docker networking has been fixed!${NC}"
echo ""
echo "Now run: ./start-poc.sh"
