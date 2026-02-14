#!/bin/bash
# Disable Docker iptables management
# This allows containers to run without Docker managing firewall rules

echo "Disabling Docker iptables management..."
echo "This allows Docker to create networks without managing iptables."
echo ""

# Backup current config
sudo cp /etc/docker/daemon.json /etc/docker/daemon.json.backup-$(date +%s)

# Update config to disable iptables
cat /etc/docker/daemon.json | jq 'del(.iptables) | . + {"iptables": false}' | sudo tee /etc/docker/daemon.json.tmp
sudo mv /etc/docker/daemon.json.tmp /etc/docker/daemon.json

echo "Docker daemon.json updated:"
cat /etc/docker/daemon.json

echo ""
echo "Restarting Docker..."
sudo systemctl restart docker

sleep 5

echo ""
echo "Done! Now run: ./start-poc.sh"
