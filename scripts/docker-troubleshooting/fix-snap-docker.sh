#!/bin/bash
# Fix for Snap Docker iptables issues
# Snap Docker has restricted access to iptables

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=========================================="
echo "Snap Docker Detected"
echo "=========================================="
echo ""
echo -e "${YELLOW}You're running Docker from snap, which has restricted iptables access.${NC}"
echo ""
echo "Options:"
echo "  1. Give snap Docker firewall-control permission (quick)"
echo "  2. Switch to apt Docker (recommended, requires reinstall)"
echo ""
read -p "Choose option (1 or 2): " -n 1 -r
echo

if [[ $REPLY == "1" ]]; then
    echo ""
    echo "Connecting snap Docker to firewall-control..."
    sudo snap connect docker:firewall-control
    sudo snap connect docker:network-control
    sudo snap restart docker
    
    echo "Waiting for Docker to restart..."
    sleep 10
    
    echo ""
    echo -e "${GREEN}Done! Now run: ./start-poc.sh${NC}"
    
elif [[ $REPLY == "2" ]]; then
    echo ""
    echo -e "${RED}This will remove snap Docker and install apt Docker${NC}"
    echo ""
    read -p "Continue? (y/n): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing snap Docker..."
        sudo snap remove docker
        
        echo "Installing Docker from apt..."
        sudo apt-get update
        sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        sudo apt-get update
        sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        
        echo "Adding your user to docker group..."
        sudo usermod -aG docker $USER
        
        echo ""
        echo -e "${GREEN}Docker installed!${NC}"
        echo ""
        echo "You need to log out and back in for group membership to take effect."
        echo "Then run: ./start-poc.sh"
    fi
else
    echo "Cancelled"
fi
