# Docker Troubleshooting Scripts

These scripts were used to resolve Docker networking issues during setup. They are kept here for reference but should not be needed for normal operations.

## Scripts

- **fix-docker.sh** - Switches from iptables-nft to iptables-legacy
- **fix-snap-docker.sh** - Configures snap Docker with firewall-control permissions
- **create-docker-chains.sh** - Manually creates Docker iptables chains
- **disable-docker-iptables.sh** - Disables Docker's iptables management
- **nuclear-reset-docker.sh** - Complete Docker networking reset

## When to Use

Only use these if you encounter Docker networking errors like:
- "Chain 'DOCKER-ISOLATION-STAGE-2' does not exist"
- "Failed to Setup IP tables"
- Network creation failures

## Normal Setup

For normal operations, just use:
```bash
./start-poc.sh
```
