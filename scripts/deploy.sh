#!/bin/bash
# Enterprise deployment script for JA4 Proxy

set -euo pipefail

# Configuration
ENVIRONMENT=${1:-production}
VERSION=${2:-latest}
CONFIG_DIR="/opt/ja4proxy"
LOG_DIR="/var/log/ja4proxy"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check available disk space (minimum 10GB)
    available=$(df / | tail -1 | awk '{print $4}')
    if [[ $available -lt 10485760 ]]; then
        log_error "Insufficient disk space. At least 10GB required."
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Setup directories and permissions
setup_directories() {
    log_info "Setting up directories and permissions..."
    
    # Create system user if not exists
    if ! id "ja4proxy" &>/dev/null; then
        useradd -r -s /bin/false -d /var/lib/ja4proxy ja4proxy
        log_info "Created ja4proxy user"
    fi
    
    # Create directories
    mkdir -p "${CONFIG_DIR}"/{config,ssl,secrets}
    mkdir -p "${LOG_DIR}"
    mkdir -p /var/lib/ja4proxy
    mkdir -p /backup/ja4proxy
    
    # Set permissions
    chown -R ja4proxy:ja4proxy "${CONFIG_DIR}" "${LOG_DIR}" /var/lib/ja4proxy
    chmod 750 "${CONFIG_DIR}" "${LOG_DIR}" /var/lib/ja4proxy
    chmod 700 "${CONFIG_DIR}/secrets" "${CONFIG_DIR}/ssl"
    
    log_info "Directories and permissions configured"
}

# Generate SSL certificates if not present
setup_ssl() {
    log_info "Setting up SSL certificates..."
    
    local ssl_dir="${CONFIG_DIR}/ssl"
    
    if [[ ! -f "${ssl_dir}/proxy.crt" ]]; then
        log_info "Generating SSL certificates..."
        
        # Generate CA
        openssl genrsa -out "${ssl_dir}/ca.key" 4096
        openssl req -new -x509 -days 3650 -key "${ssl_dir}/ca.key" -out "${ssl_dir}/ca.crt" \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=JA4Proxy-CA" \
            -config <(echo '[v3_ca]'; echo 'basicConstraints = CA:TRUE')
        
        # Generate server certificate
        openssl genrsa -out "${ssl_dir}/proxy.key" 4096
        openssl req -new -key "${ssl_dir}/proxy.key" -out "${ssl_dir}/proxy.csr" \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=ja4proxy.local"
        
        openssl x509 -req -days 365 -in "${ssl_dir}/proxy.csr" \
            -CA "${ssl_dir}/ca.crt" -CAkey "${ssl_dir}/ca.key" \
            -CAcreateserial -out "${ssl_dir}/proxy.crt"
        
        # Create combined certificate for HAProxy
        cat "${ssl_dir}/proxy.crt" "${ssl_dir}/proxy.key" > "${ssl_dir}/proxy.pem"
        
        # Set permissions
        chmod 600 "${ssl_dir}"/*.key "${ssl_dir}"/*.pem
        chmod 644 "${ssl_dir}"/*.crt
        chown -R ja4proxy:ja4proxy "${ssl_dir}"
        
        log_info "SSL certificates generated"
    else
        log_info "SSL certificates already exist"
    fi
}

# Setup secrets
setup_secrets() {
    log_info "Setting up secrets..."
    
    local secrets_dir="${CONFIG_DIR}/secrets"
    
    # Generate Redis password if not exists
    if [[ ! -f "${secrets_dir}/redis_password.txt" ]]; then
        openssl rand -base64 32 > "${secrets_dir}/redis_password.txt"
        log_info "Generated Redis password"
    fi
    
    # Generate Grafana admin password if not exists
    if [[ ! -f "${secrets_dir}/grafana_password.txt" ]]; then
        openssl rand -base64 16 > "${secrets_dir}/grafana_password.txt"
        log_info "Generated Grafana admin password"
    fi
    
    # Generate Elastic password if not exists
    if [[ ! -f "${secrets_dir}/elastic_password.txt" ]]; then
        openssl rand -base64 16 > "${secrets_dir}/elastic_password.txt"
        log_info "Generated Elasticsearch password"
    fi
    
    # Set permissions
    chmod 600 "${secrets_dir}"/*
    chown ja4proxy:ja4proxy "${secrets_dir}"/*
}

# Deploy configuration
deploy_config() {
    log_info "Deploying configuration for environment: ${ENVIRONMENT}"
    
    if [[ -f "config/${ENVIRONMENT}.yml" ]]; then
        cp "config/${ENVIRONMENT}.yml" "${CONFIG_DIR}/config/proxy.yml"
        chown ja4proxy:ja4proxy "${CONFIG_DIR}/config/proxy.yml"
        chmod 640 "${CONFIG_DIR}/config/proxy.yml"
        log_info "Configuration deployed"
    else
        log_error "Configuration file config/${ENVIRONMENT}.yml not found"
        exit 1
    fi
    
    # Copy monitoring configurations
    if [[ -d "monitoring" ]]; then
        cp -r monitoring "${CONFIG_DIR}/"
        chown -R ja4proxy:ja4proxy "${CONFIG_DIR}/monitoring"
        log_info "Monitoring configuration deployed"
    fi
}

# Setup firewall
setup_firewall() {
    log_info "Configuring firewall..."
    
    if command -v firewall-cmd &> /dev/null; then
        # FirewallD configuration
        firewall-cmd --permanent --new-zone=ja4proxy 2>/dev/null || true
        firewall-cmd --permanent --zone=ja4proxy --add-port=80/tcp
        firewall-cmd --permanent --zone=ja4proxy --add-port=443/tcp
        firewall-cmd --permanent --zone=ja4proxy --add-port=8080/tcp
        firewall-cmd --permanent --zone=ja4proxy --add-port=9090/tcp
        firewall-cmd --reload
        log_info "FirewallD configured"
    elif command -v ufw &> /dev/null; then
        # UFW configuration
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw allow 8080/tcp
        ufw allow 9090/tcp
        log_info "UFW configured"
    else
        log_warn "No supported firewall found. Please configure manually."
    fi
}

# Deploy application
deploy_application() {
    log_info "Deploying JA4 Proxy version ${VERSION}..."
    
    # Set environment variables
    export REDIS_PASSWORD=$(cat "${CONFIG_DIR}/secrets/redis_password.txt")
    export GRAFANA_PASSWORD=$(cat "${CONFIG_DIR}/secrets/grafana_password.txt")
    export ELASTIC_PASSWORD=$(cat "${CONFIG_DIR}/secrets/elastic_password.txt")
    export GRAFANA_SECRET_KEY=$(openssl rand -base64 32)
    
    # Pull latest images
    docker-compose -f "docker-compose.${ENVIRONMENT}.yml" pull
    
    # Start services
    docker-compose -f "docker-compose.${ENVIRONMENT}.yml" up -d
    
    log_info "Application deployment initiated"
}

# Health checks
run_health_checks() {
    log_info "Running health checks..."
    
    local max_attempts=30
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        attempt=$((attempt + 1))
        
        # Check proxy health
        if curl -sf http://localhost:8080/health &>/dev/null; then
            log_info "✓ Proxy health check passed"
            break
        elif [[ $attempt -eq $max_attempts ]]; then
            log_error "✗ Proxy health check failed after ${max_attempts} attempts"
            return 1
        else
            log_info "Waiting for proxy to be ready... (attempt ${attempt}/${max_attempts})"
            sleep 10
        fi
    done
    
    # Check metrics endpoint
    if curl -sf http://localhost:9090/metrics | grep -q "ja4_requests_total"; then
        log_info "✓ Metrics endpoint check passed"
    else
        log_error "✗ Metrics endpoint check failed"
        return 1
    fi
    
    # Check Redis connectivity
    if docker exec ja4proxy-redis-1 redis-cli ping 2>/dev/null | grep -q "PONG"; then
        log_info "✓ Redis connectivity check passed"
    else
        log_error "✗ Redis connectivity check failed"
        return 1
    fi
    
    log_info "All health checks passed"
}

# Setup monitoring
setup_monitoring() {
    log_info "Setting up monitoring..."
    
    # Wait for Grafana to be ready
    sleep 30
    
    # Import Grafana dashboards
    if [[ -d "monitoring/grafana/dashboards" ]]; then
        for dashboard in monitoring/grafana/dashboards/*.json; do
            if [[ -f "$dashboard" ]]; then
                curl -X POST \
                    -H "Content-Type: application/json" \
                    -u "admin:${GRAFANA_PASSWORD}" \
                    -d @"$dashboard" \
                    http://localhost:3000/api/dashboards/db 2>/dev/null || true
            fi
        done
        log_info "Grafana dashboards imported"
    fi
}

# Setup systemd service for auto-start
setup_systemd() {
    log_info "Setting up systemd service..."
    
    cat > /etc/systemd/system/ja4proxy.service << EOF
[Unit]
Description=JA4 Proxy Service
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/docker-compose -f docker-compose.${ENVIRONMENT}.yml up -d
ExecStop=/usr/bin/docker-compose -f docker-compose.${ENVIRONMENT}.yml down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ja4proxy.service
    
    log_info "Systemd service configured"
}

# Setup log rotation
setup_log_rotation() {
    log_info "Setting up log rotation..."
    
    cat > /etc/logrotate.d/ja4proxy << EOF
${LOG_DIR}/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su ja4proxy ja4proxy
}
EOF

    log_info "Log rotation configured"
}

# Setup backup cron job
setup_backup() {
    log_info "Setting up backup cron job..."
    
    # Create backup script
    cat > /usr/local/bin/ja4proxy-backup.sh << 'EOF'
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/backup/ja4proxy"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "${BACKUP_DIR}/${DATE}"

# Backup Redis data
docker exec ja4proxy-redis-1 redis-cli BGSAVE || exit 1
sleep 5
docker cp ja4proxy-redis-1:/data/dump.rdb "${BACKUP_DIR}/${DATE}/" || exit 1

# Backup configuration
cp -r /opt/ja4proxy/config "${BACKUP_DIR}/${DATE}/"

# Create archive
cd "${BACKUP_DIR}"
tar -czf "ja4proxy_backup_${DATE}.tar.gz" "${DATE}/"
rm -rf "${DATE}"

# Cleanup old backups (keep 7 days)
find "${BACKUP_DIR}" -name "ja4proxy_backup_*.tar.gz" -mtime +7 -delete

logger "JA4 Proxy backup completed: ja4proxy_backup_${DATE}.tar.gz"
EOF

    chmod +x /usr/local/bin/ja4proxy-backup.sh
    
    # Add to crontab (daily at 2 AM)
    (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/ja4proxy-backup.sh") | crontab -
    
    log_info "Backup cron job configured"
}

# Print summary
print_summary() {
    log_info "Deployment Summary"
    echo "===================="
    echo "Environment: ${ENVIRONMENT}"
    echo "Version: ${VERSION}"
    echo "Configuration: ${CONFIG_DIR}"
    echo "Logs: ${LOG_DIR}"
    echo ""
    echo "Services:"
    echo "- Proxy: http://localhost:8080"
    echo "- Metrics: http://localhost:9090"
    echo "- Grafana: http://localhost:3000 (admin/$(cat ${CONFIG_DIR}/secrets/grafana_password.txt))"
    echo "- Kibana: http://localhost:5601"
    echo "- HAProxy Stats: http://localhost:8404/stats"
    echo ""
    echo "Management Commands:"
    echo "- View logs: docker-compose -f docker-compose.${ENVIRONMENT}.yml logs -f"
    echo "- Restart: systemctl restart ja4proxy"
    echo "- Status: systemctl status ja4proxy"
    echo ""
    log_info "Deployment completed successfully!"
}

# Main execution
main() {
    log_info "Starting JA4 Proxy enterprise deployment..."
    
    check_prerequisites
    setup_directories
    setup_ssl
    setup_secrets
    deploy_config
    setup_firewall
    deploy_application
    run_health_checks
    setup_monitoring
    setup_systemd
    setup_log_rotation
    setup_backup
    print_summary
}

# Script help
show_help() {
    echo "Usage: $0 [ENVIRONMENT] [VERSION]"
    echo ""
    echo "Arguments:"
    echo "  ENVIRONMENT    Deployment environment (default: production)"
    echo "  VERSION        Docker image version (default: latest)"
    echo ""
    echo "Examples:"
    echo "  $0 production v1.0.0"
    echo "  $0 staging latest"
    echo ""
    echo "This script will:"
    echo "  - Check prerequisites"
    echo "  - Setup directories and permissions"
    echo "  - Generate SSL certificates"
    echo "  - Setup secrets"
    echo "  - Deploy configuration"
    echo "  - Configure firewall"
    echo "  - Deploy application"
    echo "  - Run health checks"
    echo "  - Setup monitoring"
    echo "  - Configure systemd service"
    echo "  - Setup log rotation"
    echo "  - Setup backup cron job"
}

# Check for help flag
if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
    show_help
    exit 0
fi

# Run main function
main "$@"