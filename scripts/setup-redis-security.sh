#!/bin/bash
# Setup script for Redis security (TLS + Secrets)
# Run this once to generate all required certificates and secrets

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Redis Security Setup for JA4proxy${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Directories
SSL_DIR="./ssl/redis"
SECRETS_DIR="./secrets"

# Create directories
mkdir -p "$SSL_DIR"
mkdir -p "$SECRETS_DIR"

# Step 1: Generate passwords
echo -e "${GREEN}▶ Step 1: Generating strong passwords...${NC}"

if [ ! -f "$SECRETS_DIR/redis_password.txt" ]; then
    openssl rand -base64 32 > "$SECRETS_DIR/redis_password.txt"
    echo -e "${GREEN}✓ Generated redis_password.txt${NC}"
else
    echo -e "${YELLOW}⚠ redis_password.txt already exists, skipping${NC}"
fi

if [ ! -f "$SECRETS_DIR/redis_admin_password.txt" ]; then
    openssl rand -base64 32 > "$SECRETS_DIR/redis_admin_password.txt"
    echo -e "${GREEN}✓ Generated redis_admin_password.txt${NC}"
else
    echo -e "${YELLOW}⚠ redis_admin_password.txt already exists, skipping${NC}"
fi

if [ ! -f "$SECRETS_DIR/redis_monitor_password.txt" ]; then
    openssl rand -base64 32 > "$SECRETS_DIR/redis_monitor_password.txt"
    echo -e "${GREEN}✓ Generated redis_monitor_password.txt${NC}"
else
    echo -e "${YELLOW}⚠ redis_monitor_password.txt already exists, skipping${NC}"
fi

if [ ! -f "$SECRETS_DIR/redis_backup_password.txt" ]; then
    openssl rand -base64 32 > "$SECRETS_DIR/redis_backup_password.txt"
    echo -e "${GREEN}✓ Generated redis_backup_password.txt${NC}"
else
    echo -e "${YELLOW}⚠ redis_backup_password.txt already exists, skipping${NC}"
fi

# Set permissions
chmod 600 "$SECRETS_DIR"/*.txt
echo -e "${GREEN}✓ Set secure permissions on passwords${NC}"

# Step 2: Generate TLS certificates
echo ""
echo -e "${GREEN}▶ Step 2: Generating TLS certificates...${NC}"

if [ ! -f "$SSL_DIR/ca.key" ]; then
    # Generate CA
    openssl genrsa -out "$SSL_DIR/ca.key" 4096
    openssl req -new -x509 -days 3650 -key "$SSL_DIR/ca.key" \
        -out "$SSL_DIR/ca.crt" \
        -subj "/C=US/ST=California/L=San Francisco/O=JA4proxy/OU=Security/CN=JA4proxy Redis CA"
    echo -e "${GREEN}✓ Generated Certificate Authority (CA)${NC}"
else
    echo -e "${YELLOW}⚠ CA already exists, skipping${NC}"
fi

if [ ! -f "$SSL_DIR/redis.key" ]; then
    # Generate Redis server certificate
    openssl genrsa -out "$SSL_DIR/redis.key" 4096
    openssl req -new -key "$SSL_DIR/redis.key" \
        -out "$SSL_DIR/redis.csr" \
        -subj "/C=US/ST=California/L=San Francisco/O=JA4proxy/OU=Security/CN=redis"
    
    # Create extensions file for SAN
    cat > "$SSL_DIR/redis.ext" << EOF
subjectAltName = DNS:redis,DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF
    
    openssl x509 -req -days 365 -in "$SSL_DIR/redis.csr" \
        -CA "$SSL_DIR/ca.crt" -CAkey "$SSL_DIR/ca.key" \
        -CAcreateserial -out "$SSL_DIR/redis.crt" \
        -extfile "$SSL_DIR/redis.ext"
    
    rm "$SSL_DIR/redis.csr" "$SSL_DIR/redis.ext"
    echo -e "${GREEN}✓ Generated Redis server certificate${NC}"
else
    echo -e "${YELLOW}⚠ Redis certificate already exists, skipping${NC}"
fi

if [ ! -f "$SSL_DIR/client.key" ]; then
    # Generate client certificate
    openssl genrsa -out "$SSL_DIR/client.key" 4096
    openssl req -new -key "$SSL_DIR/client.key" \
        -out "$SSL_DIR/client.csr" \
        -subj "/C=US/ST=California/L=San Francisco/O=JA4proxy/OU=Security/CN=proxy"
    
    # Create extensions file for client
    cat > "$SSL_DIR/client.ext" << EOF
extendedKeyUsage = clientAuth
EOF
    
    openssl x509 -req -days 365 -in "$SSL_DIR/client.csr" \
        -CA "$SSL_DIR/ca.crt" -CAkey "$SSL_DIR/ca.key" \
        -CAcreateserial -out "$SSL_DIR/client.crt" \
        -extfile "$SSL_DIR/client.ext"
    
    rm "$SSL_DIR/client.csr" "$SSL_DIR/client.ext"
    echo -e "${GREEN}✓ Generated client certificate${NC}"
else
    echo -e "${YELLOW}⚠ Client certificate already exists, skipping${NC}"
fi

# Set permissions on certificates
chmod 600 "$SSL_DIR"/*.key
chmod 644 "$SSL_DIR"/*.crt
echo -e "${GREEN}✓ Set secure permissions on certificates${NC}"

# Step 3: Generate ACL file with password hashes
echo ""
echo -e "${GREEN}▶ Step 3: Generating Redis ACL configuration...${NC}"

# Read passwords
APP_PASSWORD=$(cat "$SECRETS_DIR/redis_password.txt")
ADMIN_PASSWORD=$(cat "$SECRETS_DIR/redis_admin_password.txt")
MONITOR_PASSWORD=$(cat "$SECRETS_DIR/redis_monitor_password.txt")
BACKUP_PASSWORD=$(cat "$SECRETS_DIR/redis_backup_password.txt")

# Generate ACL file (passwords will be hashed by Redis on load)
cat > "$SECRETS_DIR/users.acl" << EOF
# Redis ACL Configuration for JA4proxy - Generated $(date)

user default off nopass nocommands

user admin on >$ADMIN_PASSWORD ~* &* +@all

user ja4proxy on >$APP_PASSWORD ~ja4:* ~rate:* ~enforcement:* ~stats:* ~gdpr:* &* +@read +@write +@set +@sortedset +@string +@hash +@geo +@hyperloglog +ping +echo +select +info -@dangerous -@admin -@slow

user monitor on >$MONITOR_PASSWORD ~* &* +@read +ping +info +client|list +client|info +cluster|info +config|get +slowlog|get +latency +memory

user backup on >$BACKUP_PASSWORD ~* &* +bgsave +lastsave +info +select +scan -@write -@dangerous
EOF

chmod 600 "$SECRETS_DIR/users.acl"
echo -e "${GREEN}✓ Generated ACL configuration${NC}"

# Step 4: Verify certificates
echo ""
echo -e "${GREEN}▶ Step 4: Verifying certificates...${NC}"

# Verify CA
if openssl x509 -in "$SSL_DIR/ca.crt" -noout -text > /dev/null 2>&1; then
    echo -e "${GREEN}✓ CA certificate is valid${NC}"
else
    echo -e "${RED}✗ CA certificate is invalid${NC}"
    exit 1
fi

# Verify Redis cert
if openssl verify -CAfile "$SSL_DIR/ca.crt" "$SSL_DIR/redis.crt" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Redis certificate is valid${NC}"
else
    echo -e "${RED}✗ Redis certificate is invalid${NC}"
    exit 1
fi

# Verify client cert
if openssl verify -CAfile "$SSL_DIR/ca.crt" "$SSL_DIR/client.crt" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Client certificate is valid${NC}"
else
    echo -e "${RED}✗ Client certificate is invalid${NC}"
    exit 1
fi

# Step 5: Create summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✓ Redis Security Setup Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${BLUE}Generated Files:${NC}"
echo ""
echo -e "${YELLOW}Passwords (secrets/):${NC}"
echo "  - redis_password.txt (app user)"
echo "  - redis_admin_password.txt (admin user)"
echo "  - redis_monitor_password.txt (monitoring)"
echo "  - redis_backup_password.txt (backup)"
echo "  - users.acl (ACL configuration)"
echo ""
echo -e "${YELLOW}Certificates (ssl/redis/):${NC}"
echo "  - ca.crt (Certificate Authority)"
echo "  - redis.crt, redis.key (Redis server)"
echo "  - client.crt, client.key (Client/Proxy)"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Review generated passwords in secrets/"
echo "  2. Deploy with: docker compose -f docker-compose.prod.yml up -d"
echo "  3. Test connection: ./scripts/test-redis-tls.sh"
echo "  4. Backup secrets/ directory securely!"
echo ""
echo -e "${RED}⚠ IMPORTANT: Keep secrets/ directory secure!${NC}"
echo -e "${RED}⚠ Add secrets/ to .gitignore${NC}"
echo -e "${RED}⚠ Never commit passwords to version control${NC}"
echo ""

# Add to .gitignore
if ! grep -q "secrets/" .gitignore 2>/dev/null; then
    echo "secrets/" >> .gitignore
    echo -e "${GREEN}✓ Added secrets/ to .gitignore${NC}"
fi

if ! grep -q "ssl/" .gitignore 2>/dev/null; then
    echo "ssl/" >> .gitignore
    echo -e "${GREEN}✓ Added ssl/ to .gitignore${NC}"
fi

echo ""
echo -e "${GREEN}Setup complete! Certificates valid for 365 days.${NC}"
echo -e "${YELLOW}Set calendar reminder to renew certificates in 11 months.${NC}"
echo ""
