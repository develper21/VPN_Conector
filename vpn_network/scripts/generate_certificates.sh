#!/bin/bash

# VPN Security Project - Certificate Generation Script
# This script generates SSL/TLS certificates for the VPN server and clients

set -e

# Default values
CA_CERT="ca.crt"
CA_KEY="ca.key"
SERVER_CERT="server.crt"
SERVER_KEY="server.key"
CLIENT_CERT="client.crt"
CLIENT_KEY="client.key"
CERT_DAYS=3650
KEY_SIZE=4096
COUNTRY="US"
ORG="VPN Security Project"
OU="VPN"
DOMAIN="vpn.example.com"
OUTPUT_DIR="certificates"
FORCE_OVERWRITE=false

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Print usage information
function show_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --ca-cert FILE     CA certificate file (default: ca.crt)"
    echo "  --ca-key FILE      CA private key file (default: ca.key)"
    echo "  --server-cert FILE Server certificate file (default: server.crt)"
    echo "  --server-key FILE  Server private key file (default: server.key)"
    echo "  --client-cert FILE Client certificate file (default: client.crt)"
    echo "  --client-key FILE  Client private key file (default: client.key)"
    echo "  -d, --days DAYS    Certificate validity in days (default: 3650)"
    echo "  -b, --bits BITS    Key size in bits (default: 4096)"
    echo "  -C, --country C    Country code (default: US)"
    echo "  -O, --org ORG      Organization name (default: VPN Security Project)"
    echo "  -U, --unit UNIT    Organizational Unit (default: VPN)"
    echo "  -D, --domain DOM   Domain name (default: vpn.example.com)"
    echo "  -o, --output DIR   Output directory (default: certificates)"
    echo "  -f, --force        Overwrite existing files without prompt"
    echo "  -h, --help         Show this help message and exit"
    echo ""
    echo "Examples:"
    echo "  $0 --domain myvpn.example.com"
    echo "  $0 --days 730 --bits 2048 --output my_certs"
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --ca-cert)
            CA_CERT="$2"
            shift 2
            ;;
        --ca-key)
            CA_KEY="$2"
            shift 2
            ;;
        --server-cert)
            SERVER_CERT="$2"
            shift 2
            ;;
        --server-key)
            SERVER_KEY="$2"
            shift 2
            ;;
        --client-cert)
            CLIENT_CERT="$2"
            shift 2
            ;;
        --client-key)
            CLIENT_KEY="$2"
            shift 2
            ;;
        -d|--days)
            CERT_DAYS="$2"
            shift 2
            ;;
        -b|--bits)
            KEY_SIZE="$2"
            shift 2
            ;;
        -C|--country)
            COUNTRY="$2"
            shift 2
            ;;
        -O|--org)
            ORG="$2"
            shift 2
            ;;
        -U|--unit)
            OU="$2"
            shift 2
            ;;
        -D|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -f|--force)
            FORCE_OVERWRITE=true
            shift
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            echo "Error: Unknown option $1"
            show_usage
            ;;
    esac
done

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Function to check if file exists and prompt for overwrite
function check_overwrite() {
    local file="$1"
    if [ -f "$file" ] && [ "$FORCE_OVERWRITE" = false ]; then
        read -p "File $file already exists. Overwrite? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Skipping $file"
            return 1
        fi
    fi
    return 0
}

# Generate CA certificate
function generate_ca() {
    local ca_cert="$OUTPUT_DIR/$CA_CERT"
    local ca_key="$OUTPUT_DIR/$CA_KEY"
    
    if ! check_overwrite "$ca_key" || ! check_overwrite "$ca_cert"; then
        return 0
    fi
    
    echo -e "${GREEN}🔑 Generating CA private key...${NC}"
    openssl genrsa -out "$ca_key" $KEY_SIZE
    
    echo -e "${GREEN}📜 Generating CA certificate...${NC}"
    openssl req -x509 -new -nodes -key "$ca_key" -sha256 -days $CERT_DAYS -out "$ca_cert" \
        -subj "/C=$COUNTRY/O=$ORG/OU=$OU/CN=VPN Root CA"
    
    echo -e "${GREEN}✅ CA certificate generated:${NC}"
    echo -e "  Private key: ${YELLOW}$ca_key${NC}"
    echo -e "  Certificate: ${YELLOW}$ca_cert${NC}"
    echo
}

# Generate server certificate
function generate_server_cert() {
    local server_cert="$OUTPUT_DIR/$SERVER_CERT"
    local server_key="$OUTPUT_DIR/$SERVER_KEY"
    local server_csr="$OUTPUT_DIR/server.csr"
    
    if ! check_overwrite "$server_key" || ! check_overwrite "$server_cert"; then
        return 0
    fi
    
    echo -e "${GREEN}🔑 Generating server private key...${NC}"
    openssl genrsa -out "$server_key" $KEY_SIZE
    
    echo -e "${GREEN}📝 Generating server certificate signing request...${NC}"
    openssl req -new -key "$server_key" -out "$server_csr" \
        -subj "/C=$COUNTRY/O=$ORG/OU=$OU/CN=$DOMAIN"
    
    # Create server certificate extensions file
    local extfile="$OUTPUT_DIR/server.ext"
    cat > "$extfile" <<- EOL
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = *.$DOMAIN
IP.1 = 127.0.0.1
EOL
    
    echo -e "${GREEN}📜 Signing server certificate with CA...${NC}"
    openssl x509 -req -in "$server_csr" -CA "$OUTPUT_DIR/$CA_CERT" -CAkey "$OUTPUT_DIR/$CA_KEY" \
        -CAcreateserial -out "$server_cert" -days $CERT_DAYS -sha256 -extfile "$extfile"
    
    # Clean up
    rm -f "$server_csr" "$extfile"
    
    echo -e "${GREEN}✅ Server certificate generated:${NC}"
    echo -e "  Private key: ${YELLOW}$server_key${NC}"
    echo -e "  Certificate: ${YELLOW}$server_cert${NC}"
    echo
}

# Generate client certificate
function generate_client_cert() {
    local client_cert="$OUTPUT_DIR/$CLIENT_CERT"
    local client_key="$OUTPUT_DIR/$CLIENT_KEY"
    local client_csr="$OUTPUT_DIR/client.csr"
    
    if ! check_overwrite "$client_key" || ! check_overwrite "$client_cert"; then
        return 0
    fi
    
    echo -e "${GREEN}🔑 Generating client private key...${NC}"
    openssl genrsa -out "$client_key" $KEY_SIZE
    
    echo -e "${GREEN}📝 Generating client certificate signing request...${NC}"
    openssl req -new -key "$client_key" -out "$client_csr" \
        -subj "/C=$COUNTRY/O=$ORG/OU=$OU/CN=VPN Client"
    
    # Create client certificate extensions file
    local extfile="$OUTPUT_DIR/client.ext"
    cat > "$extfile" <<- EOL
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
extendedKeyUsage = clientAuth
EOL
    
    echo -e "${GREEN}📜 Signing client certificate with CA...${NC}"
    openssl x509 -req -in "$client_csr" -CA "$OUTPUT_DIR/$CA_CERT" -CAkey "$OUTPUT_DIR/$CA_KEY" \
        -CAcreateserial -out "$client_cert" -days $CERT_DAYS -sha256 -extfile "$extfile"
    
    # Clean up
    rm -f "$client_csr" "$extfile"
    
    echo -e "${GREEN}✅ Client certificate generated:${NC}"
    echo -e "  Private key: ${YELLOW}$client_key${NC}"
    echo -e "  Certificate: ${YELLOW}$client_cert${NC}"
    echo
}

# Generate all certificates
generate_ca
generate_server_cert
generate_client_cert

echo -e "${GREEN}✨ All certificates have been generated in ${YELLOW}$OUTPUT_DIR/${NC}"
echo -e "${GREEN}🔐 Don't forget to secure your private keys!${NC}"

# Generate a sample OpenVPN config file
SAMPLE_CONFIG="$OUTPUT_DIR/client.ovpn"
cat > "$SAMPLE_CONFIG" <<- EOL
# OpenVPN Client Configuration
client
dev tun
proto udp
remote $DOMAIN 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
key-direction 1
verb 3

# CA Certificate
<ca>
$(cat "$OUTPUT_DIR/$CA_CERT")
</ca>

# Client Certificate
<cert>
$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "$OUTPUT_DIR/$CLIENT_CERT")
</cert>

# Client Key
<key>
$(cat "$OUTPUT_DIR/$CLIENT_KEY")
</key>

# TLS Auth (if using tls-auth/tls-crypt)
# <tls-auth>
# # Add tls-auth or tls-crypt key here if used
# </tls-auth>
EOL

echo -e "${GREEN}📄 Sample OpenVPN client configuration:${NC} ${YELLOW}$SAMPLE_CONFIG${NC}"
echo -e "${GREEN}🚀 You can now use these certificates to secure your VPN connections.${NC}"
