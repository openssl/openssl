#!/bin/bash

# Script pour générer les certificats dual pour tester TLS Dual Chain
# Ce script crée les certificats nécessaires pour tester l'approche dual chain

set -e  # Exit on any error

# Variables d'environnement pour utiliser OpenSSL 3.3.0 + OQS provider
export LD_LIBRARY_PATH="$(cd $(dirname "$0") && pwd):$LD_LIBRARY_PATH"
export OPENSSL_MODULES="$(cd $(dirname "$0") && pwd)/providers"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Set absolute path to the modified OpenSSL binary
OPENSSL_BIN="$(cd $(dirname "$0") && pwd)/apps/openssl"

# Function to check OpenSSL version and OQS support
check_openssl() {
    print_status "Checking OpenSSL installation..."
    
    if [ ! -f "$OPENSSL_BIN" ]; then
        print_error "Modified OpenSSL binary not found at $OPENSSL_BIN"
        print_error "Please build OpenSSL first with 'make'"
        exit 1
    fi
    
    if ! $OPENSSL_BIN version &>/dev/null; then
        print_error "Modified OpenSSL is not executable"
        exit 1
    fi
    
    OPENSSL_VERSION=$($OPENSSL_BIN version | awk '{print $2}')
    print_status "Modified OpenSSL version: $OPENSSL_VERSION"
    
    # Check if OQS provider is available
    if ! $OPENSSL_BIN list -providers 2>/dev/null | grep -q "oqs"; then
        print_warning "OQS provider not found. Falcon512 may not be available."
        print_warning "Make sure OpenSSL is compiled with OQS support."
    else
        print_success "OQS provider found"
    fi
}

# Function to create test directory
setup_test_env() {
    print_status "Setting up test environment..."
    
    TEST_DIR="test_dual_tls"
    if [ -d "$TEST_DIR" ]; then
        print_warning "Test directory already exists. Removing old files..."
        rm -rf "$TEST_DIR"
    fi
    
    mkdir -p "$TEST_DIR"
    cd "$TEST_DIR"
    print_success "Test directory created: $(pwd)"
}

# Function to generate CA infrastructure
generate_ca() {
    print_status "Generating CA infrastructure..."
    
    # Generate CA private key (RSA)
    $OPENSSL_BIN genpkey -algorithm RSA -out ca_key.pem -aes256 -pass pass:testpass
    
    # Create CA certificate
    $OPENSSL_BIN req -new -x509 -key ca_key.pem -out ca_cert.pem -days 365 \
        -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=TestCA" \
        -passin pass:testpass
    
    print_success "CA infrastructure generated (RSA)"

    # Generate Falcon512 CA key and certificate
    print_status "Generating Falcon512 CA infrastructure..."
    $OPENSSL_BIN genpkey -algorithm falcon512 -out ca_pq_key.pem
    $OPENSSL_BIN req -new -x509 -key ca_pq_key.pem -out ca_pq_cert.pem -days 365 \
        -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=TestCA-Falcon512"
    print_success "CA infrastructure generated (Falcon512)"
}

# Function to generate server certificates (RSA + PQ)
generate_server_certs() {
    print_status "Generating server certificates..."
    
    # Generate RSA server key and certificate
    print_status "Generating RSA server certificate..."
    $OPENSSL_BIN genpkey -algorithm RSA -out server_rsa_key.pem
    $OPENSSL_BIN req -new -key server_rsa_key.pem -out server_rsa_req.pem \
        -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=server.example.com"
    $OPENSSL_BIN x509 -req -in server_rsa_req.pem -CA ca_cert.pem -CAkey ca_key.pem \
        -CAcreateserial -out server_rsa_cert.pem -days 365 \
        -passin pass:testpass
    
    # Generate PQ server key and certificate (Falcon512)
    print_status "Generating PQ server certificate (Falcon512)..."
    if ! $OPENSSL_BIN genpkey -algorithm falcon512 -out server_pq_key.pem 2>/dev/null; then
        print_warning "Falcon512 not available, using RSA as fallback..."
        $OPENSSL_BIN genpkey -algorithm RSA -out server_pq_key.pem
    fi
    
    $OPENSSL_BIN req -new -key server_pq_key.pem -out server_pq_req.pem \
        -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=server.example.com"
    
    # Sign PQC server cert with Falcon512 CA
    $OPENSSL_BIN x509 -req -in server_pq_req.pem -CA ca_pq_cert.pem -CAkey ca_pq_key.pem \
        -CAcreateserial -out server_pq_cert.pem -days 365
    
    print_success "Server certificates generated"
}

# Function to generate client certificates (RSA + PQ)
generate_client_certs() {
    print_status "Generating client certificates..."
    
    # Generate RSA client key and certificate
    print_status "Generating RSA client certificate..."
    $OPENSSL_BIN genpkey -algorithm RSA -out client_rsa_key.pem
    $OPENSSL_BIN req -new -key client_rsa_key.pem -out client_rsa_req.pem \
        -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=client.example.com"
    $OPENSSL_BIN x509 -req -in client_rsa_req.pem -CA ca_cert.pem -CAkey ca_key.pem \
        -CAcreateserial -out client_rsa_cert.pem -days 365 \
        -passin pass:testpass
    
    # Generate PQ client key and certificate (Falcon512)
    print_status "Generating PQ client certificate (Falcon512)..."
    if ! $OPENSSL_BIN genpkey -algorithm falcon512 -out client_pq_key.pem 2>/dev/null; then
        print_warning "Falcon512 not available, using RSA as fallback..."
        $OPENSSL_BIN genpkey -algorithm RSA -out client_pq_key.pem
    fi
    
    $OPENSSL_BIN req -new -key client_pq_key.pem -out client_pq_req.pem \
        -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=client.example.com"
    
    # Sign PQC client cert with Falcon512 CA
    $OPENSSL_BIN x509 -req -in client_pq_req.pem -CA ca_pq_cert.pem -CAkey ca_pq_key.pem \
        -CAcreateserial -out client_pq_cert.pem -days 365
    
    print_success "Client certificates generated"
}

# Function to verify certificates
verify_certificates() {
    print_status "Verifying certificates..."
    
    echo ""
    print_status "=== Server Certificate Verification ==="
    if $OPENSSL_BIN verify -CAfile ca_cert.pem server_rsa_cert.pem 2>/dev/null; then
        print_success "RSA server certificate verified"
    else
        print_error "RSA server certificate verification failed"
    fi
    
    if $OPENSSL_BIN verify -CAfile ca_cert.pem server_pq_cert.pem 2>/dev/null; then
        print_success "PQ server certificate verified"
    else
        print_error "PQ server certificate verification failed"
    fi
    
    echo ""
    print_status "=== Client Certificate Verification ==="
    if $OPENSSL_BIN verify -CAfile ca_cert.pem client_rsa_cert.pem 2>/dev/null; then
        print_success "RSA client certificate verified"
    else
        print_error "RSA client certificate verification failed"
    fi
    
    if $OPENSSL_BIN verify -CAfile ca_cert.pem client_pq_cert.pem 2>/dev/null; then
        print_success "PQ client certificate verified"
    else
        print_error "PQ client certificate verification failed"
    fi
}

# Function to display file information
show_file_info() {
    print_status "Generated files:"
    echo "  - ca_key.pem: CA private key (RSA, encrypted)"
    echo "  - ca_cert.pem: CA certificate"
    echo "  - server_rsa_key.pem: Server RSA private key"
    echo "  - server_rsa_cert.pem: Server RSA certificate"
    echo "  - server_pq_key.pem: Server PQ private key (Falcon512/RSA)"
    echo "  - server_pq_cert.pem: Server PQ certificate"
    echo "  - client_rsa_key.pem: Client RSA private key"
    echo "  - client_rsa_cert.pem: Client RSA certificate"
    echo "  - client_pq_key.pem: Client PQ private key (Falcon512/RSA)"
    echo "  - client_pq_cert.pem: Client PQ certificate"
    echo ""
    print_status "File sizes:"
    ls -lh *.pem
}

# Function to show test commands
show_test_commands() {
    echo ""
    print_status "=== Test Commands ==="
    echo ""
    echo "To test the dual certificate handshake, use these commands:"
    echo ""
    echo "1. Start the server:"
    echo "   $OPENSSL_BIN s_server \\"
    echo "       -accept 8443 \\"
    echo "       -cert server_rsa_cert.pem \\"
    echo "       -key server_rsa_key.pem \\"
    echo "       -pqcert server_pq_cert.pem \\"
    echo "       -pqkey server_pq_key.pem \\"
    echo "       -CAfile ca_cert.pem \\"
    echo "       -enable_dual_certs \\"
    echo "       -msg"
    echo ""
    echo "2. In another terminal, connect with the client:"
    echo "   $OPENSSL_BIN s_client \\"
    echo "       -connect localhost:8443 \\"
    echo "       -cert client_rsa_cert.pem \\"
    echo "       -key client_rsa_key.pem \\"
    echo "       -pqcert client_pq_cert.pem \\"
    echo "       -pqkey client_pq_key.pem \\"
    echo "       -CAfile ca_cert.pem \\"
    echo "       -enable_dual_certs \\"
    echo "       -msg \\"
    echo "       -showcerts"
    echo ""
}

# Main execution
main() {
    echo "=========================================="
    echo "Dual Certificate Generation Script"
    echo "=========================================="
    echo ""
    
    # Check prerequisites
    check_openssl
    
    # Setup and run tests
    setup_test_env
    generate_ca
    generate_server_certs
    generate_client_certs
    verify_certificates
    show_file_info
    show_test_commands
    
    echo ""
    print_success "Certificate generation completed successfully!"
    print_status "Test files are located in: $(pwd)"
    echo ""
    print_status "To clean up test files, run: rm -rf $TEST_DIR"
}

# Run main function
main "$@" 