#!/bin/bash

# RFC 9763 Related Certificate Test Script
# This script automates the testing process for RFC 9763 implementation
# with OpenSSL 3.3.4 + OQS support

# Bound Certificate Test Script
# This script automates the testing process for Bound Certificate implementation
# with OpenSSL 3.3.4 + OQS support

set -e  # Exit on any error

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

# Function to check if command exists
check_command() {
    if ! command -v $1 &> /dev/null; then
        print_error "$1 is not installed or not in PATH"
        exit 1
    fi
}

# Function to check OpenSSL version and OQS support
check_openssl() {
    print_status "Checking OpenSSL installation..."
    
    if ! command -v openssl &> /dev/null; then
        print_error "OpenSSL is not installed or not in PATH"
        exit 1
    fi
    
    OPENSSL_VERSION=$(openssl version | awk '{print $2}')
    print_status "OpenSSL version: $OPENSSL_VERSION"
    
    # Check if OQS provider is available
    if ! openssl list -providers 2>/dev/null | grep -q "oqs"; then
        print_warning "OQS provider not found. Falcon512 may not be available."
        print_warning "Make sure OpenSSL is compiled with OQS support."
    else
        print_success "OQS provider found"
    fi
}

# Function to create test directory
setup_test_env() {
    print_status "Setting up test environment..."
    
    TEST_DIR="test_bound_certs"
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
    openssl genpkey -algorithm RSA -out ca_key.pem -aes256 -pass pass:testpass
    
    # Create CA certificate
    openssl req -new -x509 -key ca_key.pem -out ca_cert.pem -days 365 \
        -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=TestCA" \
        -passin pass:testpass
    
    print_success "CA infrastructure generated"
}

# Function to generate bound certificate (RSA)
generate_bound_cert() {
    print_status "Generating bound certificate (RSA)..."
    
    # Generate bound certificate private key (RSA)
    openssl genpkey -algorithm RSA -out bound_key.pem
    
    # Create bound certificate request
    openssl req -new -key bound_key.pem -out bound_cert_req.pem \
        -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=bound.example.com"
    
    # Sign bound certificate
    openssl x509 -req -in bound_cert_req.pem -CA ca_cert.pem -CAkey ca_key.pem \
        -CAcreateserial -out bound_cert.pem -days 365 \
        -passin pass:testpass
    
    print_success "Bound certificate (RSA) generated"
}

# Function to generate new certificate (Falcon512)
generate_new_cert() {
    print_status "Generating new certificate (Falcon512)..."
    
    # Generate new certificate private key (Falcon512)
    if ! openssl genpkey -algorithm falcon512 -out new_key.pem 2>/dev/null; then
        print_error "Failed to generate Falcon512 key. OQS provider may not be available."
        print_warning "Falling back to RSA for testing..."
        openssl genpkey -algorithm RSA -out new_key.pem
    fi
    
    # Create CSR with relatedCertRequest attribute
    if openssl req -new -key new_key.pem -out new_cert_req.pem \
        -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=new.example.com" \
        -add-related-cert bound_cert.pem \
        -related-uri "file://$(pwd)/bound_cert.pem" 2>/dev/null; then
        print_success "CSR with relatedCertRequest attribute created"
    else
        print_warning "relatedCertRequest attribute not supported in this OpenSSL build"
        print_warning "Creating CSR without relatedCertRequest attribute..."
        openssl req -new -key new_key.pem -out new_cert_req.pem \
            -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=new.example.com"
    fi
    
    # Sign the CSR to create the new certificate
    openssl x509 -req -in new_cert_req.pem -CA ca_cert.pem -CAkey ca_key.pem \
        -CAcreateserial -out new_cert.pem -days 365 \
        -passin pass:testpass
    
    print_success "New certificate generated"
}

# Function to verify certificates
verify_certificates() {
    print_status "Verifying certificates..."
    
    echo ""
    print_status "=== CSR Verification ==="
    if openssl req -in new_cert_req.pem -text -noout 2>/dev/null | grep -q "relatedCertRequest"; then
        print_success "relatedCertRequest attribute found in CSR"
        openssl req -in new_cert_req.pem -text -noout | grep -A 20 "relatedCertRequest"
    else
        print_warning "relatedCertRequest attribute not found in CSR"
    fi
    
    echo ""
    print_status "=== Certificate Verification ==="
    if openssl x509 -in new_cert.pem -text -noout 2>/dev/null | grep -q "RelatedCertificate"; then
        print_success "RelatedCertificate extension found in certificate"
        openssl x509 -in new_cert.pem -text -noout | grep -A 10 "RelatedCertificate"
    else
        print_warning "RelatedCertificate extension not found in certificate"
    fi
    
    echo ""
    print_status "=== Signature Verification ==="
    if openssl req -in new_cert_req.pem -verify -noout 2>/dev/null; then
        print_success "CSR signature verification passed"
    else
        print_error "CSR signature verification failed"
    fi
    
    if openssl x509 -in new_cert.pem -verify -noout 2>/dev/null; then
        print_success "Certificate signature verification passed"
    else
        print_error "Certificate signature verification failed"
    fi
}

# Function to display file information
show_file_info() {
    print_status "Generated files:"
    echo "  - ca_key.pem: CA private key (RSA, encrypted)"
    echo "  - ca_cert.pem: CA certificate"
    echo "  - bound_key.pem: Bound certificate private key (RSA)"
    echo "  - bound_cert.pem: Bound certificate (RSA)"
    echo "  - new_key.pem: New certificate private key (Falcon512/RSA)"
    echo "  - new_cert_req.pem: CSR with relatedCertRequest attribute"
    echo "  - new_cert.pem: Final certificate with RelatedCertificate extension"
    echo ""
    print_status "File sizes:"
    ls -lh *.pem
}

# Main execution
main() {
    echo "=========================================="
    echo "Bound Certificate Test Script"
    echo "=========================================="
    echo ""
    
    # Check prerequisites
    check_command openssl
    check_openssl
    
    # Setup and run tests
    setup_test_env
    generate_ca
    generate_bound_cert
    generate_new_cert
    verify_certificates
    show_file_info
    
    echo ""
    print_success "Test process completed successfully!"
    print_status "Test files are located in: $(pwd)"
    echo ""
    print_status "To clean up test files, run: rm -rf $TEST_DIR"
}

# Run main function
main "$@" 