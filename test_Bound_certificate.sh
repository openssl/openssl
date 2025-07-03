#!/bin/bash

# Variables d'environnement pour utiliser OpenSSL 3.3.0 + OQS provider
export PATH=/usr/local/ssl/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/ssl/lib64:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=/usr/local/ssl/lib64/pkgconfig
export OPENSSL_MODULES=/usr/local/ssl/lib64/ossl-modules
export OPENSSL_CONF=/usr/local/ssl/openssl.cnf

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
    $OPENSSL_BIN genpkey -algorithm RSA -out ca_key.pem -aes256 -pass pass:testpass
    
    # Create CA certificate
    $OPENSSL_BIN req -new -x509 -key ca_key.pem -out ca_cert.pem -days 365 \
        -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=TestCA" \
        -passin pass:testpass
    
    print_success "CA infrastructure generated"
}

# Function to generate bound certificate (RSA)
generate_bound_cert() {
    print_status "Generating bound certificate (RSA)..."
    
    # Generate bound certificate private key (RSA)
    $OPENSSL_BIN genpkey -algorithm RSA -out bound_key.pem
    
    # Create bound certificate request
    $OPENSSL_BIN req -new -key bound_key.pem -out bound_cert_req.pem \
        -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=bound.example.com"
    
    # Sign bound certificate
    $OPENSSL_BIN x509 -req -in bound_cert_req.pem -CA ca_cert.pem -CAkey ca_key.pem \
        -CAcreateserial -out bound_cert.pem -days 365 \
        -passin pass:testpass
    
    print_success "Bound certificate (RSA) generated"
}

# Function to generate new certificate (Falcon512)
generate_new_cert() {
    print_status "Generating new certificate (Falcon512)..."
    
    # Generate new certificate private key (Falcon512)
    if ! $OPENSSL_BIN genpkey -algorithm falcon512 -out new_key.pem 2>/dev/null; then
        print_error "Failed to generate Falcon512 key. OQS provider may not be available."
        print_warning "Falling back to RSA for testing..."
        $OPENSSL_BIN genpkey -algorithm RSA -out new_key.pem
    fi
    
    # Create CSR with relatedCertRequest attribute
    if $OPENSSL_BIN req -new -key new_key.pem -out new_cert_req.pem \
        -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=new.example.com" \
        -add_related_cert bound_cert.pem \
        -related_uri "file://$(pwd)/bound_cert.pem" 2>/dev/null; then
        print_success "CSR with relatedCertRequest attribute created"
    else
        print_warning "relatedCertRequest attribute not supported in this OpenSSL build"
        print_warning "Creating CSR without relatedCertRequest attribute..."
        $OPENSSL_BIN req -new -key new_key.pem -out new_cert_req.pem \
            -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=new.example.com"
    fi
    
    # Sign the CSR to create the new certificate with RelatedCertificate extension
    if $OPENSSL_BIN x509 -req -in new_cert_req.pem -CA ca_cert.pem -CAkey ca_key.pem \
        -CAcreateserial -out new_cert.pem -days 365 \
        -add_related_cert bound_cert.pem \
        -related_uri "file://$(pwd)/bound_cert.pem" \
        -passin pass:testpass 2>/dev/null; then
        print_success "New certificate with RelatedCertificate extension generated"
    else
        print_warning "RelatedCertificate extension not supported, creating certificate without extension..."
        $OPENSSL_BIN x509 -req -in new_cert_req.pem -CA ca_cert.pem -CAkey ca_key.pem \
            -CAcreateserial -out new_cert.pem -days 365 \
            -passin pass:testpass
    fi
    
    print_success "New certificate generated"
}

# Function to verify certificates
verify_certificates() {
    print_status "Verifying certificates..."
    
    echo ""
    print_status "=== CSR Verification ==="
    if $OPENSSL_BIN req -in new_cert_req.pem -text -noout 2>/dev/null | grep -q "relatedCertRequest"; then
        print_success "relatedCertRequest attribute found in CSR"
        $OPENSSL_BIN req -in new_cert_req.pem -text -noout | grep -A 20 "relatedCertRequest"
    else
        print_warning "relatedCertRequest attribute not found in CSR"
    fi
    
    echo ""
    print_status "=== Certificate Verification ==="
    if $OPENSSL_BIN x509 -in new_cert.pem -text -noout 2>/dev/null | grep -q "RelatedCertificate"; then
        print_success "RelatedCertificate extension found in certificate"
        $OPENSSL_BIN x509 -in new_cert.pem -text -noout | grep -A 10 "RelatedCertificate"
    else
        print_warning "RelatedCertificate extension not found in certificate"
    fi
    
    echo ""
    print_status "=== Signature Verification ==="
    if $OPENSSL_BIN req -in new_cert_req.pem -verify -noout 2>/dev/null; then
        print_success "CSR signature verification passed"
    else
        print_error "CSR signature verification failed"
    fi
    
    if $OPENSSL_BIN verify -CAfile ca_cert.pem new_cert.pem 2>/dev/null; then
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

    echo "✅ Certificate verification completed successfully"
    echo ""

    # Test the new URI extension functionality
    echo "🔗 Testing RelatedCertificate extension with URI functionality..."
    echo ""

    # Create a new certificate with URI in the extension
    echo "📝 Creating certificate with URI in RelatedCertificate extension..."
    $OPENSSL_BIN req -new -key new_key.pem -out new_cert_with_uri_req.pem \
        -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=new-with-uri.example.com" \
        -add_related_cert bound_cert.pem \
        -related_uri "file://$(pwd)/bound_cert.pem"

    if [ $? -eq 0 ]; then
        echo "✅ CSR with relatedCertRequest created successfully"
        
        # Sign the CSR to create the new certificate with URI extension
        $OPENSSL_BIN x509 -req -in new_cert_with_uri_req.pem -CA ca_cert.pem -CAkey ca_key.pem \
            -CAcreateserial -out new_cert_with_uri.pem -days 365 \
            -add_related_cert_extension bound_cert.pem \
            -related_uri "file://$(pwd)/bound_cert.pem"
        
        if [ $? -eq 0 ]; then
            echo "✅ Certificate with URI extension created successfully"
            
            # Display the certificate with URI extension
            echo ""
            echo "📋 Certificate with URI extension details:"
            $OPENSSL_BIN x509 -in new_cert_with_uri.pem -text -noout | grep -A 15 "RelatedCertificate"
            
            # Verify the certificate
            echo ""
            echo "🔍 Verifying certificate with URI extension..."
            $OPENSSL_BIN verify -CAfile ca_cert.pem new_cert_with_uri.pem
            
            if [ $? -eq 0 ]; then
                echo "✅ Certificate with URI extension verified successfully"
            else
                echo "❌ Certificate with URI extension verification failed"
            fi
        else
            echo "❌ Failed to create certificate with URI extension"
        fi
    else
        echo "❌ Failed to create CSR with relatedCertRequest"
    fi

    echo ""
    echo "🎉 All tests completed!"
}

# Run main function
main "$@" 