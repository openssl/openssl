#!/usr/bin/env bash
#
# build-dsllvm-world.sh - Build OpenSSL with DSLLVM (World/Portable variant)
#
# This script builds the WORLD_COMPAT variant of DSMIL-grade OpenSSL.
# This build is portable (x86-64-v3) and suitable for internet-facing services.
#
# Usage:
#   ./util/build-dsllvm-world.sh [options]
#
# Options:
#   --clean         Clean before building
#   --test          Run test suite after build
#   --install       Install after successful build (requires sudo)
#   --prefix=PATH   Installation prefix (default: /opt/openssl-world)
#   --help          Show this help
#
# See: OPENSSL_SECURE_SPEC.md

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
CLEAN=0
TEST=0
INSTALL=0
PREFIX="/opt/openssl-world"
OPENSSLDIR="/opt/openssl-world/ssl"
BUILD_JOBS=$(nproc)

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN=1
            shift
            ;;
        --test)
            TEST=1
            shift
            ;;
        --install)
            INSTALL=1
            shift
            ;;
        --prefix=*)
            PREFIX="${1#*=}"
            OPENSSLDIR="${PREFIX}/ssl"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--clean] [--test] [--install] [--prefix=PATH] [--help]"
            echo ""
            echo "Build DSMIL-grade OpenSSL (WORLD_COMPAT variant) with DSLLVM"
            echo ""
            echo "Options:"
            echo "  --clean         Clean before building"
            echo "  --test          Run test suite after build"
            echo "  --install       Install after successful build (requires sudo)"
            echo "  --prefix=PATH   Installation prefix (default: /opt/openssl-world)"
            echo "  --help          Show this help"
            echo ""
            echo "Example:"
            echo "  $0 --clean --test --prefix=/opt/openssl-world"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}DSLLVM World Build (WORLD_COMPAT)${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check for dsclang compiler
if ! command -v dsclang &> /dev/null; then
    echo -e "${YELLOW}Warning: 'dsclang' not found in PATH${NC}"
    echo -e "${YELLOW}Checking for standard clang...${NC}"

    if ! command -v clang &> /dev/null; then
        echo -e "${RED}Error: Neither 'dsclang' nor 'clang' found${NC}"
        echo -e "${RED}Please install DSLLVM or create a symlink:${NC}"
        echo -e "${RED}  sudo ln -s \$(which clang) /usr/local/bin/dsclang${NC}"
        exit 1
    fi

    echo -e "${YELLOW}Using clang as fallback for dsclang${NC}"
    echo -e "${YELLOW}For production builds, use DSLLVM with CSNA 2.0${NC}"

    # Create temporary symlinks
    mkdir -p /tmp/dsllvm-bin
    ln -sf "$(which clang)" /tmp/dsllvm-bin/dsclang
    ln -sf "$(which clang++)" /tmp/dsllvm-bin/dsclang++
    export PATH="/tmp/dsllvm-bin:$PATH"
fi

# Display compiler version
echo -e "${GREEN}Compiler version:${NC}"
dsclang --version | head -1
echo ""

# Clean if requested
if [ $CLEAN -eq 1 ]; then
    echo -e "${YELLOW}Cleaning build directory...${NC}"
    if [ -f "Makefile" ]; then
        make distclean || true
    fi
    echo -e "${GREEN}✓ Clean complete${NC}"
    echo ""
fi

# Configure
echo -e "${BLUE}Configuring OpenSSL (dsllvm-world)...${NC}"
echo -e "${GREEN}  Prefix:     ${PREFIX}${NC}"
echo -e "${GREEN}  OpenSSL Dir: ${OPENSSLDIR}${NC}"
echo -e "${GREEN}  Build Jobs: ${BUILD_JOBS}${NC}"
echo ""

./Configure dsllvm-world \
    --prefix="${PREFIX}" \
    --openssldir="${OPENSSLDIR}" \
    enable-ec_nistp_64_gcc_128 \
    no-ssl3 \
    no-weak-ssl-ciphers \
    enable-tls1_3 \
    no-comp \
    --with-rand-seed=rdcpu,rdseed,devrandom \
    threads \
    shared

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Configure failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Configure complete${NC}"
echo ""

# Build
echo -e "${BLUE}Building OpenSSL...${NC}"
make -j${BUILD_JOBS}

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Build complete${NC}"
echo ""

# Test if requested
if [ $TEST -eq 1 ]; then
    echo -e "${BLUE}Running test suite...${NC}"
    make test

    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ Tests failed${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ All tests passed${NC}"
    echo ""
fi

# Install if requested
if [ $INSTALL -eq 1 ]; then
    echo -e "${BLUE}Installing OpenSSL to ${PREFIX}...${NC}"

    if [ ! -w "$(dirname ${PREFIX})" ]; then
        echo -e "${YELLOW}Installation requires sudo${NC}"
        sudo make install
    else
        make install
    fi

    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ Installation failed${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ Installation complete${NC}"
    echo ""

    # Display installation info
    echo -e "${GREEN}Installation successful!${NC}"
    echo -e "${GREEN}  Binary:   ${PREFIX}/bin/openssl${NC}"
    echo -e "${GREEN}  Library:  ${PREFIX}/lib64/libssl.so${NC}"
    echo -e "${GREEN}  Config:   ${OPENSSLDIR}/openssl.cnf${NC}"
    echo ""
    echo -e "${YELLOW}To use this build:${NC}"
    echo -e "${YELLOW}  export PATH=${PREFIX}/bin:\$PATH${NC}"
    echo -e "${YELLOW}  export LD_LIBRARY_PATH=${PREFIX}/lib64:\$LD_LIBRARY_PATH${NC}"
    echo -e "${YELLOW}  export OPENSSL_CONF=${OPENSSLDIR}/world.cnf${NC}"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}DSLLVM World Build Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}Build Summary:${NC}"
echo -e "  Target:      dsllvm-world"
echo -e "  Profile:     WORLD_COMPAT (portable, internet-compatible)"
echo -e "  Arch:        x86-64-v3"
echo -e "  Compiler:    $(dsclang --version | head -1)"
echo -e "  Prefix:      ${PREFIX}"
echo -e "  PQC:         Opportunistic (ML-KEM, ML-DSA available)"
echo ""

if [ $INSTALL -ne 1 ]; then
    echo -e "${YELLOW}To install, run:${NC}"
    echo -e "${YELLOW}  sudo make install${NC}"
    echo -e "${YELLOW}Or re-run with --install flag${NC}"
fi

exit 0
