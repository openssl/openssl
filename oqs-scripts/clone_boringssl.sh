#!/bin/bash

###########
# Clone OQS-BoringSSL source
#
# Environment variables:
#  - BSSL_REPO: which repo to check out from, default https://github.com/open-quantum-safe/boringssl.git
#  - BSSL_BRANCH: which branch to check out, default master
###########

set -exo pipefail

BSSL_REPO=${BSSL_REPO:-"https://github.com/open-quantum-safe/boringssl.git"}
BSSL_BRANCH=${BSSL_BRANCH:-"master"}

rm -rf boringssl
git clone --depth 1 --branch "${BSSL_BRANCH}" --single-branch "${BSSL_REPO}" boringssl

# The interop tests need to know what is enabled in BoringSSL,
# and this seems to be the least cumbersome way to do so.
cp boringssl/oqs_test/common.py oqs-interop-test/bssl_algorithms.py
