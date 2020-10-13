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
