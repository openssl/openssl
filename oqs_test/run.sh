#!/bin/bash

###########
# Do a full run through of a single liboqs/OpenSSL integration test combination
#
# Environment variables:
#  - ARCH: either x64 (default) or x86
#
# The following environment variables affect subsequent scripts:
#  - OPENSSL_SYS_DIR: path to system OpenSSL installation; default /usr
#  - LIBOQS_REPO: which repo to check out from, default https://github.com/open-quantum-safe/liboqs.git
#  - LIBOQS_BRANCH: which branch to check out, default master
#  - LIBTYPE: can be either shared, in which case shared OpenSSL libraries are built, or no-shared, in which case static OpenSSL libraries are built.
###########

set -exo pipefail

ARCH=${ARCH:-"x64"}

scripts/clone_liboqs.sh
scripts/build_liboqs.sh

scripts/build_openssl.sh
LD_LIBRARY_PATH=$(dirname $PWD) python3 -m nose --rednose --verbose
