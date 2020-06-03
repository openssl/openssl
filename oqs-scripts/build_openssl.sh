#!/bin/bash

###########
# Build OpenSSL
#
# Must be run after OQS has been installed inside the OpenSSL source code directory
#
# Environment variables:
#  - OPENSSL_LIBTYPE: can be either shared, in which case shared OpenSSL libraries are built, or no-shared, in which case static OpenSSL libraries are built.
###########

set -exo pipefail

OPENSSL_LIBTYPE=${OPENSSL_LIBTYPE:-"no-shared"}
case "${OSTYPE}" in
    darwin*)  ./Configure ${OPENSSL_LIBTYPE} darwin64-x86_64-cc ;;
    linux*)   ./Configure ${OPENSSL_LIBTYPE} linux-x86_64 -lm  ;;
    *)        echo "Unknown operating system: $OSTYPE" ; exit 1 ;;
esac
make clean
if [ "x${CIRCLECI}" == "xtrue" ]; then
    make -j2
else
    make -j
fi
