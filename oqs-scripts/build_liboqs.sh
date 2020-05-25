#!/bin/bash

###########
# Build liboqs
#
# Environment variables:
#  - OPENSSL_DIR: path to install liboqs, default ${PROJECT_ROOT}/oqs
#  - LIBOQS_LIBTYPE: if 'shared', build a shared library, else build a static library.
#  - LIBOQS_USE_OPENSSL: the value to pass to the -DOQS_USE_OPENSSL build flag. Can be 'ON' or 'OFF',
#                        and is 'ON' by default.
###########

set -exo pipefail

OPENSSL_DIR=${OPENSSL_DIR:-"$(pwd)/oqs"}
LIBOQS_USE_OPENSSL=${LIBOQS_USE_OPENSSL:-"ON"}

cd oqs-test/tmp/liboqs

rm -rf build
mkdir build && cd build

if [ "x${LIBOQS_LIBTYPE}" == "xshared" ]; then
    cmake .. -GNinja -DCMAKE_INSTALL_PREFIX="${OPENSSL_DIR}" -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL="${LIBOQS_USE_OPENSSL}"
else
    cmake .. -GNinja -DCMAKE_INSTALL_PREFIX="${OPENSSL_DIR}" -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL="${LIBOQS_USE_OPENSSL}"
fi
ninja
ninja install
