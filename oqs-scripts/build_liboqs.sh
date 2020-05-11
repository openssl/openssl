#!/bin/bash

###########
# Build liboqs
#
# Environment variables:
#  - OPENSSL_DIR: path to install liboqs, default ${PROJECT_ROOT}/oqs
###########

set -exo pipefail

OPENSSL_DIR=${OPENSSL_DIR:-"`pwd`/oqs"}

cd oqs-test/tmp/liboqs

rm -rf build
mkdir build && cd build

if [ "x${LIBOQS_LIBTYPE}" == "xshared" ]; then
    cmake .. -GNinja -DCMAKE_INSTALL_PREFIX=${OPENSSL_DIR} -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON
else
    cmake .. -GNinja -DCMAKE_INSTALL_PREFIX=${OPENSSL_DIR} -DOQS_BUILD_ONLY_LIB=ON ..
fi
ninja
ninja install
