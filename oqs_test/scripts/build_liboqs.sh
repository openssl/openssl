#!/bin/bash

###########
# Build liboqs
#
# Environment variables:
#  - OPENSSL_DIR: path to install liboqs, default `pwd`/../oqs
###########

set -exo pipefail

OPENSSL_DIR=${OPENSSL_DIR:-"`pwd`/../oqs"}

cd tmp/liboqs

rm -rf build
mkdir build && cd build

if [ "x${LIBTYPE}" == "xshared" ]; then
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=${OPENSSL_DIR} -DBUILD_SHARED_LIBS=ON ..
else
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=${OPENSSL_DIR} ..
fi
ninja
ninja install
