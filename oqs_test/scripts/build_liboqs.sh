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

# temporary cludge to avoid CPU features to be build in that executors may not have:
# TBD XXX replace with dynamic CPU feature detection at runtime!!! XXX TBD
if [ "x${CIRCLECI}" == "xtrue" ]; then
sed -i -e "s/x86/t86/g" .CMake/cpu-extensions.cmake
fi

rm -rf build
mkdir build && cd build

if [ "x${LIBTYPE}" == "xshared" ]; then
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=${OPENSSL_DIR} -DBUILD_SHARED_LIBS=ON ..
else
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=${OPENSSL_DIR} ..
fi
ninja
ninja install
