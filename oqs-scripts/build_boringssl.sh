#!/bin/bash

###########
# Build (static) OQS-BoringSSL
#
###########

set -exo pipefail

PROJECT_ROOT=$(pwd)

cd boringssl

rm -rf build
mkdir build && cd build

cmake .. -G"Ninja" -DLIBOQS_DIR="${PROJECT_ROOT}/oqs"

if [ "x${CIRCLECI}" == "xtrue" ]; then
    ninja -j4
else
    ninja
fi
