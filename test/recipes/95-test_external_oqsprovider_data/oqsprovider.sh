#!/bin/sh
#
# Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# OpenSSL external testing using the OQS provider
#
set -e

PWD="$(pwd)"

SRCTOP="$(cd $SRCTOP; pwd)"
BLDTOP="$(cd $BLDTOP; pwd)"

if [ "$SRCTOP" != "$BLDTOP" ] ; then
    echo "Out of tree builds not supported with oqsprovider test!"
    exit 1
fi

O_EXE="$BLDTOP/apps"
O_BINC="$BLDTOP/include"
O_SINC="$SRCTOP/include"
O_LIB="$BLDTOP"

unset OPENSSL_CONF

export PATH="$O_EXE:$PATH"
export LD_LIBRARY_PATH="$O_LIB:$LD_LIBRARY_PATH"
export OPENSSL_ROOT_DIR="$O_LIB"

# Check/Set openssl version
OPENSSL_VERSION=`openssl version | cut -f 2 -d ' '`

echo "------------------------------------------------------------------"
echo "Testing OpenSSL using oqsprovider:"
echo "   CWD:                $PWD"
echo "   SRCTOP:             $SRCTOP"
echo "   BLDTOP:             $BLDTOP"
echo "   OPENSSL_ROOT_DIR:   $OPENSSL_ROOT_DIR"
echo "   OpenSSL version:    $OPENSSL_VERSION"
echo "------------------------------------------------------------------"

if [ ! -d $SRCTOP/oqs-provider/oqs ]; then
# disable rainbow family by default; all further config options listed at
# https://github.com/open-quantum-safe/liboqs/wiki/Customizing-liboqs
(
       cd $SRCTOP/oqs-provider \
           && git clone --depth 1 --branch 0.7.2 https://github.com/open-quantum-safe/liboqs.git \
           && cd liboqs \
           && mkdir build \
           && cd build \
           && cmake -DOQS_ENABLE_SIG_RAINBOW=OFF -DCMAKE_INSTALL_PREFIX=$SRCTOP/oqs-provider/oqs .. \
           && make \
           && make install
   )
fi

echo "   CWD:                $PWD"
cmake $SRCTOP/oqs-provider -DCMAKE_INCLUDE_PATH=$SRCTOP/oqs-provider/oqs -DCMAKE_PREFIX_PATH=$SRCTOP/oqs-provider/oqs -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT_DIR" -DOPENSSL_BLDTOP=$BLDTOP -B _build && cmake --build _build
export CTEST_OUTPUT_ON_FAILURE=1
export HARNESS_OSSL_PREFIX=''
export OPENSSL_APP="$O_EXE/openssl"
if [ -z "$OQS_SKIP_TESTS" ]; then
    export OQS_SKIP_TESTS="rainbow,111"
fi
export OPENSSL_MODULES=$PWD/_build/oqsprov
export OQS_PROVIDER_TESTSCRIPTS=$SRCTOP/oqs-provider
$SRCTOP/oqs-provider/scripts/runtests.sh
