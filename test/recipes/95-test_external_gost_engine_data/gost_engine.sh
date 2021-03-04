#!/bin/sh
#
# Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# OpenSSL external testing using the GOST engine
#
set -e

PWD="$(pwd)"

O_EXE="$PWD/$BLDTOP/apps"
O_BINC="$PWD/$BLDTOP/include"
O_SINC="$PWD/$SRCTOP/include"
O_LIB="$PWD/$BLDTOP"

unset OPENSSL_CONF

if [ "$O_BINC" != "$O_SINC" ] ; then
    echo "Out of tree builds not supported with gost_engine test!"
    exit 1
fi

export PATH="$O_EXE:$PATH"
export LD_LIBRARY_PATH="$O_LIB:$LD_LIBRARY_PATH"
export OPENSSL_ROOT_DIR="$O_LIB"

# Check/Set openssl version
OPENSSL_VERSION=`openssl version | cut -f 2 -d ' '`

echo "------------------------------------------------------------------"
echo "Testing OpenSSL using GOST engine:"
echo "   CWD:                $PWD"
echo "   SRCTOP:             $SRCTOP"
echo "   BLDTOP:             $BLDTOP"
echo "   OPENSSL_ROOT_DIR:   $OPENSSL_ROOT_DIR"
echo "   OpenSSL version:    $OPENSSL_VERSION"
echo "------------------------------------------------------------------"

cd $SRCTOP/gost-engine
rm -rf build
mkdir -p build
cd build
cmake .. -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT_DIR"
make
export CTEST_OUTPUT_ON_FAILURE=1
export HARNESS_OSSL_PREFIX=''
export OPENSSL_ENGINES="$OPENSSL_ROOT_DIR/gost-engine/build/bin"
export OPENSSL_APP="$O_EXE/openssl"
make test
make tcl_tests
