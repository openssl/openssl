#!/bin/sh
#
# Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
# Copyright (c) 2017, Oracle and/or its affiliates.  All rights reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# OpenSSL external testing using the Python Cryptography module
#
set -e
set -x

O_EXE=`pwd`/$BLDTOP/apps
O_BINC=`pwd`/$BLDTOP/include
O_SINC=`pwd`/$SRCTOP/include
O_LIB=`pwd`/$BLDTOP

export PATH=$O_EXE:$PATH
export LD_LIBRARY_PATH=$O_LIB:$LD_LIBRARY_PATH

# Check/Set openssl version
OPENSSL_VERSION=`openssl version | cut -f 2 -d ' '`

echo "------------------------------------------------------------------"
echo "Testing OpenSSL using Python Cryptography:"
echo "   CWD:                $PWD"
echo "   SRCTOP:             $SRCTOP"
echo "   BLDTOP:             $BLDTOP"
echo "   OpenSSL version:    $OPENSSL_VERSION"
echo "------------------------------------------------------------------"

cd $SRCTOP

# Create a python virtual env and activate
rm -rf venv-cryptography
python -m venv venv-cryptography
. ./venv-cryptography/bin/activate

cd pyca-cryptography

pip install .[test]
pip install -e vectors

sudo rm /usr/lib/x86_64-linux-gnu/libcrypto.so
sudo rm /usr/lib/x86_64-linux-gnu/libssl.so

echo "------------------------------------------------------------------"
echo "Building cryptography"
echo "------------------------------------------------------------------"
LDFLAGS="-L$O_LIB" CFLAGS="-I$O_BINC -I$O_SINC -L$O_LIB" pip install .

echo "------------------------------------------------------------------"
echo "Running tests"
echo "------------------------------------------------------------------"

openssl version
pwd
ls /opt/hostedtoolcache/Python/3.9.14/x64/lib
find .. -name libcrypto.so
sudo find /opt -name libcrypto.so
echo $PATH
echo $LD_LIBRARY_PATH
export CFLAGS="-I$O_BINC -I$O_SINC -L$O_LIB"
export LDFLAGS="-L$O_LIB"
which pytest
pytest --version

pytest -n auto tests --wycheproof-root=../wycheproof

cd ../
deactivate
rm -rf venv-cryptography

exit 0

