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
# Upgrade pip to always have latest
pip install -U pip

# Handling Rust
export RUSTUP_HOME="$PWD/venv-cryptography/.rustup"
export CARGO_HOME="$PWD/venv-cryptography/.cargo"
export PATH="$CARGO_HOME/bin:$PATH"
RUST_VERSION="1.85.1"

# Install Rust
if [ ! -f $CARGO_HOME/bin/cargo ]; then
     echo "Installing Rust..."
     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
         --no-modify-path \
         --default-toolchain "$RUST_VERSION" \
         --profile minimal
fi

# Load cargo/env
. "$CARGO_HOME/env"

# Explicitly set the default toolchain (in case installation didn't)
rustup default "$RUST_VERSION" >/dev/null 2>&1

# Verify installation
if ! command -v cargo >/dev/null 2>&1; then
    echo "Error: Rust installation failed!" >&2
    exit 1
fi

echo "Rust is installed: $(rustc --version)"

cd pyca-cryptography

echo "------------------------------------------------------------------"
echo "Building cryptography and installing test requirements"
echo "------------------------------------------------------------------"
OPENSSL_DIR=$O_LIB OPENSSL_LIB_DIR=$O_LIB OPENSSL_INCLUDE_DIR=$O_SINC LDFLAGS="-L$O_LIB" CFLAGS="-I$O_BINC -I$O_SINC " pip install .[test]
pip install -e vectors

echo "------------------------------------------------------------------"
echo "Print linked libraries"
echo "------------------------------------------------------------------"
ldd $(find ../venv-cryptography/lib/ -iname '*.so')


echo "------------------------------------------------------------------"
echo "Running tests"
echo "------------------------------------------------------------------"
pytest -n auto tests --wycheproof-root=../wycheproof

cd ../
deactivate
rm -rf venv-cryptography

exit 0

