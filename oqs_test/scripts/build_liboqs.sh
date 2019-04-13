#!/bin/bash

###########
# Build liboqs
#
# Environment variables:
#  - OPENSSL_SYS_DIR: path to system OpenSSL installation; default /usr
#  - OPENSSL_DIR: path to install liboqs, default `pwd`/../oqs
###########

set -exo pipefail

case "$OSTYPE" in
    darwin*)  OPENSSL_SYS_DIR=${OPENSSL_SYS_DIR:-"/usr/local/opt/openssl"} ;;
    linux*)   OPENSSL_SYS_DIR=${OPENSSL_SYS_DIR:-"/usr"} ;;
    *)        echo "Unknown operating system: $OSTYPE" ; exit 1 ;;
esac

OPENSSL_DIR=${OPENSSL_DIR:-"`pwd`/../oqs"}

cd tmp/liboqs
autoreconf -i
./configure --prefix=${OPENSSL_DIR} --enable-shared=no --enable-openssl --with-openssl-dir=${OPENSSL_SYS_DIR}
if [ "x${CIRCLECI}" == "xtrue" ] || [ "x${TRAVIS}" == "xtrue" ]; then
    make -j2
else
    make -j
fi
make install
