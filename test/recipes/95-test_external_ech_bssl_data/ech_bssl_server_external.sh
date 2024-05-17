#!/bin/sh

#
# Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# OpenSSL ECH external testing using boringssl
#
# set -e

PWD="$(pwd)"

SRCTOP="$(cd $SRCTOP; pwd)"
BLDTOP="$(cd $BLDTOP; pwd)"

if [ "$SRCTOP" != "$BLDTOP" ] ; then
    echo "Out of tree builds not supported with ECH external test!"
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
ECHCONFIGFILE=$SRCTOP/test/certs/echconfig.pem
httphost=server.example
httpreq="GET /stats HTTP/1.1\\r\\nConnection: close\\r\\nHost: $httphost\\r\\n\\r\\n"
BTOOL=$SRCTOP/boringssl/.local/bin

echo "------------------------------------------------------------------"
echo "Testing ECH-enabled boringssl server using s_client:"
echo "   CWD:                 $PWD"
echo "   SRCTOP:              $SRCTOP"
echo "   BLDTOP:              $BLDTOP"
echo "   OPENSSL_ROOT_DIR:    $OPENSSL_ROOT_DIR"
echo "   OpenSSL version:     $OPENSSL_VERSION"
echo "   PEM ECH Config file: $ECHCONFIGFILE"

echo "------------------------------------------------------------------"

if [ ! -d $SRCTOP/boringssl ]; then
    mkdir -p $SRCTOP/boringssl
fi
if [ ! -d $SRCTOP/boringssl/.local ]; then
(
       cd $SRCTOP \
           && git clone https://boringssl.googlesource.com/boringssl \
           && cd boringssl \
           && mkdir build \
           && cd build \
           && cmake -DOPENSSL_ROOT_DIR=$OPENSSL_ROOT_DIR -DCMAKE_INSTALL_PREFIX=$SRCTOP/boringssl/.local .. \
           && make \
           && make install
   )
fi

echo "   CWD:                $PWD"

bssllist=`mktemp`
bsslech=`mktemp`
bsslkey=`mktemp`
bsslpem=`mktemp`
echo "Generating ECH keys for a bssl s_server."
$BTOOL/bssl generate-ech -out-ech-config-list $bssllist \
    -out-ech-config $bsslech -out-private-key $bsslkey \
    -public-name example.com -config-id 222 -max-name-length 0
res=$?
# the b64 form is friendlier for s_client
cat $bssllist | base64 -w0 >$bsslpem

# Start a boringssl s_server
$BTOOL/bssl s_server \
    -accept 8443 \
    -key $SRCTOP/test/certs/echserver.key -cert $SRCTOP/test/certs/echserver.pem \
    -ech-config $bsslech -ech-key $bsslkey \
    -www -loop &
pids=`ps -ef | grep s_server | grep -v grep | awk '{print $2}'`
if [ -z "$pids" ]
then
    echo "No sign of s_server - exiting (before client)"
    rm -f $bssllist $bsslech $bsslkey $bsslpem
    exit 88
fi
echo "Running openssl s_client against localhost"
(echo -e $httpreq ; sleep 2) | \
    $SRCTOP/apps/openssl s_client -connect localhost:8443 \
        -CAfile $SRCTOP/test/certs/rootcert.pem \
        -ech_config_list `cat $bsslpem` \
        -servername $httphost \
        -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2
success=$?
rm -f $bssllist $bsslech $bsslkey $bsslpem
kill $pids
# bssl returns 1 if ok, we want to exit with 0 for a PASS
exit $((success != 1))
