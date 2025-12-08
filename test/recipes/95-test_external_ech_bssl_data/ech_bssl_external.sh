#!/bin/sh

#
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# OpenSSL ECH external testing using boringssl client

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
ECHCONFIGFILE=$SRCTOP/test/certs/echdir/ech-eg.pem
httphost=server.example
httpreq="GET /stats HTTP/1.1\\r\\nConnection: close\\r\\nHost: $httphost\\r\\n\\r\\n"
BTOOL=$SRCTOP/boringssl/.local/bin

echo "------------------------------------------------------------------"
echo "Testing OpenSSL s_server using ECH-enabled boringssl client:"
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

# Start an openssl s_server
$SRCTOP/apps/openssl s_server \
    -key $SRCTOP/test/certs/echserver.key -cert $SRCTOP/test/certs/echserver.pem \
    -key2 $SRCTOP/test/certs/echserver.key -cert2 $SRCTOP/test/certs/echserver.pem \
    -CAfile $SRCTOP/test/certs/rootcert.pem \
    -ech_key $ECHCONFIGFILE -port 8443  -tls1_3 -WWW \
    -naccept 1 -ign_eof -servername server.example &
pids=`ps -ef | grep s_server | grep -v grep | awk '{print $2}'`
if [ -z "$pids" ]
then
    echo "No sign of s_server - exiting (before client)"
    exit 88
fi
# We want the binary ECHConfigList for bssl so extract that
# from the PEM file
bechfile=`mktemp`
resfile=`mktemp`
cat $ECHCONFIGFILE \
        | awk '/^-----BEGIN ECHCONFIG/,/^-----END ECHCONFIG/' \
        | tail -n+2 | head -n+2 | tr -d '\n' | base64 -d >$bechfile
echo "Running bssl s_client against localhost"
(echo -e $httpreq ; sleep 2) | \
    $BTOOL/bssl s_client -connect localhost:8443 \
        -ech-config-list $bechfile \
        -server-name $httphost \
        -root-certs $SRCTOP/test/certs/rootcert.pem > $resfile 2>&1
rm -f $bechfile
cat $resfile
success=`grep -c "Encrypted ClientHello: yes" $resfile`
rm -f $resfile 
# if success==1 we're good so exit with a zero for test success
exit $((success != 1))
