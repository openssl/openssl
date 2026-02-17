#!/usr/bin/env bash

#
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# OpenSSL ECH external testing using nss client

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

echo "------------------------------------------------------------------"
echo "Testing OpenSSL s_server using ECH-enabled nss client:"
echo "   CWD:                 $PWD"
echo "   SRCTOP:              $SRCTOP"
echo "   BLDTOP:              $BLDTOP"
echo "   OPENSSL_ROOT_DIR:    $OPENSSL_ROOT_DIR"
echo "   OpenSSL version:     $OPENSSL_VERSION"
echo "   PEM ECH Config file: $ECHCONFIGFILE"

echo "------------------------------------------------------------------"

LATEST='non-existent-directory'
if [ -f $SRCTOP/nss/dist/latest ]; then
    LATEST=`cat $SRCTOP/nss/dist/latest`
fi
LDIR=$SRCTOP/nss/dist/$LATEST/bin
NLIB=$SRCTOP/nss/dist/$LATEST/lib

if [ ! -f $LDIR/tstclnt ]; then
    # clone our NSS and NSPR
    echo "You need to have built NSS before running this test."
    echo "To do that, run the following commands:"
    cat <<EOF
        mkdir $SRCTOP/nss
        cd $SRCTOP/nss
        git clone https://github.com/nss-dev/nss.git
        hg clone https://hg.mozilla.org/projects/nspr
        cd $SRCTOP/nss/nss
        USE_64=1 make nss_build_all
        USE_64=1 make install
EOF
    exit 1
fi 

if [ ! -f $LDIR/tstclnt ]; then
    echo "Bad NSS build - exiting"
    exit 99
fi
if [ ! -f $LDIR/certutil ]; then
    echo "Bad NSS build - exiting"
    exit 99
fi

# If we have an NSS build, create an NSS DB for our fake root so we can 
# use NSS' tstclnt to talk to our s_server.
if [ -f $LDIR/certutil ]
then
    mkdir -p $SRCTOP/nss/ca
	LD_LIBRARY_PATH=$NLIB $LDIR/certutil -A \
        -i $SRCTOP/test/certs/rootcert.pem \
        -n "oe" -t "CT,C,C" -d $SRCTOP/nss/ca/
fi

echo "   CWD:                $PWD"

# Start an openssl s_server
$SRCTOP/apps/openssl s_server \
    -key $SRCTOP/test/certs/echserver.key -cert $SRCTOP/test/certs/echserver.pem \
    -key2 $SRCTOP/test/certs/echserver.key -cert2 $SRCTOP/test/certs/echserver.pem \
    -CAfile $SRCTOP/test/certs/rootcert.pem \
    -ech_key $ECHCONFIGFILE -port 8443  -tls1_3 -WWW -naccept 1 \
    -ign_eof -servername server.example &
pids=`ps -ef | grep s_server | grep -v grep | awk '{print $2}'`
if [ -z "$pids" ]
then
    echo "No sign of s_server - exiting (before client)"
    exit 88
fi

# to ensure we detect a fail, use the wrong ECHConfig ...
# ECHCONFIGFILE=$SRCTOP/esnistuff/d13.pem
ECH=`cat $ECHCONFIGFILE \
        | awk '/^-----BEGIN ECHCONFIG/,/^-----END ECHCONFIG/' \
        | tail -n+2 | head -n+2 | tr -d '\n'`

NSSPARAMS="-Q -4 -b -d $SRCTOP/nss/ca"
LD_LIBRARY_PATH="$NLIB" $LDIR/tstclnt $NSSPARAMS -h localhost -p 8443 -a $httphost -N $ECH 
res=$?
exit $res

