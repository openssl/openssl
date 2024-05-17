#!/bin/sh

# set -x 

#
# Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# OpenSSL ECH external testing using nss
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
httpreq="GET / HTTP/1.1\\r\\nConnection: close\\r\\nHost: $httphost\\r\\n\\r\\n"
LDIR=$SRCTOP/nss/dist/Debug/bin
LLIB=$SRCTOP/nss/dist/Debug/lib

echo "------------------------------------------------------------------"
echo "Testing OpenSSL s_client using ECH-enabled nss server:"
echo "   CWD:                 $PWD"
echo "   SRCTOP:              $SRCTOP"
echo "   BLDTOP:              $BLDTOP"
echo "   OPENSSL_ROOT_DIR:    $OPENSSL_ROOT_DIR"
echo "   OpenSSL version:     $OPENSSL_VERSION"
echo "   PEM ECH Config file: $ECHCONFIGFILE"

echo "------------------------------------------------------------------"

if [ ! -d $SRCTOP/nss ]; then
    mkdir -p $SRCTOP/nss
fi
# see comment below for why "git apply" is needed for now.
if [ ! -f $LDIR/tstclnt ]; then
(
       cd $SRCTOP/nss \
           && git clone https://github.com/nss-dev/nss.git \
           && hg clone https://hg.mozilla.org/projects/nspr \
           && cd nss \
           && git apply ../../test/recipes/95-test_external_ech_nss_data/nsspatch \
           && ./build.sh
   )
fi

if [ ! -f $LDIR/tstclnt ]; then
    echo "Failed to build NSS - exiting"
    exit 99
fi
if [ ! -f $LDIR/certutil ]; then
    echo "Failed to build NSS - exiting"
    exit 99
fi

# If we have an NSS build, create an NSS DB for our fake root so we can 
# use NSS' tstclnt to talk to our s_server.
if [ ! -d $SRCTOP/nss/server ]
then
    mkdir -p $SRCTOP/nss/server
	LD_LIBRARY_PATH=$LLIB $LDIR/certutil -A \
        -i $SRCTOP/test/certs/rootcert.pem \
        -n "oe" -t "CT,C,C" -d $SRCTOP/nss/server/
    sillypass="sillypass"
    $SRCTOP/apps/openssl pkcs12 -export -out tmp.p12 \
        -inkey $SRCTOP/test/certs/echserver.key \
        -in $SRCTOP/test/certs/echserver.pem \
        -password "pass:$sillypass"
    echo -n $sillypass >sillypassfile
	LD_LIBRARY_PATH=$LLIB $LDIR/pk12util \
        -i tmp.p12 -d $SRCTOP/nss/server -w sillypassfile 
    cat sillypassfile
    # rm -f sillypassfile tmp.p12
fi

echo "   CWD:                $PWD"

# Start an NSS server
# We'll let the server generate the ECH key pair for now (see 
# below for why). Note that as of 20240124 this requires a
# (trivial) code change to get NSS's selfserve to work in this mode. 
# I've reported that to moz folks but just in case it doesn't get
# fixed soon the diff is in nsspatch (alongside this script).
# NSS devs have said they'll land that patch at which point we won't
# need nsspath any more.

# need to use ``stdbuf -o0`` so that we don't get buffering and
# can grab echconfig immediately...
LD_LIBRARY_PATH=$LLIB stdbuf -o0 $LDIR/selfserv -p 8443 -d $SRCTOP/nss/server \
    -n server.example -X "publicname:example.com" >ss-echfile &

if [ -s ss-echfile ]
then
    echo "Did you remember to patch NSS? See $0 for details"
    exit 78
fi

# For the future, we'd like a provide our private-key/ECHConfig to
# NSS - looks like there could be some work required to get that
# selfserve option working.
# https://bugzilla.mozilla.org/show_bug.cgi?id=1876732

pids=`ps -ef | grep selfserv | grep -v grep | awk '{print $2}'`
if [ -z "$pids" ]
then
    echo "No sign of selfserv - exiting (before client)"
    exit 88
fi

# to ensure we detect a fail, use the wrong ECHConfig ...
# ECHCONFIGFILE=$SRCTOP/esnistuff/d13.pem
# ECH=`cat $ECHCONFIGFILE | tail -2 | head -1`
ECH=`cat ss-echfile | tail -2 | head -1`
echo "Running openssl s_client against localhost"
(echo -e $httpreq ; sleep 2) | \
    $SRCTOP/apps/openssl s_client -connect localhost:8443 \
        -CAfile $SRCTOP/test/certs/rootcert.pem \
        -ech_config_list $ECH \
        -servername $httphost \
        -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2
# TODO: with no ECHConfig loaded server treats as GREASE and
# doesn't fail even if ECH failed. Maybe grep result from
# s_client (maybe from stderr, not sure)
success=$?
kill $pids
exit $success
