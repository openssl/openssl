#!/bin/sh
#
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# OpenSSL external testing using the pkcs11-provider
#

if [ "$(id -u)" -ne 0 ]; then
    echo "Need to be root to run this test!"
    exit 1
fi

PWD="$(pwd)"

SRCTOP="$(cd $SRCTOP; pwd)"
BLDTOP="$(cd $BLDTOP; pwd)"

if [ "$SRCTOP" != "$BLDTOP" ] ; then
    echo "Out of tree builds not supported with crau test!"
    exit 1
fi

cd $BLDTOP

O_EXE="$BLDTOP/apps"
O_BINC="$BLDTOP/include"
O_SINC="$SRCTOP/include"
O_LIB="$BLDTOP"

export PATH="$O_EXE:$PATH"
export LD_LIBRARY_PATH="$O_LIB:$LD_LIBRARY_PATH"
export OPENSSL_ROOT_DIR="$O_LIB"

echo "------------------------------------------------------------------"
echo "Building crypto-auditing"
echo "------------------------------------------------------------------"

cd $OPENSSL_ROOT_DIR/crypto-auditing

cp "$OPENSSL_ROOT_DIR"/vmlinux.h agent/src/bpf
cp "$OPENSSL_ROOT_DIR"/vmlinux.h agent/tests/agenttest/src/bpf

cargo build --verbose

cd -

echo "------------------------------------------------------------------"
echo "Running tests"
echo "------------------------------------------------------------------"

OPENSSL=$O_EXE/openssl
CRAU_AGENT=$OPENSSL_ROOT_DIR/crypto-auditing/target/debug/crau-agent
CRAU_QUERY=$OPENSSL_ROOT_DIR/crypto-auditing/target/debug/crau-query
CRAU_CBOR_LOG=`mktemp`
CRAU_JSON_LOG=`mktemp`

rm -f "$CRAU_CBOR_LOG" "$CRAU_JSON_LOG"

"$CRAU_AGENT" -c /dev/null --library "$O_LIB"/libcrypto.so.4 \
              --log-file "$CRAU_CBOR_LOG" &

# wait until crau-agent starts
timeout 2 sh -c "while true; do test -e \"""$CRAU_CBOR_LOG""\" && break; done"

agent_pids=`ps -ef | grep crau-agent | grep -v grep | awk '{print $2}'`
if [ -z "$agent_pids" ]
then
    echo "No sign of crau-agent - exiting (before client)"
    exit 88
fi

"$O_EXE"/openssl s_server -tls1_3 -WWW -naccept 1 \
        -cert test/certs/servercert.pem -key test/certs/serverkey.pem &

server_pids=`ps -ef | grep s_server | grep -v grep | awk '{print $2}'`
if [ -z "$server_pids" ]
then
    echo "No sign of s_server - exiting (before client)"
    exit 88
fi

httpreq="GET / HTTP/1.1\\r\\nConnection: close\\r\\n\\r\\n"

(echo -e "$httpreq"; sleep 2) | \
    "$O_EXE"/openssl s_client -CAfile test/certs/rootcert.pem -connect localhost:4433


"$CRAU_QUERY" --log-file "$CRAU_CBOR_LOG" | tee "$CRAU_JSON_LOG"

# check if at least one TLS 1.3 handshake took place
jq --exit-status '[.[] | .events | select(.name == "tls::handshake") | select(."tls::protocol_version" == 772)] | length > 0' "$CRAU_JSON_LOG"

success=$?

# crau-agent needs killing
kill $agent_pids
exit $success
