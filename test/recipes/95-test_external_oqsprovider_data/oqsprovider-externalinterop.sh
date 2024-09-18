#!/bin/bash

set -e 

# Use newly built oqsprovider to test interop with external sites

if [ -z "$OPENSSL_APP" ]; then
    echo "OPENSSL_APP env var not set. Exiting."
    exit 1
fi

if [ -z "$OPENSSL_MODULES" ]; then
    echo "Warning: OPENSSL_MODULES env var not set."
fi

# Set OSX DYLD_LIBRARY_PATH if not already externally set
if [ -z "$DYLD_LIBRARY_PATH" ]; then
    export DYLD_LIBRARY_PATH=$LD_LIBRARY_PATH
fi

# We assume the value of env var HTTP_PROXY is "http://host.domain:port_num"
if [ ! -z "${HTTP_PROXY}" ]; then
    echo "Using Web proxy \"${HTTP_PROXY}\""
    export USE_PROXY="-proxy ${HTTP_PROXY#http://} -allow_proxy_certs"
else
    export USE_PROXY=""
fi

# Ascertain algorithms are available:

# skipping these tests for now as per https://mailarchive.ietf.org/arch/msg/tls/hli5ogDbUudAA4tZXskVbOqeor4
# TBD replace with suitable ML-KEM hybrid tests as and when available XXX 

exit 0

echo " Cloudflare:"

if ! ($OPENSSL_APP list -kem-algorithms | grep x25519_kyber768); then
   echo "Skipping unconfigured x25519_kyber768 interop test"
else
   export OQS_CODEPOINT_X25519_KYBER512=65072
   (echo -e "GET /cdn-cgi/trace HTTP/1.1\nHost: cloudflare.com\n\n"; sleep 1; echo $'\cc') | "${OPENSSL_APP}" s_client ${USE_PROXY} -connect pq.cloudflareresearch.com:443 -groups x25519_kyber768 -servername cloudflare.com -ign_eof 2>/dev/null | grep kex=X25519Kyber768Draft00
fi

if ! ($OPENSSL_APP list -kem-algorithms | grep x25519_kyber512); then
   echo "Skipping unconfigured x25519_kyber512 interop test"
else
   (echo -e "GET /cdn-cgi/trace HTTP/1.1\nHost: cloudflare.com\n\n"; sleep 1; echo $'\cc') | "${OPENSSL_APP}" s_client ${USE_PROXY} -connect pq.cloudflareresearch.com:443 -groups x25519_kyber512 -servername cloudflare.com -ign_eof 2>/dev/null | grep kex=X25519Kyber512Draft00
fi
