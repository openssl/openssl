#!/bin/bash

# Use newly built oqsprovider to save PKCS#12 files from keys and
# and certificates files generated using alg $1.
# Assumed oqsprovider-certgen.sh to have run before for same algorithm

set -e
set -x

if [ $# -lt 1 ]; then
    echo "Usage: $0 <algorithmname>. Exiting."
    exit 1
fi

echo "oqsprovider-pkcs12gen.sh commencing..."

if [ -z "$OPENSSL_APP" ]; then
    echo "OPENSSL_APP env var not set. Exiting."
    exit 1
fi

if [ -z "$OPENSSL_MODULES" ]; then
    echo "Warning: OPENSSL_MODULES env var not set."
fi

if [ -z "$OPENSSL_CONF" ]; then
    echo "OPENSSL_CONF env var not set. Exiting."
    exit 1
fi

# Set OSX DYLD_LIBRARY_PATH if not already externally set
if [ -z "$DYLD_LIBRARY_PATH" ]; then
    export DYLD_LIBRARY_PATH=$LD_LIBRARY_PATH
fi

# Assumes certgen has been run before: Quick check
if [[ -f tmp/$1_CA.crt &&  -f tmp/$1_CA.key ]]; then
   echo "Key and certificate using $1 found."
else
   echo "File tmp/$1_CA.crt and/or tmp/$1_CA.key not found. Did certgen run before? Exiting."
   exit -1
fi

echo "Generating PKCS#12 files..."

# pkcs12 test:
$OPENSSL_APP pkcs12 -export -in tmp/$1_srv.crt -inkey tmp/$1_srv.key -passout pass: -out tmp/$1_srv_1.p12

if [ $? -ne 0 ] || [ ! -f tmp/$1_srv_1.p12 ]; then
    echo "PKCS#12 generation with oqsprovider enabled failed."
    exit 1
fi

# Generate config file with oqsprovider disabled
sed -e 's/^oqsprovider/# oqsprovider/' $OPENSSL_CONF > tmp/openssl-ca-no-oqsprovider.cnf

# This print an error but OpenSSL returns 0 and .p12 file is generated correctly
OPENSSL_CONF=tmp/openssl-ca-no-oqsprovider.cnf $OPENSSL_APP pkcs12 -provider default -provider oqsprovider -export -in tmp/$1_srv.crt -inkey tmp/$1_srv.key -passout pass: -out tmp/$1_srv_2.p12

if [ $? -ne 0 ] || [ ! -f tmp/$1_srv_2.p12 ]; then
    echo "PKCS#12 generation with oqsprovider disabled failed."
    exit 1
fi

if [ $(cat tmp/$1_srv_1.p12 | $OPENSSL_APP sha256) -neq $(cat tmp/$1_srv_2.p12 | $OPENSSL_APP sha256) ]; then
    echo "PKCS#12 files differ when oqsprovider is enabled or not."
    exit 1
fi
