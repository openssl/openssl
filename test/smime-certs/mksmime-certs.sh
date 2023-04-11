#!/bin/sh
# Copyright 2013-2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Utility to recreate S/MIME certificates in this directory.
# Invoke when changes are need from within this directory.

OPENSSL=../../apps/openssl
CONF=ca.cnf
export OPENSSL_CONF=./$CONF

gen() {
    $OPENSSL x509 -CA smroot.pem -new -days 36524 -force_pubkey $1 -subj "$2" \
             -extfile $CONF -extensions $3
}

# Root CA: create certificate directly
CN="Test S/MIME RSA Root" $OPENSSL req -config ca.cnf -x509 -noenc \
	-keyout smroot.pem -out smroot.pem -key ../certs/ca-key.pem -days 36524

# EE RSA certificates with respective extensions
cp ../certs/ee-key.pem smrsa1.pem
gen smrsa1.pem "/CN=Test SMIME EE RSA #1" usr_rsa_cert >>smrsa1.pem
cp ../certs/ee-key-3072.pem smrsa2.pem
gen smrsa2.pem "/CN=Test SMIME EE RSA #2" usr_rsa_cert >>smrsa2.pem
cp ../certs/ee-key-4096.pem smrsa3.pem
gen smrsa3.pem "/CN=Test SMIME EE RSA #3" usr_rsa_cert >>smrsa3.pem

# Create DSA certificates with respective extensions

cp ../certs/server-dsa-key.pem smdsa1.pem
gen smdsa1.pem "/CN=Test SMIME EE DSA #1" signer_cert >>smdsa1.pem
cp ../certs/server-dsa-key.pem smdsa2.pem
gen smdsa2.pem "/CN=Test SMIME EE DSA #1" signer_cert >>smdsa2.pem
cp ../certs/server-dsa-key.pem smdsa3.pem
gen smdsa3.pem "/CN=Test SMIME EE DSA #1" signer_cert >>smdsa3.pem

# Create EC certificates with respective extensions

cp ../certs/ee-ecdsa-key.pem smec1.pem
gen smec1.pem "/CN=Test SMIME EE EC #1" signer_cert >>smec1.pem
cp ../certs/server-ecdsa-key.pem smec2.pem
gen smec2.pem "/CN=Test SMIME EE EC #2" signer_cert >>smec2.pem

# Do not renew this cert as it is used for legacy data decrypt test
#$OPENSSL ecparam -out ecp.pem -name P-256
#CN="Test S/MIME EE EC #3" $OPENSSL req -config ca.cnf -noenc \
#	-keyout smec3.pem -out req.pem -newkey ec:ecp.pem
#$OPENSSL x509 -req -in req.pem -CA smroot.pem -days 36524 \
#	-extfile ca.cnf -extensions signer_cert -CAcreateserial >>smec3.pem
#rm ecp.pem req.pem

# Create X9.42 DH parameters and key.
$OPENSSL genpkey -genparam -algorithm DHX -out dhp.pem
$OPENSSL genpkey -paramfile dhp.pem -out smdh.pem
rm dhp.pem
# Create X9.42 DH certificate with respective extensions
gen smdh.pem "/CN=Test SMIME EE DH" dh_cert >>smdh.pem

# EE RSA code signing end entity certificate with respective extensions
cp ../certs/ee-key.pem csrsa1.pem
gen csrsa1.pem "/CN=Test CodeSign EE RSA" codesign_cert >>csrsa1.pem
