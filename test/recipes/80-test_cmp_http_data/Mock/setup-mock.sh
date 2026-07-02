#! /bin/bash
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You can obtain a copy in the file LICENSE in the source distribution
# or at https://www.openssl.org/source/license.html
#
# Script to set up credentials for CMP mock server and tested client (signer)
# Usage: ./setup-mock.sh [PQC]
# Using the optional parameter "PQC" will generate certificates using PQC algorithms,
# otherwise classic algorithms are used.
# Using PQC algorithms makes testing take longer as it is more computationally intensive.
###################################################################
set -e
#set -x  # for debug

mkcert_sh="../../../certs/mkcert.sh"
OPENSSL=openssl
# Specify whether PQC or Classic algorithms are used
# Possible values: "PQC" or "Classic"
# Check if first parameter is PQC, then set USE_PQC accordingly

if [[ "${1,,}" == "pqc" ]]; then
    OPENSSL_VER=$($OPENSSL version | awk '{print $2}')
    if [[ "$(printf '%s\n' "3.5.0" "$OPENSSL_VER" | sort -V | head -n1)" != "3.5.0" ]]; then
        echo "Error: OpenSSL version 3.5 or higher is required for PQC algorithms. Current version: $OPENSSL_VER"
        exit 1
    fi
    USE_PQC=1
fi

if [ -z "$DAYS" ]; then
    DAYS=36524 # 100 years, with 24 leap years per 100 years until 2400
fi

if [[ ${USE_PQC+set} ]]; then
    alg="MLDSA65"
    #  Central key generation test(s) will fail as leaf cert is required
    #  for encryption 
    alg2="SLH-DSA-SHAKE-192s" 
else
    alg="rsa"
    alg2=$alg
fi
    # algorithms for server certificate chain
    server_rootca_keyalg=$alg
    server_leaf_keyalg=$alg
    # rootCACert update test case
    new_rootca_keyalg=$alg

    # algorithms for client certificate chain
    signer_rootca_keyalg=$alg
    signer_interca_keyalg=$alg
    signer_subinterca_keyalg=$alg
    # signer leaf uses alg2 to exercise algorithm diversity in the chain;
    # for PQC mode, alg2 is SLH-DSA which is a signature-only algorithm
    signer_leaf_keyalg=$alg2

# CMP server certificate
rename_serverfiles() {
    echo "Removing intermediate files and renaming mock server files"
    # removing unneeded files
    rm server_root-key.pem server_root-pubkey.pem newWithNew-key.pem newWithNew-pubkey.pem
    mv server_root-cert.pem server_root.crt
    cp server_root.crt trusted.crt
    cat trusted.crt >> big_trusted.crt # works also if not yet existing
    mv server_root.crt oldWithOld.pem
    mv server-key.pem server.key
    mv server-cert.pem server.crt
    mv newWithNew-cert.pem newWithNew.pem
}

remove_serverfiles() {
    echo "Removing server files"
    rm -f server_root.crt trusted.crt server.key server.crt
    rm -f oldWithOld.pem newWithNew.pem oldWithNew.pem newWithOld.pem
}

gen_server_credentials() {
    remove_serverfiles
    # allow time to sync file system after deletions
    sleep 5
    OPENSSL_KEYALG=${server_rootca_keyalg} \
    $mkcert_sh genroot "Root CA" server_root-key server_root-cert
    OPENSSL_KEYALG=${server_leaf_keyalg} \
    $mkcert_sh genee -p serverAuth,cmKGA server.example server-key server-cert server_root-key server_root-cert

    OPENSSL_KEYALG=${new_rootca_keyalg} \
    $mkcert_sh genroot "Root CA" newWithNew-key newWithNew-cert

    $OPENSSL pkey -in newWithNew-key.pem -out newWithNew-pubkey.pem -outform PEM -pubout
    $OPENSSL x509 -new -subj "/CN=Root CA" -CA server_root-cert.pem -CAkey server_root-key.pem \
        -out newWithOld.pem -force_pubkey newWithNew-pubkey.pem \
        -extfile <(printf "basicConstraints=critical,CA:true")

    $OPENSSL pkey -in server_root-key.pem -out server_root-pubkey.pem -outform PEM -pubout
    $OPENSSL x509 -new -subj "/CN=Root CA" -CA newWithNew-cert.pem -CAkey newWithNew-key.pem \
        -out oldWithNew.pem -force_pubkey server_root-pubkey.pem \
        -extfile <(printf "basicConstraints=critical,CA:true")

    rename_serverfiles
}

rename_signerfiles() {
    echo "Renaming signer files"
    mv signer_root-cert.pem root.crt
    cat root.crt >> big_root.crt
    cp root.crt signer_root.crt
    # $OPENSSL crl -in signer_subinterCA-crl0.pem -out crl.der -outform DER
    mv signer_subinterCA-crl0.pem oldcrl.pem
    mv signer_subinterCA-crl1.pem newcrl.pem
    rm -f signer_root-key.pem signer_interCA-key.pem signer_interCA-cert.pem \
        signer_subinterCA-key.pem
    mv signer_subinterCA-cert.pem issuing.crt
    cat issuing.crt >> big_issuing.crt
    mv signer_leaf-key.pem new.key
    $OPENSSL pkey -in new.key -out new_pass_12345.key -aes256 -passout file:12345.txt
    mv signer_leaf-csr.pem csr.pem
    cp new.key signer.key
    mv signer_leaf-cert.pem signer_only.crt
    mv signer_issuing-cert.pem signer_issuing.crt
    mv signer_chain.pem signer.crt
}
remove_signerfiles() {
    echo "Removing signer files"
    rm -f root.crt signer_root.crt newcrl.pem oldcrl.pem new.key signer.key signer_only.crt \
        signer_no_SKID.crt signer_issuing.crt signer.crt issuing.crt csr.pem
}

#  cannot use genee() because this uses a self-signature for the POP in a PKCS#10 CSR
genee_kem() {
    local cn=$1; shift
    local key=$1; shift
    local cert=$1; shift
    local cakey=$1; shift
    local ca=$1; shift
    echo "Generating KEM certificate"
    $OPENSSL genpkey -algorithm "$OPENSSL_KEYALG" -out ${key}.pem -outpubkey ${cn}-pubkey.pem
    $OPENSSL x509 -new -subj "/CN=${cn}" -CA ${ca}.pem -CAkey ${cakey}.pem \
        -out ${cert}.pem -force_pubkey ${cn}-pubkey.pem \
        -extfile <(printf "basicConstraints=critical,CA:false\nkeyUsage=critical,keyEncipherment")
    $OPENSSL x509 -new -subj "/CN=${cn}-noSKID" -CA ${ca}.pem -CAkey ${cakey}.pem \
        -out ${cert}-noSKID.pem -force_pubkey ${cn}-pubkey.pem \
        -extfile <(printf "basicConstraints=critical,CA:false\nkeyUsage=critical,keyEncipherment\nsubjectKeyIdentifier=none")
    rm -f ${cn}-pubkey.pem
}

gen_client_chain() {
    echo "Generating signer certificates"
    remove_signerfiles
    # allow time to sync file system after deletions
    sleep 5
    OPENSSL_KEYALG=${signer_rootca_keyalg} \
    $mkcert_sh genroot "signer-rootCA" signer_root-key signer_root-cert
    OPENSSL_KEYALG=${signer_interca_keyalg} \
    $mkcert_sh genca "signer-interCA" signer_interCA-key signer_interCA-cert signer_root-key signer_root-cert
    OPENSSL_KEYALG=${signer_subinterca_keyalg} \
    $mkcert_sh genca "signer-subinterCA" signer_subinterCA-key signer_subinterCA-cert signer_interCA-key signer_interCA-cert

    if [[ "$signer_leaf_keyalg" == *KEM* ]]; then
        OPENSSL_KEYALG=${signer_leaf_keyalg} genee_kem "signer-leaf" signer_leaf-key signer_leaf-cert signer_subinterCA-key signer_subinterCA-cert
        # cannot use KEM signer_leaf-key.pem for PKCS#10 CSR generation, using signer_subinterCA-key instead
        $OPENSSL req -new -subj "/CN=signer-leaf-csr" -key signer_subinterCA-key.pem -out signer_leaf-csr.pem
    else
        OPENSSL_KEYALG=${signer_leaf_keyalg} \
        $mkcert_sh genee -p clientAuth "signer-leaf" signer_leaf-key signer_leaf-cert signer_subinterCA-key signer_subinterCA-cert
        # create signer certificate without subjectKeyIdentifier
        # $OPENSSL req -new -subj "/CN=signer-leaf-noSKID" -key signer_leaf-key.pem \
        #  | $OPENSSL x509 -req -days $DAYS -extfile <(printf "subjectKeyIdentifier=none") -out signer_leaf-cert-noSKID.crt -CA signer_subinterCA-cert.pem -CAkey signer_subinterCA-key.pem
        $OPENSSL req -new -subj "/CN=signer-leaf-csr" -key signer_leaf-key.pem -out signer_leaf-csr.pem
    fi

    echo "Generating demoCA folder"
    mkdir -p demoCA
    touch demoCA/index.txt
    echo 1007 > demoCA/crlnumber
    $OPENSSL ca -gencrl -keyfile signer_subinterCA-key.pem -cert signer_subinterCA-cert.pem -out signer_subinterCA-crl0.pem -crldays $DAYS \
            -config <(printf "[ca]\ndefault_ca= CA_default\n[CA_default]\n%s\n%s\n%s\n" \
		      "database = ./demoCA/index.txt" "crlnumber = ./demoCA/crlnumber" "default_md = default")
    cat signer_leaf-cert.pem signer_subinterCA-cert.pem signer_interCA-cert.pem > signer_chain.pem
    cat signer_subinterCA-cert.pem signer_interCA-cert.pem signer_root-cert.pem > signer_fullchain.pem
    $OPENSSL pkcs12 -export -out signer.p12 -inkey signer_leaf-key.pem -in signer_leaf-cert.pem -certfile signer_fullchain.pem -password file:12345.txt
    rm -f signer_fullchain.pem
    cat signer_subinterCA-cert.pem signer_interCA-cert.pem > signer_issuing-cert.pem
    sleep 5 # Wait for 5 seconds before generating the next CRL
    $OPENSSL ca -gencrl -keyfile signer_subinterCA-key.pem -cert signer_subinterCA-cert.pem -out signer_subinterCA-crl1.pem -crldays $DAYS \
               -config <(printf "[ca]\ndefault_ca= CA_default\n[CA_default]\n%s\n%s\n%s\n" \
						      "database = ./demoCA/index.txt" "crlnumber = ./demoCA/crlnumber" "default_md = default")
    rename_signerfiles
    rm -rf demoCA
}

gen_server_credentials
gen_client_chain
