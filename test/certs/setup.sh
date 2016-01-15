#! /bin/sh

# Primary root: root-cert
# root certs variants: CA:false, key2, DN2
# trust variants: +serverAuth -serverAuth +clientAuth
#
./mkcert.sh genroot "Root CA" root-key root-cert
./mkcert.sh genss "Root CA" root-key root-nonca
./mkcert.sh genroot "Root CA" root-key2 root-cert2
./mkcert.sh genroot "Root Cert 2" root-key root-name2
#
openssl x509 -in root-cert.pem -trustout \
    -addtrust serverAuth -out root+serverAuth.pem
openssl x509 -in root-cert.pem -trustout \
    -addreject serverAuth -out root-serverAuth.pem
openssl x509 -in root-cert.pem -trustout \
    -addtrust clientAuth -out root+clientAuth.pem

# Primary intermediate ca: ca-cert
# ca variants: CA:false, key2, DN2, issuer2, expired
# trust variants: +serverAuth, -serverAuth, +clientAuth
#
./mkcert.sh genca "CA" ca-key ca-cert root-key root-cert
./mkcert.sh genee "CA" ca-key ca-nonca root-key root-cert
./mkcert.sh genca "CA" ca-key2 ca-cert2 root-key root-cert
./mkcert.sh genca "CA2" ca-key ca-name2 root-key root-cert
./mkcert.sh genca "CA" ca-key ca-root2 root-key2 root-cert2
./mkcert.sh genca "CA" ca-key ca-expired root-key root-cert -days -1
#
openssl x509 -in ca-cert.pem -trustout \
    -addtrust serverAuth -out ca+serverAuth.pem
openssl x509 -in ca-cert.pem -trustout \
    -addreject serverAuth -out ca-serverAuth.pem
openssl x509 -in ca-cert.pem -trustout \
    -addtrust clientAuth -out ca+clientAuth.pem

# Primary leaf cert: ee-cert
# ee variants: expired, issuer-key2, issuer-name2
# trust variants: +serverAuth, -serverAuth, +clientAuth, -clientAuth
# purpose variants: client
#
./mkcert.sh genee server.example ee-key ee-cert ca-key ca-cert
./mkcert.sh genee server.example ee-key ee-expired ca-key ca-cert -days -1
./mkcert.sh genee server.example ee-key ee-cert2 ca-key2 ca-cert2
./mkcert.sh genee server.example ee-key ee-name2 ca-key ca-name2
./mkcert.sh genee -p clientAuth server.example ee-key ee-client ca-key ca-cert
#
openssl x509 -in ee-cert.pem -trustout \
    -addtrust serverAuth -out ee+serverAuth.pem
openssl x509 -in ee-cert.pem -trustout \
    -addreject serverAuth -out ee-serverAuth.pem
openssl x509 -in ee-client.pem -trustout \
    -addtrust clientAuth -out ee+clientAuth.pem
openssl x509 -in ee-client.pem -trustout \
    -addreject clientAuth -out ee-clientAuth.pem
