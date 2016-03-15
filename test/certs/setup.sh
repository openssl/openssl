#! /bin/sh

# Primary root: root-cert
# root cert variants: CA:false, key2, DN2
# trust variants: +serverAuth -serverAuth +clientAuth -clientAuth +anyEKU -anyEKU
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
openssl x509 -in root-cert.pem -trustout \
    -addreject clientAuth -out root-clientAuth.pem
openssl x509 -in root-cert.pem -trustout \
    -addreject anyExtendedKeyUsage -out root-anyEKU.pem
openssl x509 -in root-cert.pem -trustout \
    -addtrust anyExtendedKeyUsage -out root+anyEKU.pem
openssl x509 -in root-cert2.pem -trustout \
    -addtrust serverAuth -out root2+serverAuth.pem
openssl x509 -in root-cert2.pem -trustout \
    -addreject serverAuth -out root2-serverAuth.pem
openssl x509 -in root-cert2.pem -trustout \
    -addtrust clientAuth -out root2+clientAuth.pem
openssl x509 -in root-nonca.pem -trustout \
    -addtrust serverAuth -out nroot+serverAuth.pem
openssl x509 -in root-nonca.pem -trustout \
    -addtrust anyExtendedKeyUsage -out nroot+anyEKU.pem

# Root CA security level variants:
# MD5 self-signature
OPENSSL_SIGALG=md5 \
./mkcert.sh genroot "Root CA" root-key root-cert-md5
# 768-bit key
OPENSSL_KEYBITS=768 \
./mkcert.sh genroot "Root CA" root-key-768 root-cert-768

# primary client-EKU root: croot-cert
# trust variants: +serverAuth -serverAuth +clientAuth +anyEKU -anyEKU
#
./mkcert.sh genroot "Root CA" root-key croot-cert clientAuth
#
openssl x509 -in croot-cert.pem -trustout \
    -addtrust serverAuth -out croot+serverAuth.pem
openssl x509 -in croot-cert.pem -trustout \
    -addreject serverAuth -out croot-serverAuth.pem
openssl x509 -in croot-cert.pem -trustout \
    -addtrust clientAuth -out croot+clientAuth.pem
openssl x509 -in croot-cert.pem -trustout \
    -addreject clientAuth -out croot-clientAuth.pem
openssl x509 -in croot-cert.pem -trustout \
    -addreject anyExtendedKeyUsage -out croot-anyEKU.pem
openssl x509 -in croot-cert.pem -trustout \
    -addtrust anyExtendedKeyUsage -out croot+anyEKU.pem

# primary server-EKU root: sroot-cert
# trust variants: +serverAuth -serverAuth +clientAuth +anyEKU -anyEKU
#
./mkcert.sh genroot "Root CA" root-key sroot-cert serverAuth
#
openssl x509 -in sroot-cert.pem -trustout \
    -addtrust serverAuth -out sroot+serverAuth.pem
openssl x509 -in sroot-cert.pem -trustout \
    -addreject serverAuth -out sroot-serverAuth.pem
openssl x509 -in sroot-cert.pem -trustout \
    -addtrust clientAuth -out sroot+clientAuth.pem
openssl x509 -in sroot-cert.pem -trustout \
    -addreject clientAuth -out sroot-clientAuth.pem
openssl x509 -in sroot-cert.pem -trustout \
    -addreject anyExtendedKeyUsage -out sroot-anyEKU.pem
openssl x509 -in sroot-cert.pem -trustout \
    -addtrust anyExtendedKeyUsage -out sroot+anyEKU.pem

# Primary intermediate ca: ca-cert
# ca variants: CA:false, key2, DN2, issuer2, expired
# trust variants: +serverAuth, -serverAuth, +clientAuth, -clientAuth, -anyEKU, +anyEKU
#
./mkcert.sh genca "CA" ca-key ca-cert root-key root-cert
./mkcert.sh genee "CA" ca-key ca-nonca root-key root-cert
./mkcert.sh gen_nonbc_ca "CA" ca-key ca-nonbc root-key root-cert
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
openssl x509 -in ca-cert.pem -trustout \
    -addreject clientAuth -out ca-clientAuth.pem
openssl x509 -in ca-cert.pem -trustout \
    -addreject anyExtendedKeyUsage -out ca-anyEKU.pem
openssl x509 -in ca-cert.pem -trustout \
    -addtrust anyExtendedKeyUsage -out ca+anyEKU.pem
openssl x509 -in ca-nonca.pem -trustout \
    -addtrust serverAuth -out nca+serverAuth.pem
openssl x509 -in ca-nonca.pem -trustout \
    -addtrust serverAuth -out nca+anyEKU.pem

# Intermediate CA security variants:
# MD5 issuer signature,
OPENSSL_SIGALG=md5 \
./mkcert.sh genca "CA" ca-key ca-cert-md5 root-key root-cert
openssl x509 -in ca-cert-md5.pem -trustout \
    -addtrust anyExtendedKeyUsage -out ca-cert-md5-any.pem
# Issuer has 768-bit key
./mkcert.sh genca "CA" ca-key ca-cert-768i root-key-768 root-cert-768
# CA has 768-bit key
OPENSSL_KEYBITS=768 \
./mkcert.sh genca "CA" ca-key-768 ca-cert-768 root-key root-cert

# client intermediate ca: cca-cert
# trust variants: +serverAuth, -serverAuth, +clientAuth, -clientAuth
#
./mkcert.sh genca "CA" ca-key cca-cert root-key root-cert clientAuth
#
openssl x509 -in cca-cert.pem -trustout \
    -addtrust serverAuth -out cca+serverAuth.pem
openssl x509 -in cca-cert.pem -trustout \
    -addreject serverAuth -out cca-serverAuth.pem
openssl x509 -in cca-cert.pem -trustout \
    -addtrust clientAuth -out cca+clientAuth.pem
openssl x509 -in cca-cert.pem -trustout \
    -addtrust clientAuth -out cca-clientAuth.pem
openssl x509 -in cca-cert.pem -trustout \
    -addreject anyExtendedKeyUsage -out cca-anyEKU.pem
openssl x509 -in cca-cert.pem -trustout \
    -addtrust anyExtendedKeyUsage -out cca+anyEKU.pem

# server intermediate ca: sca-cert
# trust variants: +serverAuth, -serverAuth, +clientAuth, -clientAuth, -anyEKU, +anyEKU
#
./mkcert.sh genca "CA" ca-key sca-cert root-key root-cert serverAuth
#
openssl x509 -in sca-cert.pem -trustout \
    -addtrust serverAuth -out sca+serverAuth.pem
openssl x509 -in sca-cert.pem -trustout \
    -addreject serverAuth -out sca-serverAuth.pem
openssl x509 -in sca-cert.pem -trustout \
    -addtrust clientAuth -out sca+clientAuth.pem
openssl x509 -in sca-cert.pem -trustout \
    -addreject clientAuth -out sca-clientAuth.pem
openssl x509 -in sca-cert.pem -trustout \
    -addreject anyExtendedKeyUsage -out sca-anyEKU.pem
openssl x509 -in sca-cert.pem -trustout \
    -addtrust anyExtendedKeyUsage -out sca+anyEKU.pem

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

# Leaf cert security level variants
# MD5 issuer signature
OPENSSL_SIGALG=md5 \
./mkcert.sh genee server.example ee-key ee-cert-md5 ca-key ca-cert
# 768-bit issuer key
./mkcert.sh genee server.example ee-key ee-cert-768i ca-key-768 ca-cert-768
# 768-bit leaf key
OPENSSL_KEYBITS=768 \
./mkcert.sh genee server.example ee-key-768 ee-cert-768 ca-key ca-cert
