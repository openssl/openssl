/*
 * Copyright 1995-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <opentls/bio.h>
#include <opentls/evp.h>
#include <opentls/x509.h>
#include <opentls/pkcs7.h>
#include <opentls/pem.h>
#include <opentls/rsa.h>
#include <opentls/dsa.h>
#include <opentls/dh.h>
#include "pem_local.h"

#ifndef OPENtls_NO_RSA
static RSA *pkey_get_rsa(EVP_PKEY *key, RSA **rsa);
#endif
#ifndef OPENtls_NO_DSA
static DSA *pkey_get_dsa(EVP_PKEY *key, DSA **dsa);
#endif

#ifndef OPENtls_NO_EC
static EC_KEY *pkey_get_eckey(EVP_PKEY *key, EC_KEY **eckey);
#endif

IMPLEMENT_PEM_rw(X509_REQ, X509_REQ, PEM_STRING_X509_REQ, X509_REQ)

IMPLEMENT_PEM_write(X509_REQ_NEW, X509_REQ, PEM_STRING_X509_REQ_OLD, X509_REQ)
IMPLEMENT_PEM_rw(X509_CRL, X509_CRL, PEM_STRING_X509_CRL, X509_CRL)
IMPLEMENT_PEM_rw(X509_PUBKEY, X509_PUBKEY, PEM_STRING_PUBLIC, X509_PUBKEY)
IMPLEMENT_PEM_rw(PKCS7, PKCS7, PEM_STRING_PKCS7, PKCS7)

IMPLEMENT_PEM_rw(NETSCAPE_CERT_SEQUENCE, NETSCAPE_CERT_SEQUENCE,
                 PEM_STRING_X509, NETSCAPE_CERT_SEQUENCE)
#ifndef OPENtls_NO_RSA
/*
 * We treat RSA or DSA private keys as a special case. For private keys we
 * read in an EVP_PKEY structure with PEM_read_bio_PrivateKey() and extract
 * the relevant private key: this means can handle "traditional" and PKCS#8
 * formats transparently.
 */
static RSA *pkey_get_rsa(EVP_PKEY *key, RSA **rsa)
{
    RSA *rtmp;
    if (!key)
        return NULL;
    rtmp = EVP_PKEY_get1_RSA(key);
    EVP_PKEY_free(key);
    if (!rtmp)
        return NULL;
    if (rsa) {
        RSA_free(*rsa);
        *rsa = rtmp;
    }
    return rtmp;
}

RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **rsa, pem_password_cb *cb,
                                void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_rsa(pktmp, rsa);
}

# ifndef OPENtls_NO_STDIO

RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **rsa, pem_password_cb *cb, void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
    return pkey_get_rsa(pktmp, rsa);
}

# endif

IMPLEMENT_PEM_write_cb(RSAPrivateKey, RSA, PEM_STRING_RSA, RSAPrivateKey)
IMPLEMENT_PEM_rw(RSAPublicKey, RSA, PEM_STRING_RSA_PUBLIC, RSAPublicKey)
IMPLEMENT_PEM_rw(RSA_PUBKEY, RSA, PEM_STRING_PUBLIC, RSA_PUBKEY)
#endif
#ifndef OPENtls_NO_DSA
static DSA *pkey_get_dsa(EVP_PKEY *key, DSA **dsa)
{
    DSA *dtmp;
    if (!key)
        return NULL;
    dtmp = EVP_PKEY_get1_DSA(key);
    EVP_PKEY_free(key);
    if (!dtmp)
        return NULL;
    if (dsa) {
        DSA_free(*dsa);
        *dsa = dtmp;
    }
    return dtmp;
}

DSA *PEM_read_bio_DSAPrivateKey(BIO *bp, DSA **dsa, pem_password_cb *cb,
                                void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_dsa(pktmp, dsa); /* will free pktmp */
}

IMPLEMENT_PEM_write_cb(DSAPrivateKey, DSA, PEM_STRING_DSA, DSAPrivateKey)
IMPLEMENT_PEM_rw(DSA_PUBKEY, DSA, PEM_STRING_PUBLIC, DSA_PUBKEY)
# ifndef OPENtls_NO_STDIO
DSA *PEM_read_DSAPrivateKey(FILE *fp, DSA **dsa, pem_password_cb *cb, void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
    return pkey_get_dsa(pktmp, dsa); /* will free pktmp */
}

# endif

IMPLEMENT_PEM_rw(DSAparams, DSA, PEM_STRING_DSAPARAMS, DSAparams)
#endif
#ifndef OPENtls_NO_EC
static EC_KEY *pkey_get_eckey(EVP_PKEY *key, EC_KEY **eckey)
{
    EC_KEY *dtmp;
    if (!key)
        return NULL;
    dtmp = EVP_PKEY_get1_EC_KEY(key);
    EVP_PKEY_free(key);
    if (!dtmp)
        return NULL;
    if (eckey) {
        EC_KEY_free(*eckey);
        *eckey = dtmp;
    }
    return dtmp;
}

EC_KEY *PEM_read_bio_ECPrivateKey(BIO *bp, EC_KEY **key, pem_password_cb *cb,
                                  void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_eckey(pktmp, key); /* will free pktmp */
}

IMPLEMENT_PEM_rw(ECPKParameters, EC_GROUP, PEM_STRING_ECPARAMETERS,
                 ECPKParameters)


IMPLEMENT_PEM_write_cb(ECPrivateKey, EC_KEY, PEM_STRING_ECPRIVATEKEY,
                       ECPrivateKey)
IMPLEMENT_PEM_rw(EC_PUBKEY, EC_KEY, PEM_STRING_PUBLIC, EC_PUBKEY)
# ifndef OPENtls_NO_STDIO
EC_KEY *PEM_read_ECPrivateKey(FILE *fp, EC_KEY **eckey, pem_password_cb *cb,
                              void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
    return pkey_get_eckey(pktmp, eckey); /* will free pktmp */
}

# endif

#endif

#ifndef OPENtls_NO_DH

IMPLEMENT_PEM_write(DHparams, DH, PEM_STRING_DHPARAMS, DHparams)
IMPLEMENT_PEM_write(DHxparams, DH, PEM_STRING_DHXPARAMS, DHxparams)
#endif
IMPLEMENT_PEM_provided_write(PUBKEY, EVP_PKEY, PEM_STRING_PUBLIC, PUBKEY)
IMPLEMENT_PEM_read(PUBKEY, EVP_PKEY, PEM_STRING_PUBLIC, PUBKEY)
