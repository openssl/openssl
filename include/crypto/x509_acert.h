/*
 * Copyright 2015-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_X509_ACERT_H
# define OSSL_CRYPTO_X509_ACERT_H
# include "openssl/x509.h"
# include "openssl/types.h"
# include "internal/refcount.h"

# define X509_ACERT_ISSUER_V1 0
# define X509_ACERT_ISSUER_V2 1

typedef struct ossl_object_digest_info_st {
    ASN1_ENUMERATED *digestedObjectType;
    ASN1_OBJECT *otherObjectTypeID;
    X509_ALGOR *digestAlgorithm;
    ASN1_BIT_STRING *objectDigest;
} OSSL_OBJECT_DIGEST_INFO;

typedef struct X509_acert_issuer_v2form_st {
    STACK_OF(GENERAL_NAME) *issuerName;
    OSSL_ISSUER_SERIAL *baseCertificateId;
    OSSL_OBJECT_DIGEST_INFO *objectDigestInfo;
} X509_ACERT_ISSUER_V2FORM;

typedef struct X509_acert_issuer_st {
    int type;
    union {
        STACK_OF(GENERAL_NAME) *v1Form;
        X509_ACERT_ISSUER_V2FORM *v2Form;
    } u;
} X509_ACERT_ISSUER;

typedef struct X509_holder_st {
    OSSL_ISSUER_SERIAL *baseCertificateID;
    STACK_OF(GENERAL_NAME) *entityName;
    OSSL_OBJECT_DIGEST_INFO *objectDigestInfo;
} X509_HOLDER;

typedef struct X509_acert_info_st {
    ASN1_INTEGER version;      /* default of v2 */
    X509_HOLDER holder;
    X509_ACERT_ISSUER issuer;
    X509_ALGOR signature;
    ASN1_INTEGER serialNumber;
    X509_VAL validityPeriod;
    STACK_OF(X509_ATTRIBUTE) *attributes;
    ASN1_BIT_STRING *issuerUID;
    X509_EXTENSIONS *extensions;
    ASN1_ENCODING enc;                      /* encoding of signed portion of CRL */
} X509_ACERT_INFO;

typedef struct X509_acert_st {
    X509_ACERT_INFO *acinfo;
    X509_ALGOR sig_alg;
    ASN1_BIT_STRING signature;
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;
} X509_ACERT;

int ossl_x509_check_acert_time(X509_STORE_CTX *ctx, X509_ACERT *acert);
int ossl_x509_check_acert_exts(X509_ACERT *acert);
int X509_attr_cert_verify(X509_STORE_CTX *ctx, X509_ACERT *acert);
int acert_crl(X509_STORE_CTX *ctx, X509_CRL *crl, X509_ACERT *x);

#endif
