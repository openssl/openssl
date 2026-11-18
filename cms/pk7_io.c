/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include "crypto/pkcs7.h"

#if !defined(OPENSSL_NO_STDIO)
PKCS7 *d2i_PKCS7_fp(FILE *fp, PKCS7 **p7)
{
    PKCS7 *ret;
    OSSL_LIB_CTX *libctx = NULL;
    const char *propq = NULL;

    if (p7 != NULL && *p7 != NULL) {
        libctx = (*p7)->ctx.libctx;
        propq = (*p7)->ctx.propq;
    }

    ret = ASN1_item_d2i_fp_ex(ASN1_ITEM_rptr(PKCS7), fp, p7, libctx, propq);
    if (ret != NULL)
        ossl_pkcs7_SignerInfos_set_ctx(ret);
    return ret;
}

int i2d_PKCS7_fp(FILE *fp, const PKCS7 *p7)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(PKCS7), fp, p7);
}
#endif /* !defined(OPENSSL_NO_STDIO) */

PKCS7 *d2i_PKCS7_bio(BIO *bp, PKCS7 **p7)
{
    PKCS7 *ret;
    OSSL_LIB_CTX *libctx = NULL;
    const char *propq = NULL;

    if (p7 != NULL && *p7 != NULL) {
        libctx = (*p7)->ctx.libctx;
        propq = (*p7)->ctx.propq;
    }

    ret = ASN1_item_d2i_bio_ex(ASN1_ITEM_rptr(PKCS7), bp, p7, libctx, propq);
    if (ret != NULL)
        ossl_pkcs7_SignerInfos_set_ctx(ret);
    return ret;
}

int i2d_PKCS7_bio(BIO *bp, const PKCS7 *p7)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(PKCS7), bp, p7);
}

int PKCS7_ISSUER_AND_SERIAL_digest(PKCS7_ISSUER_AND_SERIAL *data,
    const EVP_MD *type, unsigned char *md,
    unsigned int *len)
{
    return ASN1_item_digest(ASN1_ITEM_rptr(PKCS7_ISSUER_AND_SERIAL), type,
        (char *)data, md, len);
}

IMPLEMENT_PEM_rw(PKCS7, PKCS7, PEM_STRING_PKCS7, PKCS7)
