/*
 * Copyright 2007-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include "internal/asn1_int.h"
#include "internal/poly1305.h"
#include "poly1305_local.h"

/*
 * POLY1305 "ASN1" method. This is just here to indicate the maximum
 * POLY1305 output length and to free up a POLY1305 key.
 */

static int poly1305_size(const EVP_PKEY *pkey)
{
    return POLY1305_DIGEST_SIZE;
}

static void poly1305_key_free(EVP_PKEY *pkey)
{
    ASN1_OCTET_STRING *os = EVP_PKEY_get0(pkey);
    if (os != NULL) {
        if (os->data != NULL)
            OPENSSL_cleanse(os->data, os->length);
        ASN1_OCTET_STRING_free(os);
    }
}

static int poly1305_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    /* nothing, (including ASN1_PKEY_CTRL_DEFAULT_MD_NID), is supported */
    return -2;
}

static int poly1305_pkey_public_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    return ASN1_OCTET_STRING_cmp(EVP_PKEY_get0(a), EVP_PKEY_get0(b));
}

const EVP_PKEY_ASN1_METHOD poly1305_asn1_meth = {
    EVP_PKEY_POLY1305,
    EVP_PKEY_POLY1305,
    0,

    "POLY1305",
    "OpenSSL POLY1305 method",

    0, 0, poly1305_pkey_public_cmp, 0,

    0, 0, 0,

    poly1305_size,
    0, 0,
    0, 0, 0, 0, 0, 0, 0,

    poly1305_key_free,
    poly1305_pkey_ctrl,
    0, 0
};
