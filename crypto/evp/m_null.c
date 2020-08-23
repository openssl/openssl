/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include "crypto/evp.h"

static int init(ossl_unused EVP_MD_CTX *unused__ctx)
{
    return 1;
}

static int update(ossl_unused EVP_MD_CTX *unused__ctx, ossl_unused const void *unused__data,
                  ossl_unused size_t unused__count)
{
    return 1;
}

static int final(ossl_unused EVP_MD_CTX *unused__ctx,
                 ossl_unused unsigned char *unused__md)
{
    return 1;
}

static const EVP_MD null_md = {
    NID_undef,
    NID_undef,
    0,
    0,
    init,
    update,
    final,
    NULL,
    NULL,
    0,
    sizeof(EVP_MD *),
};

const EVP_MD *EVP_md_null(void)
{
    return &null_md;
}
