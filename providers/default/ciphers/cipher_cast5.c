/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for cast cipher modes ecb, cbc, ofb, cfb */

#include "cipher_cast.h"
#include "internal/provider_algs.h"

static OSSL_OP_cipher_freectx_fn cast5_freectx;
static OSSL_OP_cipher_dupctx_fn cast5_dupctx;

static void cast5_freectx(void *vctx)
{
    PROV_CAST_CTX *ctx = (PROV_CAST_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *cast5_dupctx(void *ctx)
{
    PROV_CAST_CTX *in = (PROV_CAST_CTX *)ctx;
    PROV_CAST_CTX *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    *ret = *in;

    return ret;
}

/* cast5128ecb_functions */
IMPLEMENT_generic_cipher(cast5, CAST, ecb, ECB, EVP_CIPH_VARIABLE_LENGTH, 128, 64, 0, block)
= { "CAST5-ECB", NULL };
/* cast5128cbc_functions */
IMPLEMENT_generic_cipher(cast5, CAST, cbc, CBC, EVP_CIPH_VARIABLE_LENGTH, 128, 64, 64, block)
= { "CAST5-CBC", "CAST", "CAST-CBC", NULL };
/* cast564ofb64_functions */
IMPLEMENT_generic_cipher(cast5, CAST, ofb64, OFB, EVP_CIPH_VARIABLE_LENGTH, 64, 8, 64, stream)
= { "CAST5-OFB", NULL };
/* cast564cfb64_functions */
IMPLEMENT_generic_cipher(cast5, CAST, cfb64,  CFB, EVP_CIPH_VARIABLE_LENGTH, 64, 8, 64, stream)
= { "CAST5-CFB", NULL };
