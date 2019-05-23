/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for Blowfish cipher modes ecb, cbc, ofb, cfb */

#include "cipher_blowfish.h"
#include "internal/provider_algs.h"

static OSSL_OP_cipher_freectx_fn blowfish_freectx;
static OSSL_OP_cipher_dupctx_fn blowfish_dupctx;

static void blowfish_freectx(void *vctx)
{
    PROV_BLOWFISH_CTX *ctx = (PROV_BLOWFISH_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *blowfish_dupctx(void *ctx)
{
    PROV_BLOWFISH_CTX *in = (PROV_BLOWFISH_CTX *)ctx;
    PROV_BLOWFISH_CTX *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    *ret = *in;

    return ret;
}

/* bf_ecb_functions */
IMPLEMENT_generic_cipher(blowfish, BLOWFISH, ecb, ECB, EVP_CIPH_VARIABLE_LENGTH, 128, 64, 0, block)
= { "BF-ECB", NULL };
/* bf_cbc_functions */
IMPLEMENT_generic_cipher(blowfish, BLOWFISH, cbc, CBC, EVP_CIPH_VARIABLE_LENGTH, 128, 64, 64, block)
= { "BF-CBC", "BF", "BLOWFISH", NULL };
/* bf_ofb_functions */
IMPLEMENT_generic_cipher(blowfish, BLOWFISH, ofb64, OFB, EVP_CIPH_VARIABLE_LENGTH, 64, 8, 64, stream)
= { "BF-OFB", NULL };
/* bf_cfb_functions */
IMPLEMENT_generic_cipher(blowfish, BLOWFISH, cfb64,  CFB, EVP_CIPH_VARIABLE_LENGTH, 64, 8, 64, stream)
= { "BF-CFB", NULL };
