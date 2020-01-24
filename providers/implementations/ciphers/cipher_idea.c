/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * IDEA low level APIs are deprecated for public use, but still ok for internal
 * use where we're using them to implement the higher level EVP interface, as is
 * the case here.
 */
#include "internal/deprecated.h"

/* Dispatch functions for Idea cipher modes ecb, cbc, ofb, cfb */

#include "cipher_idea.h"
#include "prov/implementations.h"

static OSSL_OP_cipher_freectx_fn idea_freectx;
static OSSL_OP_cipher_dupctx_fn idea_dupctx;

static void idea_freectx(void *vctx)
{
    PROV_IDEA_CTX *ctx = (PROV_IDEA_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *idea_dupctx(void *ctx)
{
    PROV_IDEA_CTX *in = (PROV_IDEA_CTX *)ctx;
    PROV_IDEA_CTX *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    *ret = *in;

    return ret;
}

/* idea128ecb_functions */
IMPLEMENT_generic_cipher(idea, IDEA, ecb, ECB, 0, 128, 64, 0, block)
/* idea128cbc_functions */
IMPLEMENT_generic_cipher(idea, IDEA, cbc, CBC, 0, 128, 64, 64, block)
/* idea128ofb64_functions */
IMPLEMENT_generic_cipher(idea, IDEA, ofb64, OFB, 0, 128, 8, 64, stream)
/* idea128cfb64_functions */
IMPLEMENT_generic_cipher(idea, IDEA, cfb64,  CFB, 0, 128, 8, 64, stream)
