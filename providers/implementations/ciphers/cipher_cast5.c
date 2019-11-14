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
#include "prov/implementations.h"
#include "prov/providercommonerr.h"

#define CAST5_FLAGS (EVP_CIPH_VARIABLE_LENGTH)

static OSSL_OP_cipher_freectx_fn cast5_freectx;
static OSSL_OP_cipher_dupctx_fn cast5_dupctx;
static OSSL_OP_cipher_settable_ctx_params_fn cast5_settable_ctx_params;

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

static int cast5_set_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_CAST_CTX *ctx = (PROV_CAST_CTX *)vctx;
    const OSSL_PARAM *p;

    if (!cipher_generic_set_ctx_params(vctx, params))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t keylen;

        if (!OSSL_PARAM_get_size_t(p, &keylen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->base.keylen = keylen;
    }
    return 1;
}

CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(cast5)
OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(cast5)

#define IMPLEMENT_cipher_func(alg, UCALG, lcmode, UCMODE, flags, kbits,        \
                              blkbits, ivbits, typ)                            \
const OSSL_DISPATCH alg##kbits##lcmode##_functions[] = {                       \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                 \
      (void (*)(void)) alg##_##kbits##_##lcmode##_newctx },                    \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) alg##_freectx },              \
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void)) alg##_dupctx },                \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))cipher_generic_einit },   \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))cipher_generic_dinit },   \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))cipher_generic_##typ##_update },\
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))cipher_generic_##typ##_final },  \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))cipher_generic_cipher },        \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void)) alg##_##kbits##_##lcmode##_get_params },                \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                         \
      (void (*)(void))cipher_generic_get_ctx_params },                         \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
      (void (*)(void))cast5_set_ctx_params },                                  \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))cipher_generic_gettable_params },                        \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))cipher_generic_gettable_ctx_params },                    \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
     (void (*)(void))cast5_settable_ctx_params },                              \
    { 0, NULL }                                                                \
};

#define IMPLEMENT_cipher(alg, UCALG, lcmode, UCMODE, flags, kbits,             \
                                 blkbits, ivbits, typ)                         \
IMPLEMENT_generic_cipher_genfn(alg, UCALG, lcmode, UCMODE, flags, kbits,       \
                               blkbits, ivbits, typ)                           \
IMPLEMENT_cipher_func(alg, UCALG, lcmode, UCMODE, flags, kbits,                \
                              blkbits, ivbits, typ)

/* cast5128ecb_functions */
IMPLEMENT_cipher(cast5, CAST, ecb, ECB, CAST5_FLAGS, 128, 64, 0, block)
/* cast5128cbc_functions */
IMPLEMENT_cipher(cast5, CAST, cbc, CBC, CAST5_FLAGS, 128, 64, 64, block)
/* cast564ofb64_functions */
IMPLEMENT_cipher(cast5, CAST, ofb64, OFB, CAST5_FLAGS, 64, 8, 64, stream)
/* cast564cfb64_functions */
IMPLEMENT_cipher(cast5, CAST, cfb64,  CFB, CAST5_FLAGS, 64, 8, 64, stream)
