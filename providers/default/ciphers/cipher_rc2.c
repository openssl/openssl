/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for RC2 cipher modes ecb, cbc, ofb, cfb */

#include "cipher_rc2.h"
#include "internal/provider_algs.h"
#include "internal/providercommonerr.h"

static OSSL_OP_cipher_freectx_fn rc2_freectx;
static OSSL_OP_cipher_dupctx_fn rc2_dupctx;
static OSSL_OP_cipher_gettable_ctx_params_fn rc2_gettable_ctx_params;
static OSSL_OP_cipher_settable_ctx_params_fn rc2_settable_ctx_params;

static void rc2_freectx(void *vctx)
{
    PROV_RC2_CTX *ctx = (PROV_RC2_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *rc2_dupctx(void *ctx)
{
    PROV_RC2_CTX *in = (PROV_RC2_CTX *)ctx;
    PROV_RC2_CTX *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    *ret = *in;

    return ret;
}

static int rc2_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_RC2_CTX *ctx = (PROV_RC2_CTX *)vctx;
    OSSL_PARAM *p;

    if (!cipher_generic_get_ctx_params(vctx, params))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_RC2_KEYBITS);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->key_bits)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

static int rc2_set_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_RC2_CTX *ctx = (PROV_RC2_CTX *)vctx;
    const OSSL_PARAM *p;

    if (!cipher_generic_set_ctx_params(vctx, params))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_RC2_KEYBITS);
    if (p != NULL) {
         if (!OSSL_PARAM_get_size_t(p, &ctx->key_bits)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }

    return 1;
}

CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START(rc2)
OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_RC2_KEYBITS, NULL),
CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_END(rc2)

CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(rc2)
OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_RC2_KEYBITS, NULL),
CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(rc2)

#define IMPLEMENT_cipher(alg, UCALG, lcmode, UCMODE, flags, kbits, blkbits,    \
                         ivbits, typ)                                          \
static OSSL_OP_cipher_get_params_fn alg##_##kbits##_##lcmode##_get_params;     \
static int alg##_##kbits##_##lcmode##_get_params(OSSL_PARAM params[])          \
{                                                                              \
    return cipher_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE, flags,  \
                                     kbits, blkbits, ivbits);                  \
}                                                                              \
static OSSL_OP_cipher_newctx_fn alg##_##kbits##_##lcmode##_newctx;             \
static void * alg##_##kbits##_##lcmode##_newctx(void *provctx)                 \
{                                                                              \
     PROV_##UCALG##_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));                   \
     if (ctx != NULL) {                                                        \
         cipher_generic_initkey(ctx, kbits, blkbits, ivbits,                   \
                                EVP_CIPH_##UCMODE##_MODE, flags,               \
                                PROV_CIPHER_HW_##alg##_##lcmode(kbits), NULL); \
         ctx->key_bits = kbits;                                                \
     }                                                                         \
     return ctx;                                                               \
}                                                                              \
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
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))cipher_generic_gettable_params },                        \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                         \
      (void (*)(void))rc2_get_ctx_params },                                    \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))rc2_gettable_ctx_params },                               \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
      (void (*)(void))rc2_set_ctx_params },                                    \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
     (void (*)(void))rc2_settable_ctx_params },                                \
    { 0, NULL }                                                                \
};

/* rc2128ecb_functions */
IMPLEMENT_cipher(rc2, RC2, ecb, ECB, EVP_CIPH_VARIABLE_LENGTH, 128, 64, 0, block)
/* rc2128cbc_functions */
IMPLEMENT_cipher(rc2, RC2, cbc, CBC, EVP_CIPH_VARIABLE_LENGTH, 128, 64, 64, block)
/* rc240cbc_functions */
IMPLEMENT_cipher(rc2, RC2, cbc, CBC, EVP_CIPH_VARIABLE_LENGTH, 40, 64, 64, block)
/* rc264cbc_functions */
IMPLEMENT_cipher(rc2, RC2, cbc, CBC, EVP_CIPH_VARIABLE_LENGTH, 64, 64, 64, block)

/* rc2128ofb128_functions */
IMPLEMENT_cipher(rc2, RC2, ofb128, OFB, EVP_CIPH_VARIABLE_LENGTH, 128, 8, 64, stream)
/* rc2128cfb128_functions */
IMPLEMENT_cipher(rc2, RC2, cfb128, CFB, EVP_CIPH_VARIABLE_LENGTH, 128, 8, 64, stream)
