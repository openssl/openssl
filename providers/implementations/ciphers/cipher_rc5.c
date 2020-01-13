/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/* Dispatch functions for RC5 cipher modes ecb, cbc, ofb, cfb */

#include "cipher_rc5.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"

static Otls_OP_cipher_freectx_fn rc5_freectx;
static Otls_OP_cipher_dupctx_fn rc5_dupctx;
Otls_OP_cipher_gettable_ctx_params_fn rc5_gettable_ctx_params;
Otls_OP_cipher_settable_ctx_params_fn rc5_settable_ctx_params;

static void rc5_freectx(void *vctx)
{
    PROV_RC5_CTX *ctx = (PROV_RC5_CTX *)vctx;

    OPENtls_clear_free(ctx,  sizeof(*ctx));
}

static void *rc5_dupctx(void *ctx)
{
    PROV_RC5_CTX *in = (PROV_RC5_CTX *)ctx;
    PROV_RC5_CTX *ret = OPENtls_malloc(sizeof(*ret));

    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    *ret = *in;

    return ret;
}

static int rc5_set_ctx_params(void *vctx, const Otls_PARAM params[])
{
    PROV_RC5_CTX *ctx = (PROV_RC5_CTX *)vctx;
    const Otls_PARAM *p;

    if (!cipher_var_keylen_set_ctx_params(vctx, params))
        return 0;

    p = Otls_PARAM_locate_const(params, Otls_CIPHER_PARAM_ROUNDS);
    if (p != NULL) {
        unsigned int rounds;

        if (!Otls_PARAM_get_uint(p, &rounds)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (rounds != RC5_8_ROUNDS
            && rounds != RC5_12_ROUNDS
            && rounds != RC5_16_ROUNDS) {
            ERR_raise(ERR_LIB_PROV, PROV_R_UNSUPPORTED_NUMBER_OF_ROUNDS);
            return 0;
        }
        ctx->rounds = rounds;
    }
    return 1;
}

CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START(rc5)
    Otls_PARAM_uint(Otls_CIPHER_PARAM_ROUNDS, NULL),
CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_END(rc5)

CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(rc5)
    Otls_PARAM_size_t(Otls_CIPHER_PARAM_KEYLEN, NULL),
    Otls_PARAM_uint(Otls_CIPHER_PARAM_ROUNDS, NULL),
CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(rc5)


static int rc5_get_ctx_params(void *vctx, Otls_PARAM params[])
{
    PROV_RC5_CTX *ctx = (PROV_RC5_CTX *)vctx;
    Otls_PARAM *p;

    if (!cipher_generic_get_ctx_params(vctx, params))
        return 0;
    p = Otls_PARAM_locate(params, Otls_CIPHER_PARAM_ROUNDS);
    if (p != NULL && !Otls_PARAM_set_uint(p, ctx->rounds)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

#define IMPLEMENT_cipher(alg, UCALG, lcmode, UCMODE, flags, kbits,             \
                         blkbits, ivbits, typ)                                 \
static Otls_OP_cipher_get_params_fn alg##_##kbits##_##lcmode##_get_params;     \
static int alg##_##kbits##_##lcmode##_get_params(Otls_PARAM params[])          \
{                                                                              \
    return cipher_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE, flags,  \
                                     kbits, blkbits, ivbits);                  \
}                                                                              \
static Otls_OP_cipher_newctx_fn alg##_##kbits##_##lcmode##_newctx;             \
static void * alg##_##kbits##_##lcmode##_newctx(void *provctx)                 \
{                                                                              \
     PROV_##UCALG##_CTX *ctx = OPENtls_zalloc(sizeof(*ctx));                   \
     if (ctx != NULL) {                                                        \
         cipher_generic_initkey(ctx, kbits, blkbits, ivbits,                   \
                                EVP_CIPH_##UCMODE##_MODE, flags,               \
                                PROV_CIPHER_HW_##alg##_##lcmode(kbits), NULL); \
         ctx->rounds = RC5_12_ROUNDS;                                          \
     }                                                                         \
     return ctx;                                                               \
}                                                                              \
const Otls_DISPATCH alg##kbits##lcmode##_functions[] = {                       \
    { Otls_FUNC_CIPHER_NEWCTX,                                                 \
      (void (*)(void)) alg##_##kbits##_##lcmode##_newctx },                    \
    { Otls_FUNC_CIPHER_FREECTX, (void (*)(void)) alg##_freectx },              \
    { Otls_FUNC_CIPHER_DUPCTX, (void (*)(void)) alg##_dupctx },                \
    { Otls_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))cipher_generic_einit },   \
    { Otls_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))cipher_generic_dinit },   \
    { Otls_FUNC_CIPHER_UPDATE, (void (*)(void))cipher_generic_##typ##_update },\
    { Otls_FUNC_CIPHER_FINAL, (void (*)(void))cipher_generic_##typ##_final },  \
    { Otls_FUNC_CIPHER_CIPHER, (void (*)(void))cipher_generic_cipher },        \
    { Otls_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void)) alg##_##kbits##_##lcmode##_get_params },                \
    { Otls_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))cipher_generic_gettable_params },                        \
    { Otls_FUNC_CIPHER_GET_CTX_PARAMS,                                         \
      (void (*)(void))rc5_get_ctx_params },                                    \
    { Otls_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))rc5_gettable_ctx_params },                               \
    { Otls_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
      (void (*)(void))rc5_set_ctx_params },                                    \
    { Otls_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
     (void (*)(void))rc5_settable_ctx_params },                                \
    { 0, NULL }                                                                \
};

/* rc5128ecb_functions */
IMPLEMENT_cipher(rc5, RC5, ecb, ECB, EVP_CIPH_VARIABLE_LENGTH, 128, 64, 0, block)
/* rc5128cbc_functions */
IMPLEMENT_cipher(rc5, RC5, cbc, CBC, EVP_CIPH_VARIABLE_LENGTH, 128, 64, 64, block)
/* rc5128ofb64_functions */
IMPLEMENT_cipher(rc5, RC5, ofb64, OFB, EVP_CIPH_VARIABLE_LENGTH, 128, 8, 64, stream)
/* rc5128cfb64_functions */
IMPLEMENT_cipher(rc5, RC5, cfb64,  CFB, EVP_CIPH_VARIABLE_LENGTH, 128, 8, 64, stream)
