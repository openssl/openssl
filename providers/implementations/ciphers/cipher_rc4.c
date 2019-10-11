/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for RC4 ciphers */

#include "cipher_rc4.h"
#include "prov/implementations.h"

/* TODO (3.0) Figure out what flags are required */
#define RC4_FLAGS EVP_CIPH_FLAG_DEFAULT_ASN1

static OSSL_OP_cipher_freectx_fn rc4_freectx;
static OSSL_OP_cipher_dupctx_fn rc4_dupctx;

static void rc4_freectx(void *vctx)
{
    PROV_RC4_CTX *ctx = (PROV_RC4_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *rc4_dupctx(void *ctx)
{
    PROV_RC4_CTX *in = (PROV_RC4_CTX *)ctx;
    PROV_RC4_CTX *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    *ret = *in;

    return ret;
}

#define IMPLEMENT_cipher(alg, UCALG, flags, kbits, blkbits, ivbits, typ)       \
static OSSL_OP_cipher_get_params_fn alg##_##kbits##_get_params;                \
static int alg##_##kbits##_get_params(OSSL_PARAM params[])                     \
{                                                                              \
    return cipher_generic_get_params(params, 0, flags,                         \
                                     kbits, blkbits, ivbits);                  \
}                                                                              \
static OSSL_OP_cipher_newctx_fn alg##_##kbits##_newctx;                        \
static void * alg##_##kbits##_newctx(void *provctx)                            \
{                                                                              \
     PROV_##UCALG##_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));                   \
     if (ctx != NULL) {                                                        \
         cipher_generic_initkey(ctx, kbits, blkbits, ivbits, 0, flags,         \
                                PROV_CIPHER_HW_##alg(kbits), NULL);            \
     }                                                                         \
     return ctx;                                                               \
}                                                                              \
const OSSL_DISPATCH alg##kbits##_functions[] = {                               \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                 \
      (void (*)(void)) alg##_##kbits##_newctx },                               \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) alg##_freectx },              \
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void)) alg##_dupctx },                \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))cipher_generic_einit },   \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))cipher_generic_dinit },   \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))cipher_generic_##typ##_update },\
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))cipher_generic_##typ##_final },  \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))cipher_generic_cipher },        \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void)) alg##_##kbits##_get_params },                           \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                         \
      (void (*)(void))cipher_generic_get_ctx_params },                         \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
      (void (*)(void))cipher_generic_set_ctx_params },                         \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))cipher_generic_gettable_params },                        \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))cipher_generic_gettable_ctx_params },                    \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
     (void (*)(void))cipher_generic_settable_ctx_params },                     \
    { 0, NULL }                                                                \
};

/* rc440_functions */
IMPLEMENT_cipher(rc4, RC4, EVP_CIPH_VARIABLE_LENGTH, 40, 8, 0, stream)
/* rc4128_functions */
IMPLEMENT_cipher(rc4, RC4, EVP_CIPH_VARIABLE_LENGTH, 128, 8, 0, stream)
