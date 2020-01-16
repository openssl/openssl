/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/core_numbers.h>
#include "prov/implementations.h"
#include "prov/ciphercommon.h"
#include "prov/providercommonerr.h"

static OSSL_OP_cipher_newctx_fn null_newctx;
static void *null_newctx(void *provctx)
{
    static int dummy = 0;

    return &dummy;
}

static OSSL_OP_cipher_freectx_fn null_freectx;
static void null_freectx(void *vctx)
{
}

static OSSL_OP_cipher_encrypt_init_fn null_init;
static int null_init(void *vctx, const unsigned char *key, size_t keylen,
                     const unsigned char *iv, size_t ivlen)
{
    return 1;
}

static OSSL_OP_cipher_cipher_fn null_cipher;
static int null_cipher(void *vctx, unsigned char *out, size_t *outl,
                       size_t outsize, const unsigned char *in, size_t inl)
{
    if (outsize < inl)
        return 0;
    if (in != out)
        memcpy(out, in, inl);
    *outl = inl;
    return 1;
}

static OSSL_OP_cipher_final_fn null_final;
static int null_final(void *vctx, unsigned char *out, size_t *outl,
                      size_t outsize)
{
    *outl = 0;
    return 1;
}

static OSSL_OP_cipher_get_params_fn null_get_params;
static int null_get_params(OSSL_PARAM params[])
{
    return cipher_generic_get_params(params, 0, 0, 0, 8, 0);
}

static const OSSL_PARAM null_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_END
};

static OSSL_OP_cipher_gettable_ctx_params_fn null_gettable_ctx_params;
static const OSSL_PARAM *null_gettable_ctx_params(void)
{
    return null_known_gettable_ctx_params;
}

static OSSL_OP_cipher_get_ctx_params_fn null_get_ctx_params;
static int null_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

const OSSL_DISPATCH null_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX,
      (void (*)(void)) null_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) null_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void)) null_newctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))null_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))null_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))null_cipher },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))null_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))null_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void)) null_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
        (void (*)(void))cipher_generic_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))null_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
      (void (*)(void))null_gettable_ctx_params },
    { 0, NULL }
};
