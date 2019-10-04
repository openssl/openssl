/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "prov/ciphercommon.h"
#include "cipher_des.h"
#include "crypto/rand.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"

/* TODO(3.0) Figure out what flags need to be here */
#define DES_FLAGS (EVP_CIPH_RAND_KEY)

static OSSL_OP_cipher_freectx_fn des_freectx;
static OSSL_OP_cipher_encrypt_init_fn des_einit;
static OSSL_OP_cipher_decrypt_init_fn des_dinit;
static OSSL_OP_cipher_get_ctx_params_fn des_get_ctx_params;
static OSSL_OP_cipher_gettable_ctx_params_fn des_gettable_ctx_params;

static void *des_newctx(void *provctx, size_t kbits, size_t blkbits,
                        size_t ivbits, unsigned int mode, uint64_t flags,
                        const PROV_CIPHER_HW *hw)
{
    PROV_DES_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        cipher_generic_initkey(ctx, kbits, blkbits, ivbits, mode, flags, hw,
                               provctx);
    return ctx;
}

static void des_freectx(void *vctx)
{
    PROV_DES_CTX *ctx = (PROV_DES_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static int des_init(void *vctx, const unsigned char *key, size_t keylen,
                    const unsigned char *iv, size_t ivlen, int enc)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;

    ctx->enc = enc;

    if (iv != NULL) {
        if (!cipher_generic_initiv(ctx, iv, ivlen))
            return 0;
    }

    if (key != NULL) {
        if (keylen != ctx->keylen) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEYLEN);
            return 0;
        }
        return ctx->hw->init(ctx, key, keylen);
    }
    return 1;
}

static int des_einit(void *vctx, const unsigned char *key, size_t keylen,
                     const unsigned char *iv, size_t ivlen)
{
    return des_init(vctx, key, keylen, iv, ivlen, 1);
}

static int des_dinit(void *vctx, const unsigned char *key, size_t keylen,
                     const unsigned char *iv, size_t ivlen)
{
    return des_init(vctx, key, keylen, iv, ivlen, 0);
}

static int des_generatekey(PROV_CIPHER_CTX *ctx, void *ptr)
{

    DES_cblock *deskey = ptr;
    size_t kl = ctx->keylen;

    if (kl == 0 || rand_priv_bytes_ex(ctx->libctx, ptr, kl) <= 0)
        return 0;
    DES_set_odd_parity(deskey);
    return 1;
}

CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START(des)
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_RANDOM_KEY, NULL, 0),
CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_END(des)

static int des_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_CIPHER_CTX  *ctx = (PROV_CIPHER_CTX *)vctx;
    OSSL_PARAM *p;

    if (!cipher_generic_get_ctx_params(vctx, params))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_RANDOM_KEY);
    if (p != NULL && !des_generatekey(ctx, p->data)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        return 0;
    }
    return 1;
}

#define IMPLEMENT_des_cipher(type, lcmode, UCMODE, flags,                      \
                             kbits, blkbits, ivbits, block)                    \
static OSSL_OP_cipher_newctx_fn type##_##lcmode##_newctx;                      \
static void *des_##lcmode##_newctx(void *provctx)                              \
{                                                                              \
    return des_newctx(provctx, kbits, blkbits, ivbits,                         \
                      EVP_CIPH_##UCMODE##_MODE, flags,                         \
                      PROV_CIPHER_HW_des_##lcmode());                          \
}                                                                              \
static OSSL_OP_cipher_get_params_fn des_##lcmode##_get_params;                 \
static int des_##lcmode##_get_params(OSSL_PARAM params[])                      \
{                                                                              \
    return cipher_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE, flags,  \
                                     kbits, blkbits, ivbits);                  \
}                                                                              \
const OSSL_DISPATCH des_##lcmode##_functions[] = {                             \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))des_einit },              \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))des_dinit },              \
    { OSSL_FUNC_CIPHER_UPDATE,                                                 \
      (void (*)(void))cipher_generic_##block##_update },                       \
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))cipher_generic_##block##_final },\
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))cipher_generic_cipher },        \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                 \
      (void (*)(void))des_##lcmode##_newctx },                                 \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))des_freectx },                 \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void))des_##lcmode##_get_params },                             \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))cipher_generic_gettable_params },                        \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))des_get_ctx_params },   \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))des_gettable_ctx_params },                               \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
     (void (*)(void))cipher_generic_set_ctx_params },                          \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
     (void (*)(void))cipher_generic_settable_ctx_params },                     \
    { 0, NULL }                                                                \
}

/* des_ecb_functions */
IMPLEMENT_des_cipher(des, ecb, ECB, DES_FLAGS, 64, 64, 0, block);
/* des_cbc_functions */
IMPLEMENT_des_cipher(des, cbc, CBC, DES_FLAGS, 64, 64, 64, block);
/* des_ofb64_functions */
IMPLEMENT_des_cipher(des, ofb64, OFB, DES_FLAGS, 64, 8, 64, stream);
/* des_cfb64_functions */
IMPLEMENT_des_cipher(des, cfb64, CFB, DES_FLAGS, 64, 8, 64, stream);
/* des_cfb1_functions */
IMPLEMENT_des_cipher(des, cfb1, CFB, DES_FLAGS, 64, 8, 64, stream);
/* des_cfb8_functions */
IMPLEMENT_des_cipher(des, cfb8, CFB, DES_FLAGS, 64, 8, 64, stream);
