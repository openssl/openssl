/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * AES low level APIs are deprecated for public use, but still ok for internal
 * use where we're using them to implement the higher level EVP interface, as is
 * the case here.
 */
#include "internal/deprecated.h"

/* Dispatch functions for AES cipher modes cbc, cts, ofb, cfb, ctr */

#include <openssl/proverr.h>
#include "cipher_aes.h"
#include "prov/ciphercommon.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/securitycheck.h"
#include "internal/skey.h"

#define AES_CBC_BLK_BITS 128

typedef struct prov_aes_ecb_ctx_st {
    PROV_AES_CTX aesbase;
    int internal;
    OSSL_FIPS_IND_DECLARE
} PROV_AES_ECB_CTX;

struct aes_ecb_get_param_list_st {
    struct ossl_cipher_get_param_list_st common;
    OSSL_PARAM *decrypt;
};

struct aes_ecb_get_ctx_param_list_st {
    struct ossl_cipher_get_ctx_param_list_st common;
#ifdef FIPS_MODULE
    OSSL_PARAM *ind;
#endif
};

struct aes_ecb_set_ctx_param_list_st {
    struct ossl_cipher_set_ctx_param_list_st common;
#ifdef FIPS_MODULE
    OSSL_PARAM *ind;
#endif
};

#define aes_ecb_get_params_st aes_ecb_get_param_list_st
#define aes_ecb_get_ctx_params_st aes_ecb_get_ctx_param_list_st
#define aes_ecb_set_ctx_params_st aes_ecb_set_ctx_param_list_st

#include "providers/implementations/ciphers/cipher_aes_ecb.inc"

static OSSL_FUNC_cipher_freectx_fn aes_ecb_freectx;
static OSSL_FUNC_cipher_dupctx_fn aes_ecb_dupctx;
static OSSL_FUNC_cipher_encrypt_init_fn aes_ecb_einit;
static OSSL_FUNC_cipher_decrypt_init_fn aes_ecb_dinit;
static OSSL_FUNC_cipher_encrypt_skey_init_fn aes_ecb_skey_einit;
static OSSL_FUNC_cipher_decrypt_skey_init_fn aes_ecb_skey_dinit;
static OSSL_FUNC_cipher_gettable_params_fn aes_ecb_gettable_params;
static OSSL_FUNC_cipher_get_ctx_params_fn aes_ecb_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn aes_ecb_set_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn aes_ecb_gettable_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn aes_ecb_settable_ctx_params;

/* AES-ECB encryption is no longer approved in SP800-131A r3 */
#ifdef FIPS_MODULE
static int aes_ecb_encrypt_check_approved(PROV_AES_ECB_CTX *ctx, int enc)
{
    if (enc && !ctx->internal
        && !OSSL_FIPS_IND_ON_UNAPPROVED(ctx, OSSL_FIPS_IND_SETTABLE0,
            ctx->aesbase.base.libctx, "AES-ECB", "Encryption",
            FIPS_CONFIG_AES_ECB_ENCRYPT_DISABLED))
        return 0;
    return 1;
}
#endif

static void *aes_ecb_newctx(void *provctx, size_t kbits, int internal)
{
    PROV_AES_ECB_CTX *ctx;

    CIPHER_PROV_CHECK(provctx, aes);

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        OSSL_FIPS_IND_INIT(ctx)
        ossl_cipher_generic_initkey(&ctx->aesbase, kbits, AES_CBC_BLK_BITS,
            0, EVP_CIPH_ECB_MODE, 0, ossl_prov_cipher_hw_aes_ecb(kbits), provctx);
        ctx->internal = internal;
    }
    return ctx;
}

static void aes_ecb_freectx(void *vctx)
{
    PROV_AES_ECB_CTX *ctx = (PROV_AES_ECB_CTX *)vctx;

    ossl_cipher_generic_reset_ctx(&ctx->aesbase.base);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *aes_ecb_dupctx(void *ctx)
{
    PROV_AES_ECB_CTX *in = (PROV_AES_ECB_CTX *)ctx;
    PROV_AES_ECB_CTX *ret;

    if (!ossl_prov_is_running())
        return NULL;

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL)
        return NULL;
    ret->internal = in->internal;
    in->aesbase.base.hw->copyctx(&ret->aesbase.base, &in->aesbase.base);
    OSSL_FIPS_IND_COPY(ret, in)
    return ret;
}

static int aes_ecb_init(void *vctx, const uint8_t *key, size_t keylen,
    const uint8_t *iv, size_t ivlen, const OSSL_PARAM params[], int enc)
{
    if (!ossl_cipher_generic_init(vctx, key, keylen, iv, ivlen, NULL, enc))
        return 0;
    if (!aes_ecb_set_ctx_params(vctx, params))
        return 0;
#ifdef FIPS_MODULE
    if (!aes_ecb_encrypt_check_approved((PROV_AES_ECB_CTX *)vctx, enc))
        return 0;
#endif
    return 1;
}

static int aes_ecb_skey_init(void *vctx, void *skeydata,
    const uint8_t *iv, size_t ivlen, const OSSL_PARAM params[], int enc)
{
    PROV_SKEY *key = skeydata;

    if (!ossl_cipher_generic_init(vctx, key->data, key->length, iv, ivlen, NULL, enc))
        return 0;
    if (!aes_ecb_set_ctx_params(vctx, params))
        return 0;
#ifdef FIPS_MODULE
    if (!aes_ecb_encrypt_check_approved((PROV_AES_ECB_CTX *)vctx, enc))
        return 0;
#endif
    return 1;
}

static int aes_ecb_einit(void *vctx, const uint8_t *key, size_t keylen,
    const uint8_t *iv, size_t ivlen, const OSSL_PARAM params[])
{
    return aes_ecb_init(vctx, key, keylen, iv, ivlen, params, 1);
}

static int aes_ecb_dinit(void *vctx, const uint8_t *key, size_t keylen,
    const uint8_t *iv, size_t ivlen, const OSSL_PARAM params[])
{
    return aes_ecb_init(vctx, key, keylen, iv, ivlen, params, 0);
}

static int aes_ecb_skey_einit(void *vctx, void *skeydata,
    const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
    return aes_ecb_skey_init(vctx, skeydata, iv, ivlen, params, 1);
}

static int aes_ecb_skey_dinit(void *vctx, void *skeydata,
    const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
    return aes_ecb_skey_init(vctx, skeydata, iv, ivlen, params, 0);
}

static const OSSL_PARAM *aes_ecb_gettable_ctx_params(ossl_unused void *cctx,
    ossl_unused void *provctx)
{
    return aes_ecb_get_ctx_params_list;
}

static int aes_ecb_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    struct aes_ecb_get_ctx_param_list_st p;

    if (ctx == NULL || !aes_ecb_get_ctx_params_decoder(params, &p))
        return 0;

    if (!ossl_cipher_common_get_ctx_params(ctx, &p.common))
        return 0;

    if (!OSSL_FIPS_IND_GET_CTX_FROM_PARAM((PROV_AES_ECB_CTX *)vctx, p.ind))
        return 0;
    return 1;
}

static const OSSL_PARAM *aes_ecb_settable_ctx_params(ossl_unused void *cctx,
    ossl_unused void *provctx)
{
    return aes_ecb_set_ctx_params_list;
}

static int aes_ecb_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_AES_ECB_CTX *ctx = (PROV_AES_ECB_CTX *)vctx;
    struct aes_ecb_set_ctx_param_list_st p;

    if (ctx == NULL || !aes_ecb_set_ctx_params_decoder(params, &p))
        return 0;
    if (!OSSL_FIPS_IND_SET_CTX_FROM_PARAM(ctx, OSSL_FIPS_IND_SETTABLE0, p.ind))
        return 0;

    return ossl_cipher_common_set_ctx_params(&ctx->aesbase.base, &p.common);
}

static const OSSL_PARAM *aes_ecb_gettable_params(ossl_unused void *provctx)
{
    return aes_ecb_get_params_list;
}

static int aes_ecb_get_params(OSSL_PARAM params[], size_t kbits)
{
#ifdef FIPS_MODULE
    const int decrypt_only = 1;
#else
    const int decrypt_only = 0;
#endif
    struct aes_ecb_get_param_list_st p;

    if (!aes_ecb_get_params_decoder(params, &p))
        return 0;

    if (p.decrypt != NULL && !OSSL_PARAM_set_int(p.decrypt, decrypt_only)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return ossl_cipher_common_get_params(&p.common, EVP_CIPH_ECB_MODE,
        0, kbits, AES_CBC_BLK_BITS, 0);
}

#define IMPLEMENT_AES_ECB(name, bits, internal)                                        \
    static OSSL_FUNC_cipher_newctx_fn aes_##bits##_##name##_newctx;                    \
    static OSSL_FUNC_cipher_get_params_fn aes_##bits##_##name##_get_params;            \
    static void *aes_##bits##_##name##_newctx(void *provctx)                           \
    {                                                                                  \
        return aes_ecb_newctx(provctx, bits, internal);                                \
    }                                                                                  \
    static int aes_##bits##_##name##_get_params(OSSL_PARAM params[])                   \
    {                                                                                  \
        return aes_ecb_get_params(params, bits);                                       \
    }                                                                                  \
    const OSSL_DISPATCH ossl_aes##bits##name##_functions[] = {                         \
        { OSSL_FUNC_CIPHER_NEWCTX,                                                     \
            (void (*)(void))aes_##bits##_##name##_newctx },                            \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))aes_ecb_freectx },                 \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))aes_ecb_dupctx },                   \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))aes_ecb_einit },              \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))aes_ecb_dinit },              \
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))ossl_cipher_generic_block_update }, \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))ossl_cipher_generic_block_final },   \
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))ossl_cipher_generic_cipher },       \
        { OSSL_FUNC_CIPHER_GET_PARAMS,                                                 \
            (void (*)(void))aes_##bits##_##name##_get_params },                        \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                             \
            (void (*)(void))aes_ecb_get_ctx_params },                                  \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                             \
            (void (*)(void))aes_ecb_set_ctx_params },                                  \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                            \
            (void (*)(void))aes_ecb_gettable_params },                                 \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                        \
            (void (*)(void))aes_ecb_gettable_ctx_params },                             \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                        \
            (void (*)(void))aes_ecb_settable_ctx_params },                             \
        { OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT, (void (*)(void))aes_ecb_skey_einit },    \
        { OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT, (void (*)(void))aes_ecb_skey_dinit },    \
        OSSL_DISPATCH_END                                                              \
    }

/* ossl_aes256ecb_functions */
IMPLEMENT_AES_ECB(ecb, 256, 0);
/* ossl_aes192ecb_functions */
IMPLEMENT_AES_ECB(ecb, 192, 0);
/* ossl_aes128ecb_functions */
IMPLEMENT_AES_ECB(ecb, 128, 0);

/* ossl_aes256ecb_internal_functions */
IMPLEMENT_AES_ECB(ecb_internal, 256, 1);
IMPLEMENT_AES_ECB(ecb_internal, 192, 1);
IMPLEMENT_AES_ECB(ecb_internal, 128, 1);
