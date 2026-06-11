/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "cipher_ascon_aead128.h"
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/ciphercommon.h"
#include "prov/ciphercommon_aead.h"
#include "internal/common.h"
#include "providers/implementations/ciphers/cipher_ascon_aead128.inc"

static OSSL_FUNC_cipher_newctx_fn ascon_aead128_newctx;
static OSSL_FUNC_cipher_freectx_fn ascon_aead128_freectx;
static OSSL_FUNC_cipher_dupctx_fn ascon_aead128_dupctx;
static OSSL_FUNC_cipher_encrypt_init_fn ascon_aead128_einit;
static OSSL_FUNC_cipher_decrypt_init_fn ascon_aead128_dinit;
static OSSL_FUNC_cipher_update_fn ascon_aead128_update;
static OSSL_FUNC_cipher_final_fn ascon_aead128_final;
static OSSL_FUNC_cipher_cipher_fn ascon_aead128_cipher;
static OSSL_FUNC_cipher_get_params_fn ascon_aead128_get_params;
static OSSL_FUNC_cipher_get_ctx_params_fn ascon_aead128_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn ascon_aead128_set_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn ascon_aead128_gettable_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn ascon_aead128_settable_ctx_params;
#define ascon_aead128_gettable_params ossl_cipher_generic_gettable_params

#define ASCON_AEAD128_FLAGS (PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV)

/*
 * Note: get_iv_length and get_tag_length are not standard OpenSSL dispatch functions.
 * IV and tag lengths are retrieved via get_ctx_params instead.
 * These functions are kept for internal use only.
 */

/* ASCON-AEAD128 uses a fixed key length of 16 bytes (128 bits) */

static void ascon_aead128_cleanctx(void *vctx)
{
    struct ascon_aead128_ctx_st *ctx = vctx;

    ctx->is_tag_set = 0;
    ctx->is_ongoing = 0;
    ctx->assoc_data_not_allowed = 0;
    ctx->tag_len = FIXED_TAG_LENGTH;
    ctx->iv_set = 0;
    if (ctx->internal_ctx != NULL)
        ossl_ascon_aead_cleanup(ctx->internal_ctx);
    OPENSSL_cleanse(ctx->tag, sizeof(ctx->tag));
    OPENSSL_cleanse(ctx->iv, sizeof(ctx->iv));
    /* Note: key is not cleared here to allow reinitialization with NULL key */
}

static void *ascon_aead128_newctx(void *provctx)
{
    struct ascon_aead128_ctx_st *ctx;
    ASCON_AEAD_CTX *intctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->provctx = provctx;
    ctx->is_tag_set = 0;
    ctx->is_ongoing = 0;
    ctx->assoc_data_not_allowed = 0;
    ctx->tag_len = FIXED_TAG_LENGTH; /* default tag length */
    ctx->iv_set = 0;
    ctx->key_set = 0;

    intctx = OPENSSL_zalloc(sizeof(*intctx));
    if (intctx == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }
    ctx->internal_ctx = intctx;

    return ctx;
}

static void *ascon_aead128_dupctx(void *vctx)
{
    struct ascon_aead128_ctx_st *src = vctx;
    struct ascon_aead128_ctx_st *dst = NULL;
    ASCON_AEAD_CTX *saved_internal_ctx;

    if (src == NULL || !ossl_prov_is_running())
        return NULL;

    /* Create new context using the same provider context */
    if ((dst = ascon_aead128_newctx(src->provctx)) == NULL)
        return NULL;

    /* Save the newly allocated internal_ctx pointer before overwriting */
    saved_internal_ctx = dst->internal_ctx;

    /* Copy all context fields */
    *dst = *src;

    /* Restore the newly allocated internal_ctx pointer */
    dst->internal_ctx = saved_internal_ctx;

    /* Deep copy the internal LibAscon context */
    if (src->internal_ctx != NULL && dst->internal_ctx != NULL)
        memcpy(dst->internal_ctx, src->internal_ctx, sizeof(*dst->internal_ctx));

    return dst;
}

static void ascon_aead128_freectx(void *vctx)
{
    struct ascon_aead128_ctx_st *ctx = vctx;

    if (ctx == NULL)
        return;

    ctx->provctx = NULL;
    ascon_aead128_cleanctx(ctx);
    OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
    OPENSSL_free(ctx->internal_ctx);
    OPENSSL_free(ctx);
}

/* Internal initialization function (shared by encrypt and decrypt init) */

static int ascon_aead128_internal_init(void *vctx, direction_t direction,
    const unsigned char *key, size_t keylen,
    const unsigned char *iv, size_t ivlen,
    const OSSL_PARAM params[])
{
    struct ascon_aead128_ctx_st *ctx = vctx;
    uint8_t saved_tag[FIXED_TAG_LENGTH];
    int tag_was_set;
    unsigned char ivcopy[ASCON_AEAD_NONCE_LEN];

    if (ctx == NULL)
        return 0;

    if (key == NULL && iv == NULL) {
        ctx->direction = direction;
        if (params != NULL && !ascon_aead128_set_ctx_params(ctx, params))
            return 0;
        return 1;
    }

    if (key != NULL) {
        if (keylen != ASCON_AEAD128_KEY_LEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        memcpy(ctx->key, key, ASCON_AEAD128_KEY_LEN);
        ctx->key_set = 1;
    }

    if (iv != NULL) {
        if (ivlen != ASCON_AEAD_NONCE_LEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        memcpy(ctx->iv, iv, ASCON_AEAD_NONCE_LEN);
        ctx->iv_set = 1;
    }

    ctx->direction = direction;

    tag_was_set = ctx->is_tag_set;
    if (tag_was_set && direction == DECRYPTION)
        memcpy(saved_tag, ctx->tag, FIXED_TAG_LENGTH);

    if (ctx->key_set && ctx->iv_set) {
        memcpy(ivcopy, ctx->iv, sizeof(ivcopy));
        ascon_aead128_cleanctx(ctx);
        ctx->key_set = 1;
        memcpy(ctx->iv, ivcopy, sizeof(ivcopy));
        ctx->iv_set = 1;
        if (tag_was_set && direction == DECRYPTION) {
            memcpy(ctx->tag, saved_tag, FIXED_TAG_LENGTH);
            ctx->is_tag_set = 1;
        }
        ossl_ascon_aead128_init(ctx->internal_ctx, ctx->key, ctx->iv);
        ctx->is_ongoing = 1;
    } else {
        ctx->is_ongoing = 0;
        ctx->assoc_data_not_allowed = 0;
        ctx->is_tag_set = 0;
        ctx->tag_len = FIXED_TAG_LENGTH;
        if (ctx->internal_ctx != NULL)
            ossl_ascon_aead_cleanup(ctx->internal_ctx);
        OPENSSL_cleanse(ctx->tag, sizeof(ctx->tag));
        if (!ctx->key_set)
            OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
        if (!ctx->iv_set)
            OPENSSL_cleanse(ctx->iv, sizeof(ctx->iv));
    }

    if (params != NULL && !ascon_aead128_set_ctx_params(ctx, params))
        return 0;

    return 1;
}

static int ascon_aead128_einit(void *vctx, const unsigned char *key,
    size_t keylen, const unsigned char *iv,
    size_t ivlen, const OSSL_PARAM params[])
{
    return ascon_aead128_internal_init(vctx, ENCRYPTION, key, keylen, iv, ivlen, params);
}

static int ascon_aead128_dinit(void *vctx, const unsigned char *key,
    size_t keylen, const unsigned char *iv,
    size_t ivlen, const OSSL_PARAM params[])
{
    return ascon_aead128_internal_init(vctx, DECRYPTION, key, keylen, iv, ivlen, params);
}

static int ascon_aead128_update(void *vctx, unsigned char *out, size_t *outl,
    size_t outsize, const unsigned char *in, size_t inl)
{
    struct ascon_aead128_ctx_st *ctx = vctx;

    if (ctx == NULL) {
        /* Context must be set before update */
        return 0;
    }

    if (!ctx->is_ongoing) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    /* Handle AAD operation (out == NULL) - process associated data */
    if (out == NULL) {
        /* Can only add AAD before encryption/decryption updates start */
        if (ctx->assoc_data_not_allowed) {
            /* AAD already processed or encryption started - cannot add more */
            ERR_raise(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER);
            return 0;
        }

        /* Process AAD if provided */
        if (inl > 0 && in != NULL) {
            if (ctx->internal_ctx == NULL) {
                ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
                return 0;
            }
            ossl_ascon_aead128_assoc_data_update(ctx->internal_ctx, in, inl);
        }
        if (outl != NULL)
            *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    if (inl > 0 && in == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
        return 0;
    }

    if (ctx->direction == ENCRYPTION) {
        const uint8_t *plaintext = in;
        size_t plaintext_len = inl;
        uint8_t *ciphertext = out;
        size_t ciphertext_len;

        /* Mark that we've started encryption - AAD cannot be added after this */
        /* LibAscon encrypt_update will finalize AAD automatically if needed */
        ctx->assoc_data_not_allowed = 1;

        if (ctx->internal_ctx == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
            return 0;
        }

        ciphertext_len = ossl_ascon_aead128_encrypt_update(ctx->internal_ctx,
            ciphertext,
            plaintext,
            plaintext_len);
        if (outl != NULL)
            *outl = ciphertext_len;
        return 1;
    } else if (ctx->direction == DECRYPTION) {
        uint8_t *plaintext = out;
        size_t plaintext_len;
        const uint8_t *ciphertext = in;
        size_t ciphertext_len = inl;

        /* Mark that we've started decryption - AAD cannot be added after this */
        /* LibAscon decrypt_update will finalize AAD automatically if needed */
        ctx->assoc_data_not_allowed = 1;

        if (ctx->internal_ctx == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
            return 0;
        }

        plaintext_len = ossl_ascon_aead128_decrypt_update(ctx->internal_ctx,
            plaintext,
            ciphertext,
            ciphertext_len);
        if (outl != NULL)
            *outl = plaintext_len;
        return 1;
    }
    return 0;
}

/* PROVIDER'S FINAL FUNCTION */

static int ascon_aead128_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    struct ascon_aead128_ctx_st *ctx = vctx;

    if (ctx == NULL) {
        /* Context must be set before final */
        return 0;
    }

    if (!ctx->is_ongoing) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (ctx->direction == ENCRYPTION) {
        uint8_t *ciphertext = out;
        uint8_t *tag = ctx->tag;
        size_t tag_len = FIXED_TAG_LENGTH;
        size_t ret;

        ret = ossl_ascon_aead128_encrypt_final((ASCON_AEAD_CTX *)ctx->internal_ctx,
            ciphertext, tag, tag_len);
        *outl = ret;
        ctx->is_tag_set = 1;

        return 1;
    } else if (ctx->direction == DECRYPTION) {
        uint8_t *plaintext = out;
        int is_tag_valid = 0;
        size_t ret;

        if (ctx->is_tag_set) {
            const uint8_t *expected_tag = ctx->tag;
            size_t expected_tag_len = FIXED_TAG_LENGTH;

            ret = ossl_ascon_aead128_decrypt_final((ASCON_AEAD_CTX *)ctx->internal_ctx,
                plaintext, &is_tag_valid,
                expected_tag,
                expected_tag_len);

            if (is_tag_valid) {
                *outl = ret;
                return 1;
            }
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
            return 0;
        } else {
            ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
            return 0;
        }
    }

    *outl = 0;
    return 1;
}

static int ascon_aead128_get_params(OSSL_PARAM params[])
{
    return ossl_cipher_generic_get_params(params, 0, ASCON_AEAD128_FLAGS,
        ASCON_AEAD128_KEY_LEN * 8,
        1 * 8,
        ASCON_AEAD_NONCE_LEN * 8);
}

static const OSSL_PARAM *ascon_aead128_gettable_ctx_params(ossl_unused void *cctx,
    ossl_unused void *provctx)
{
    return ascon_aead128_get_ctx_params_list;
}

static int ascon_aead128_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct ascon_aead128_ctx_st *ctx = vctx;
    struct ascon_aead128_get_ctx_params_st p;

    if (ctx == NULL || !ascon_aead128_get_ctx_params_decoder(params, &p))
        return 0;

    if (p.keylen != NULL
        && !OSSL_PARAM_set_size_t(p.keylen, ASCON_AEAD128_KEY_LEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    if (p.ivlen != NULL
        && !OSSL_PARAM_set_size_t(p.ivlen, ASCON_AEAD_NONCE_LEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    if (p.taglen != NULL
        && !OSSL_PARAM_set_size_t(p.taglen, ctx->tag_len)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    if (p.tag != NULL) {
        if (!ctx->is_tag_set) {
            ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p.tag, ctx->tag, FIXED_TAG_LENGTH)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    if (p.upd_iv != NULL) {
        if (!ctx->iv_set) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p.upd_iv, ctx->iv, ASCON_AEAD_NONCE_LEN)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM *ascon_aead128_settable_ctx_params(ossl_unused void *cctx,
    ossl_unused void *provctx)
{
    return ascon_aead128_set_ctx_params_list;
}

static int ascon_aead128_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct ascon_aead128_ctx_st *ctx = vctx;
    struct ascon_aead128_set_ctx_params_st p;

    if (ctx == NULL || !ascon_aead128_set_ctx_params_decoder(params, &p))
        return 0;

    if (p.taglen != NULL) {
        size_t tag_len = 0;

        if (!OSSL_PARAM_get_size_t(p.taglen, &tag_len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (tag_len != FIXED_TAG_LENGTH) {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return 0;
        }
        ctx->tag_len = tag_len;
    }

    if (p.tag != NULL) {
        /* When data is NULL, this is a request to set tag length (for encryption) */
        if (p.tag->data == NULL) {
            /* For encryption, we accept setting tag length via NULL data */
            /* The tag length may be passed in data_size, but we always use FIXED_TAG_LENGTH */
            /* Accept any tag length request during encryption and use our fixed length */
            ctx->tag_len = FIXED_TAG_LENGTH;
            return 1;
        }

        if (p.tag->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }

        /* We only accept strictly 16-byte tags here */
        if (p.tag->data_size != FIXED_TAG_LENGTH) {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return 0;
        }
        memcpy(ctx->tag, p.tag->data, FIXED_TAG_LENGTH);
        ctx->is_tag_set = 1;
    }

    return 1;
}

/*
 * One-shot cipher function for OSSL_FUNC_CIPHER_CIPHER
 * This function handles one-shot encryption/decryption operations.
 * Based on AES-SIV pattern: handles final (in == NULL), AAD (out == NULL),
 * and regular encryption/decryption operations.
 * For AEAD ciphers, CIPHER and UPDATE should behave the same way.
 */
static int ascon_aead128_cipher(void *vctx, unsigned char *out, size_t *outl,
    size_t outsize, const unsigned char *in,
    size_t inl)
{
    struct ascon_aead128_ctx_st *ctx = vctx;
    size_t update_outl = 0;

    if (!ossl_prov_is_running())
        return 0;

    if (ctx == NULL)
        return 0;

    /* Handle final operation (in == NULL) */
    if (in == NULL) {
        size_t final_outl = 0;

        if (ascon_aead128_final(ctx, out, &final_outl, outsize) == 1) {
            if (outl != NULL)
                *outl = final_outl;
            return 1;
        }
        return 0;
    }

    /* Handle AAD operation (out == NULL) - process associated data */
    if (out == NULL) {
        if (!ctx->is_ongoing) {
            ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
            return 0;
        }
        if (ctx->assoc_data_not_allowed) {
            ERR_raise(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER);
            return 0;
        }
        if (inl > 0)
            ossl_ascon_aead128_assoc_data_update(ctx->internal_ctx, in, inl);
        if (outl != NULL)
            *outl = 0;
        return 1;
    }

    /* Check output buffer size */
    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    /* Handle regular encryption/decryption (streaming update) */
    if (!ctx->is_ongoing) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    /* Use the same logic as update */
    if (ascon_aead128_update(ctx, out, &update_outl, outsize, in, inl)
        == 1) {
        if (outl != NULL)
            *outl = update_outl;
        return 1;
    }

    return 0;
}

/*********************************************************************
 *
 *  Setup
 *
 *****/

typedef void (*funcptr_t)(void);

/* The dispatch table for ASCON-AEAD128 */
const OSSL_DISPATCH ossl_ascon_aead128_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))ascon_aead128_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))ascon_aead128_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))ascon_aead128_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))ascon_aead128_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))ascon_aead128_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))ascon_aead128_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))ascon_aead128_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))ascon_aead128_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))ascon_aead128_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))ascon_aead128_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))ascon_aead128_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))ascon_aead128_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))ascon_aead128_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))ascon_aead128_settable_ctx_params },
    OSSL_DISPATCH_END
};
