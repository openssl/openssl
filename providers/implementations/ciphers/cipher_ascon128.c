/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

# include "cipher_ascon128.h"
# include <stdlib.h>
# include <string.h>
# include <openssl/core_names.h>
# include <openssl/proverr.h>
# include "prov/implementations.h"
# include "prov/providercommon.h"
# include "prov/ciphercommon_aead.h"

/* Compatibility: OSSL_CIPHER_PARAM_AEAD_AAD may not be defined in all OpenSSL versions */
# ifndef OSSL_CIPHER_PARAM_AEAD_AAD
#  define OSSL_CIPHER_PARAM_AEAD_AAD "aad"
# endif

/*
 * Forward declarations to ensure we get signatures right.  All the
 * OSSL_FUNC_* types come from <openssl/core_dispatch.h>
 */
OSSL_FUNC_cipher_newctx_fn ossl_cipher_ascon128_newctx;
OSSL_FUNC_cipher_encrypt_init_fn ossl_cipher_ascon128_encrypt_init;
OSSL_FUNC_cipher_decrypt_init_fn ossl_cipher_ascon128_decrypt_init;
OSSL_FUNC_cipher_update_fn ossl_cipher_ascon128_update;
OSSL_FUNC_cipher_final_fn ossl_cipher_ascon128_final;
OSSL_FUNC_cipher_dupctx_fn ossl_cipher_ascon128_dupctx;
OSSL_FUNC_cipher_freectx_fn ossl_cipher_ascon128_freectx;
OSSL_FUNC_cipher_get_params_fn ossl_cipher_ascon128_get_params;
OSSL_FUNC_cipher_gettable_params_fn ossl_cipher_ascon128_gettable_params;
OSSL_FUNC_cipher_set_ctx_params_fn ossl_cipher_ascon128_set_ctx_params;
OSSL_FUNC_cipher_get_ctx_params_fn ossl_cipher_ascon128_get_ctx_params;
OSSL_FUNC_cipher_settable_ctx_params_fn ossl_cipher_ascon128_settable_ctx_params;
OSSL_FUNC_cipher_gettable_ctx_params_fn ossl_cipher_ascon128_gettable_ctx_params;

/* Note: get_iv_length and get_tag_length are not standard OpenSSL dispatch functions.
 * IV and tag lengths are retrieved via get_ctx_params instead.
 * These functions are kept for internal use only.
 */

/* ASCON-128 uses a fixed key length of 16 bytes (128 bits) */

static void ossl_cipher_ascon128_cleanctx(void *vctx)
{
    struct ascon_ctx_st *ctx = vctx;

    ctx->is_tag_set = false;
    ctx->is_ongoing = false;
    ctx->assoc_data_processed = false;
    ctx->tag_len = FIXED_TAG_LENGTH;
    memset(ctx->internal_ctx, 0, sizeof(*(ctx->internal_ctx)));
    memset(ctx->tag, 0, sizeof(ctx->tag));
}

void *ossl_cipher_ascon128_newctx(void *vprovctx)
{
    struct ascon_ctx_st *ctx;
    intctx_t *intctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->provctx = vprovctx;
    ctx->is_tag_set = false;
    ctx->is_ongoing = false;
    ctx->assoc_data_processed = false;
    ctx->tag_len = FIXED_TAG_LENGTH;  /* default tag length */

    intctx = OPENSSL_zalloc(sizeof(*intctx));
    if (intctx == NULL)
    {
        OPENSSL_clear_free(ctx, sizeof(*ctx));
        return NULL;
    }
    ctx->internal_ctx = intctx;

    return ctx;
}

void *ossl_cipher_ascon128_dupctx(void *vctx)
{
    struct ascon_ctx_st *src = vctx;
    struct ascon_ctx_st *dst = NULL;

    if (src == NULL || !ossl_prov_is_running())
        return NULL;

    /* Create new context using the same provider context */
    if ((dst = ossl_cipher_ascon128_newctx(src->provctx)) == NULL)
        return NULL;

    /* Copy all context fields */
    dst->direction = src->direction;
    dst->is_ongoing = src->is_ongoing;
    dst->is_tag_set = src->is_tag_set;
    dst->assoc_data_processed = src->assoc_data_processed;
    dst->tag_len = src->tag_len;

    /* Copy tag if it's set */
    if (src->is_tag_set) {
        memcpy(dst->tag, src->tag, FIXED_TAG_LENGTH);
    }

    /* Deep copy the internal LibAscon context */
    if (src->internal_ctx != NULL && dst->internal_ctx != NULL) {
        memcpy(dst->internal_ctx, src->internal_ctx, sizeof(*dst->internal_ctx));
    }

    return dst;
}

void ossl_cipher_ascon128_freectx(void *vctx)
{
    struct ascon_ctx_st *ctx = vctx;

    if (ctx == NULL)
        return;

    ctx->provctx = NULL;
    ossl_cipher_ascon128_cleanctx(ctx);
    OPENSSL_clear_free(ctx->internal_ctx, sizeof(*ctx->internal_ctx));
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/* Internal initialization function (shared by encrypt and decrypt init) */

static int ossl_cipher_ascon128_internal_init(void *vctx, direction_t direction,
                                      const unsigned char *key, size_t keylen,
                                      const unsigned char *nonce, size_t noncelen,
                                      const OSSL_PARAM params[])
{
    struct ascon_ctx_st *ctx = vctx;

    if (ctx == NULL)
    {
        return OSSL_RV_ERROR;
    }

    ossl_cipher_ascon128_cleanctx(ctx);

    if (nonce != NULL)
    {
        if (noncelen != ASCON_AEAD_NONCE_LEN)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return OSSL_RV_ERROR;
        }
    }

    ctx->direction = direction;

    if (key != NULL && nonce != NULL)
    {
        ascon_aead128_init(ctx->internal_ctx, key, nonce);
        ctx->is_ongoing = true;
        return OSSL_RV_SUCCESS;
    }
    return OSSL_RV_SUCCESS;
}

int ossl_cipher_ascon128_encrypt_init(void *vctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *nonce, size_t noncelen,
                              const OSSL_PARAM params[])
{
    return ossl_cipher_ascon128_internal_init(vctx, ENCRYPTION, key, keylen, nonce, noncelen, params);
}

int ossl_cipher_ascon128_decrypt_init(void *vctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *nonce, size_t noncelen,
                              const OSSL_PARAM params[])
{
    return ossl_cipher_ascon128_internal_init(vctx, DECRYPTION, key, keylen, nonce, noncelen, params);
}

int ossl_cipher_ascon128_update(void *vctx, unsigned char *out, size_t *outl,
                        size_t outsize, const unsigned char *in, size_t inl)
{
    struct ascon_ctx_st *ctx = vctx;

    if (ctx == NULL)
    {
        /* Context must be set before update */
        return OSSL_RV_ERROR;
    }

    if (ctx->is_ongoing == false)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return OSSL_RV_ERROR;
    }

    if (ctx->direction == ENCRYPTION)
    {
        /* Mark that we've started encryption - AAD cannot be added after this */
        if (!ctx->assoc_data_processed)
        {
            /* Finalize AAD processing if any was provided (LibAscon handles this internally) */
            /* The LibAscon encrypt_update will finalize AAD automatically if needed */
            ctx->assoc_data_processed = true;
        }

        const uint8_t *plaintext = in;
        size_t plaintext_len = inl;
        uint8_t *ciphertext = out;
        size_t ciphertext_len;

        ciphertext_len = ascon_aead128_encrypt_update(ctx->internal_ctx, ciphertext, plaintext, plaintext_len);
        *outl = ciphertext_len;
        return OSSL_RV_SUCCESS;
    }
    else if (ctx->direction == DECRYPTION)
    {
        /* Mark that we've started decryption - AAD cannot be added after this */
        if (!ctx->assoc_data_processed)
        {
            /* Finalize AAD processing if any was provided (LibAscon handles this internally) */
            /* The LibAscon decrypt_update will finalize AAD automatically if needed */
            ctx->assoc_data_processed = true;
        }

        uint8_t *plaintext = out;
        size_t plaintext_len;
        const uint8_t *ciphertext = in;
        size_t ciphertext_len = inl;

        plaintext_len = ascon_aead128_decrypt_update(ctx->internal_ctx, plaintext, ciphertext, ciphertext_len);
        *outl = plaintext_len;
        return OSSL_RV_SUCCESS;
    }
    return OSSL_RV_ERROR;
}

/* PROVIDER'S FINAL FUNCTION*/

int ossl_cipher_ascon128_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    struct ascon_ctx_st *ctx = vctx;

    if (ctx == NULL)
    {
        /* Context must be set before final */
        return OSSL_RV_ERROR;
    }

    if (ctx->is_ongoing == false)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return OSSL_RV_ERROR;
    }

    if (ctx->direction == ENCRYPTION)
    {
        uint8_t *ciphertext = out;
        uint8_t *tag = ctx->tag;
        size_t tag_len = FIXED_TAG_LENGTH;
        size_t ret;

        ret = ascon_aead128_encrypt_final((ascon_aead_ctx_t *)ctx->internal_ctx, ciphertext, tag, tag_len);
        *outl = ret;
        ctx->is_tag_set = true;

        return OSSL_RV_SUCCESS;
    }
    else if (ctx->direction == DECRYPTION)
    {

        uint8_t *plaintext = out;
        bool is_tag_valid = false;
        size_t ret;

        if (ctx->is_tag_set)
        {
            const uint8_t *expected_tag = ctx->tag;
            size_t expected_tag_len = FIXED_TAG_LENGTH;

            ret = ascon_aead128_decrypt_final((ascon_aead_ctx_t *)ctx->internal_ctx, plaintext, &is_tag_valid, expected_tag, expected_tag_len);

            if (is_tag_valid)
            {
                *outl = ret;
                return OSSL_RV_SUCCESS;
            }
            else
            {
                return OSSL_RV_ERROR;
            }
        }
        else
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
            return OSSL_RV_ERROR;
        }
    }

    *outl = 0;
    return OSSL_RV_SUCCESS;
}

/* Parameters that libcrypto can get from this implementation */
const OSSL_PARAM *ossl_cipher_ascon128_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        {"blocksize", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {"keylen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {"ivlen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {"aead", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {NULL, 0, NULL, 0, 0},
    };

    return table;
}

int ossl_cipher_ascon128_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++) {
        if (strcmp(p->key, "blocksize") == 0) {
            ok &= OSSL_PARAM_set_size_t(p, 1);
        } else if (strcmp(p->key, "keylen") == 0) {
            ok &= OSSL_PARAM_set_size_t(p, ASCON_AEAD128_KEY_LEN);
        } else if (strcmp(p->key, "ivlen") == 0) {
            ok &= OSSL_PARAM_set_size_t(p, ASCON_AEAD_NONCE_LEN);
        } else if (strcmp(p->key, "aead") == 0) {
            ok &= OSSL_PARAM_set_size_t(p, 1);  /* AEAD is supported */
        }
    }
    return ok;
}

const OSSL_PARAM *ossl_cipher_ascon128_gettable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        {OSSL_CIPHER_PARAM_KEYLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {OSSL_CIPHER_PARAM_AEAD_TAGLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
        {NULL, 0, NULL, 0, 0},
    };

    return table;
}

int ossl_cipher_ascon128_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct ascon_ctx_st *ctx = vctx;
    OSSL_PARAM *p;
    int ok = 1;

    if (ctx == NULL)
    {
        return 0;
    }

    for (p = params; p->key != NULL; p++) {
        if (strcmp(p->key, OSSL_CIPHER_PARAM_KEYLEN) == 0) {
            ok &= OSSL_PARAM_set_size_t(p, ASCON_AEAD128_KEY_LEN);
        } else if (strcmp(p->key, OSSL_CIPHER_PARAM_IVLEN) == 0) {
            ok &= OSSL_PARAM_set_size_t(p, ASCON_AEAD_NONCE_LEN);
        } else if (strcmp(p->key, OSSL_CIPHER_PARAM_AEAD_TAGLEN) == 0) {
            ok &= OSSL_PARAM_set_size_t(p, ctx->tag_len);
        } else if (strcmp(p->key, OSSL_CIPHER_PARAM_AEAD_TAG) == 0) {
            /* Check that p->data_type matches "octet string" */
            /* Check that p->data (the given buffer) is not NULL */
            if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
            {
                ok = 0;
                break;
            }

            /* Check if the given buffer is big enough */
            if (p->data_size < FIXED_TAG_LENGTH)
            {
                ok = 0;
                break;
            }

            /* Check if ctx->is_tag_set is true */
            if (!ctx->is_tag_set)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
                ok = 0;
                break;
            }
            /* Copy tag to destination */
            memcpy(p->data, ctx->tag, FIXED_TAG_LENGTH);
            p->return_size = FIXED_TAG_LENGTH;
            ok &= 1;
        }
    }

    return ok;
}

/* Parameters that libcrypto can send to this implementation */
const OSSL_PARAM *ossl_cipher_ascon128_settable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        {OSSL_CIPHER_PARAM_AEAD_AAD, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
        {OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
        {OSSL_CIPHER_PARAM_AEAD_TAGLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {NULL, 0, NULL, 0, 0},
    };

    return table;
}

int ossl_cipher_ascon128_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct ascon_ctx_st *ctx = vctx;
    const OSSL_PARAM *p;
    int ok = 1;

    if (ctx == NULL)
    {
        return 0;
    }

    for (p = params; p->key != NULL; p++) {
        if (strcmp(p->key, OSSL_CIPHER_PARAM_AEAD_AAD) == 0) {
            /* Process associated data (AAD) before encryption/decryption */
            if (!ctx->is_ongoing)
            {
                /* Must have initialized with key and nonce first */
                ok = 0;
                break;
            }

            /* Can only add AAD before encryption/decryption updates start */
            if (ctx->assoc_data_processed)
            {
                /* AAD already processed or encryption started - cannot add more */
                ERR_raise(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER);
                ok = 0;
                break;
            }

            /* Process AAD if provided */
            if (p->data != NULL && p->data_type == OSSL_PARAM_OCTET_STRING && p->data_size > 0)
            {
                ascon_aead128_assoc_data_update(ctx->internal_ctx, p->data, p->data_size);
            }
            else if (p->data_size == 0)
            {
                /* Empty AAD is allowed */
                /* LibAscon allows calling with NULL data and 0 length */
                if (p->data == NULL || p->data_type == OSSL_PARAM_OCTET_STRING)
                {
                    /* Empty AAD - still valid, no-op */
                    ok = 1;
                }
                else
                {
                    ok = 0;
                }
            }
            else
            {
                ok = 0;
            }
        } else if (strcmp(p->key, OSSL_CIPHER_PARAM_AEAD_TAGLEN) == 0) {
            size_t tag_len = 0;
            if (!OSSL_PARAM_get_size_t(p, &tag_len))
            {
                ok = 0;
                break;
            }
            if (tag_len != FIXED_TAG_LENGTH)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
                ok = 0;
                break;
            }
            ctx->tag_len = tag_len;
            ok = 1;
        } else if (strcmp(p->key, OSSL_CIPHER_PARAM_AEAD_TAG) == 0) {
            if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
            {
                ok = 0;
                break;
            }

            /* We only accept strictly 16-byte tags here */
            if (p->data_size != FIXED_TAG_LENGTH)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
                ok = 0;
                break;
            }
            memcpy(ctx->tag, p->data, FIXED_TAG_LENGTH);
            ctx->is_tag_set = 1;
        }
    }
    return ok;
}

/* One-shot cipher function for OSSL_FUNC_CIPHER_CIPHER
 * This function handles one-shot encryption/decryption operations.
 * Based on AES-SIV pattern: handles final (in == NULL), AAD (out == NULL), 
 * and regular encryption/decryption operations.
 */
static int ascon128_cipher(void *vctx, unsigned char *out, size_t *outl,
                           size_t outsize, const unsigned char *in, size_t inl)
{
    struct ascon_ctx_st *ctx = vctx;

    if (!ossl_prov_is_running())
        return 0;

    if (ctx == NULL)
        return 0;

    /* Handle final operation (in == NULL) */
    if (in == NULL)
    {
        size_t final_outl = 0;
        if (ossl_cipher_ascon128_final(ctx, out, &final_outl, outsize) == OSSL_RV_SUCCESS)
        {
            if (outl != NULL)
                *outl = final_outl;
            return 1;
        }
        return 0;
    }

    /* Handle AAD operation (out == NULL) - process associated data */
    if (out == NULL)
    {
        /* For ASCON, AAD is typically set via set_ctx_params, but we support
         * this pattern for compatibility with one-shot operations */
        if (!ctx->is_ongoing)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
            return 0;
        }
        if (ctx->assoc_data_processed)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER);
            return 0;
        }
        if (inl > 0)
        {
            ascon_aead128_assoc_data_update(ctx->internal_ctx, in, inl);
        }
        return 1;
    }

    /* Check output buffer size */
    if (outsize < inl)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    /* Handle regular encryption/decryption (streaming update) */
    if (!ctx->is_ongoing)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    size_t update_outl = 0;
    if (ossl_cipher_ascon128_update(ctx, out, &update_outl, outsize, in, inl) == OSSL_RV_SUCCESS)
    {
        if (outl != NULL)
            *outl = update_outl;
        return 1;
    }

    return 0;
}

/* These helper functions tell OpenSSL the IV and tag sizes for Ascon AEAD */

size_t ossl_cipher_ascon128_get_iv_length(void *vctx)
{
    /* Ascon uses a 128-bit (16-byte) IV */
    return ASCON_AEAD_NONCE_LEN;
}

size_t ossl_cipher_ascon128_get_tag_length(void *vctx)
{
    /* Ascon authentication tag is also 16 bytes (128 bits) */
    return FIXED_TAG_LENGTH;
}

/*********************************************************************
 *
 *  Setup
 *
 *****/

typedef void (*funcptr_t)(void);

/* The dispatch table for ASCON-128 */
const OSSL_DISPATCH ossl_ascon128_functions[] = {
    {OSSL_FUNC_CIPHER_NEWCTX, (funcptr_t)ossl_cipher_ascon128_newctx},
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (funcptr_t)ossl_cipher_ascon128_encrypt_init},
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (funcptr_t)ossl_cipher_ascon128_decrypt_init},
    {OSSL_FUNC_CIPHER_UPDATE, (funcptr_t)ossl_cipher_ascon128_update},
    {OSSL_FUNC_CIPHER_FINAL, (funcptr_t)ossl_cipher_ascon128_final},
    {OSSL_FUNC_CIPHER_CIPHER, (funcptr_t)ascon128_cipher},
    {OSSL_FUNC_CIPHER_DUPCTX, (funcptr_t)ossl_cipher_ascon128_dupctx},
    {OSSL_FUNC_CIPHER_FREECTX, (funcptr_t)ossl_cipher_ascon128_freectx},
    {OSSL_FUNC_CIPHER_GET_PARAMS, (funcptr_t)ossl_cipher_ascon128_get_params},
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (funcptr_t)ossl_cipher_ascon128_gettable_params},
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (funcptr_t)ossl_cipher_ascon128_get_ctx_params},
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (funcptr_t)ossl_cipher_ascon128_gettable_ctx_params},
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (funcptr_t)ossl_cipher_ascon128_set_ctx_params},
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (funcptr_t)ossl_cipher_ascon128_settable_ctx_params},
    {0, NULL}};

