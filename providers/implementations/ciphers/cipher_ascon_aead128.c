/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "cipher_ascon_aead128.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/ciphercommon_aead.h"

/* Return value constants */
#define OSSL_RV_SUCCESS 1
#define OSSL_RV_ERROR 0

/*
 * Note: get_iv_length and get_tag_length are not standard OpenSSL dispatch functions.
 * IV and tag lengths are retrieved via get_ctx_params instead.
 * These functions are kept for internal use only.
 */

/* ASCON-AEAD128 uses a fixed key length of 16 bytes (128 bits) */

static void ascon_aead128_cleanctx(void *vctx)
{
    struct ascon_aead128_ctx_st *ctx = vctx;

    ctx->is_tag_set = false;
    ctx->is_ongoing = false;
    ctx->assoc_data_processed = false;
    ctx->tag_len = FIXED_TAG_LENGTH;
    ctx->iv_set = false;
    if (ctx->internal_ctx != NULL)
        OPENSSL_cleanse(ctx->internal_ctx, sizeof(*(ctx->internal_ctx)));
    OPENSSL_cleanse(ctx->tag, sizeof(ctx->tag));
    OPENSSL_cleanse(ctx->iv, sizeof(ctx->iv));
}

static void *ascon_aead128_newctx(void *provctx)
{
    struct ascon_aead128_ctx_st *ctx;
    ascon_aead_ctx_t *intctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->provctx = provctx;
    ctx->is_tag_set = false;
    ctx->is_ongoing = false;
    ctx->assoc_data_processed = false;
    ctx->tag_len = FIXED_TAG_LENGTH;  /* default tag length */
    ctx->iv_set = false;

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

    if (src == NULL || !ossl_prov_is_running())
        return NULL;

    /* Create new context using the same provider context */
    if ((dst = ascon_aead128_newctx(src->provctx)) == NULL)
        return NULL;

    /* Copy all context fields */
    *dst = *src;

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

    if (ctx == NULL) {
        return OSSL_RV_ERROR;
    }

    /* Validate key length if key is provided */
    if (key != NULL) {
        if (keylen != ASCON_AEAD128_KEY_LEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return OSSL_RV_ERROR;
        }
    }

    /* Validate IV length if IV is provided */
    if (iv != NULL) {
        if (ivlen != ASCON_AEAD_NONCE_LEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return OSSL_RV_ERROR;
        }
    }

    /* Only clean and initialize if both key and IV are provided */
    if (key != NULL && iv != NULL) {
        /* Preserve tag for decryption - it may have been set before reinitialization */
        uint8_t saved_tag[FIXED_TAG_LENGTH];
        int tag_was_set = ctx->is_tag_set;

        if (tag_was_set && direction == DECRYPTION) {
            memcpy(saved_tag, ctx->tag, FIXED_TAG_LENGTH);
        }

        ascon_aead128_cleanctx(ctx);
        ctx->direction = direction;
        ascon_aead128_init(ctx->internal_ctx, key, iv);
        /* Store the IV for get_updated_iv */
        memcpy(ctx->iv, iv, ASCON_AEAD_NONCE_LEN);
        ctx->iv_set = true;
        ctx->is_ongoing = true;

        /* Restore tag for decryption if it was set before reinitialization */
        if (tag_was_set && direction == DECRYPTION) {
            memcpy(ctx->tag, saved_tag, FIXED_TAG_LENGTH);
            ctx->is_tag_set = true;
        }

        return OSSL_RV_SUCCESS;
    }

    /* If only direction is being set (key/IV not provided yet), just set direction */
    ctx->direction = direction;
    return OSSL_RV_SUCCESS;
}

static int ascon_aead128_einit(void *vctx, const unsigned char *key, size_t keylen,
                                const unsigned char *iv, size_t ivlen,
                                const OSSL_PARAM params[])
{
    return ascon_aead128_internal_init(vctx, ENCRYPTION, key, keylen, iv, ivlen, params);
}

static int ascon_aead128_dinit(void *vctx, const unsigned char *key, size_t keylen,
                                const unsigned char *iv, size_t ivlen,
                                const OSSL_PARAM params[])
{
    return ascon_aead128_internal_init(vctx, DECRYPTION, key, keylen, iv, ivlen, params);
}

static int ascon_aead128_update(void *vctx, unsigned char *out, size_t *outl,
                                 size_t outsize, const unsigned char *in, size_t inl)
{
    struct ascon_aead128_ctx_st *ctx = vctx;

    if (ctx == NULL) {
        /* Context must be set before update */
        return OSSL_RV_ERROR;
    }

    if (ctx->is_ongoing == false) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return OSSL_RV_ERROR;
    }

    /* Handle AAD operation (out == NULL) - process associated data */
    if (out == NULL) {
        /* Can only add AAD before encryption/decryption updates start */
        if (ctx->assoc_data_processed) {
            /* AAD already processed or encryption started - cannot add more */
            ERR_raise(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER);
            return OSSL_RV_ERROR;
        }

        /* Process AAD if provided */
        if (inl > 0 && in != NULL) {
            ascon_aead128_assoc_data_update(ctx->internal_ctx, in, inl);
        }
        if (outl != NULL)
            *outl = 0;
        return OSSL_RV_SUCCESS;
    }

    if (ctx->direction == ENCRYPTION) {
        /* Mark that we've started encryption - AAD cannot be added after this */
        /* LibAscon encrypt_update will finalize AAD automatically if needed */
        ctx->assoc_data_processed = true;

        const uint8_t *plaintext = in;
        size_t plaintext_len = inl;
        uint8_t *ciphertext = out;
        size_t ciphertext_len;

        ciphertext_len = ascon_aead128_encrypt_update(ctx->internal_ctx, ciphertext,
                                                        plaintext, plaintext_len);
        if (outl != NULL)
            *outl = ciphertext_len;
        return OSSL_RV_SUCCESS;
    } else if (ctx->direction == DECRYPTION) {
        /* Mark that we've started decryption - AAD cannot be added after this */
        /* LibAscon decrypt_update will finalize AAD automatically if needed */
        ctx->assoc_data_processed = true;

        uint8_t *plaintext = out;
        size_t plaintext_len;
        const uint8_t *ciphertext = in;
        size_t ciphertext_len = inl;

        plaintext_len = ascon_aead128_decrypt_update(ctx->internal_ctx, plaintext,
                                                        ciphertext, ciphertext_len);
        if (outl != NULL)
            *outl = plaintext_len;
        return OSSL_RV_SUCCESS;
    }
    return OSSL_RV_ERROR;
}

/* PROVIDER'S FINAL FUNCTION */

static int ascon_aead128_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    struct ascon_aead128_ctx_st *ctx = vctx;

    if (ctx == NULL) {
        /* Context must be set before final */
        return OSSL_RV_ERROR;
    }

    if (ctx->is_ongoing == false) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return OSSL_RV_ERROR;
    }

    if (ctx->direction == ENCRYPTION) {
        uint8_t *ciphertext = out;
        uint8_t *tag = ctx->tag;
        size_t tag_len = FIXED_TAG_LENGTH;
        size_t ret;

        ret = ascon_aead128_encrypt_final((ascon_aead_ctx_t *)ctx->internal_ctx,
                                            ciphertext, tag, tag_len);
        *outl = ret;
        ctx->is_tag_set = true;

        return OSSL_RV_SUCCESS;
    } else if (ctx->direction == DECRYPTION) {
        uint8_t *plaintext = out;
        bool is_tag_valid = false;
        size_t ret;

        if (ctx->is_tag_set) {
            const uint8_t *expected_tag = ctx->tag;
            size_t expected_tag_len = FIXED_TAG_LENGTH;

            ret = ascon_aead128_decrypt_final((ascon_aead_ctx_t *)ctx->internal_ctx,
                                                plaintext, &is_tag_valid, expected_tag,
                                                expected_tag_len);

            if (is_tag_valid) {
                *outl = ret;
                return OSSL_RV_SUCCESS;
            } else {
                return OSSL_RV_ERROR;
            }
        } else {
            ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
            return OSSL_RV_ERROR;
        }
    }

    *outl = 0;
    return OSSL_RV_SUCCESS;
}

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *ascon_aead128_gettable_params(ossl_unused void *cctx,
                                                        ossl_unused void *provctx)
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

static int ascon_aead128_get_params(OSSL_PARAM params[])
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

static const OSSL_PARAM *ascon_aead128_gettable_ctx_params(ossl_unused void *cctx,
                                                             ossl_unused void *provctx)
{
    static const OSSL_PARAM table[] = {
        {OSSL_CIPHER_PARAM_KEYLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {OSSL_CIPHER_PARAM_AEAD_TAGLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
        {OSSL_CIPHER_PARAM_UPDATED_IV, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
        {NULL, 0, NULL, 0, 0},
    };

    return table;
}

static int ascon_aead128_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct ascon_aead128_ctx_st *ctx = vctx;
    OSSL_PARAM *p;
    int ok = 1;

    if (ctx == NULL) {
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
            if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING) {
                ok = 0;
                break;
            }

            /* Check if the given buffer is big enough */
            if (p->data_size < FIXED_TAG_LENGTH) {
                ok = 0;
                break;
            }

            /* Check if ctx->is_tag_set is true */
            if (!ctx->is_tag_set) {
                ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
                ok = 0;
                break;
            }
            /* Copy tag to destination */
            memcpy(p->data, ctx->tag, FIXED_TAG_LENGTH);
            p->return_size = FIXED_TAG_LENGTH;
            ok &= 1;
        } else if (strcmp(p->key, OSSL_CIPHER_PARAM_UPDATED_IV) == 0) {
            /* Check that p->data_type matches "octet string" */
            /* Check that p->data (the given buffer) is not NULL */
            if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING) {
                ok = 0;
                break;
            }

            /* Check if the given buffer is big enough */
            if (p->data_size < ASCON_AEAD_NONCE_LEN) {
                ok = 0;
                break;
            }

            /* Check if ctx->iv_set is true */
            if (!ctx->iv_set) {
                ok = 0;
                break;
            }
            /* Copy IV to destination */
            memcpy(p->data, ctx->iv, ASCON_AEAD_NONCE_LEN);
            p->return_size = ASCON_AEAD_NONCE_LEN;
            ok &= 1;
        }
    }

    return ok;
}

/* Parameters that libcrypto can send to this implementation */
static const OSSL_PARAM *ascon_aead128_settable_ctx_params(ossl_unused void *cctx,
                                                             ossl_unused void *provctx)
{
    static const OSSL_PARAM table[] = {
        {OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
        {OSSL_CIPHER_PARAM_AEAD_TAGLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {NULL, 0, NULL, 0, 0},
    };

    return table;
}

static int ascon_aead128_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct ascon_aead128_ctx_st *ctx = vctx;
    const OSSL_PARAM *p;
    int ok = 1;

    if (ctx == NULL) {
        return 0;
    }

    for (p = params; p->key != NULL; p++) {
        if (strcmp(p->key, OSSL_CIPHER_PARAM_AEAD_TAGLEN) == 0) {
            size_t tag_len = 0;

            if (!OSSL_PARAM_get_size_t(p, &tag_len)) {
                ok = 0;
                break;
            }
            if (tag_len != FIXED_TAG_LENGTH) {
                ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
                ok = 0;
                break;
            }
            ctx->tag_len = tag_len;
            ok = 1;
        } else if (strcmp(p->key, OSSL_CIPHER_PARAM_AEAD_TAG) == 0) {
            /* When data is NULL, this is a request to set tag length (for encryption) */
            if (p->data == NULL) {
                /* For encryption, we accept setting tag length via NULL data */
                /* The tag length is passed in data_size */
                if (p->data_size != FIXED_TAG_LENGTH) {
                    ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
                    ok = 0;
                    break;
                }
                ctx->tag_len = p->data_size;
                ok = 1;
                break;
            }

            if (p->data_type != OSSL_PARAM_OCTET_STRING) {
                ok = 0;
                break;
            }

            /* We only accept strictly 16-byte tags here */
            if (p->data_size != FIXED_TAG_LENGTH) {
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

/*
 * One-shot cipher function for OSSL_FUNC_CIPHER_CIPHER
 * This function handles one-shot encryption/decryption operations.
 * Based on AES-SIV pattern: handles final (in == NULL), AAD (out == NULL),
 * and regular encryption/decryption operations.
 * For AEAD ciphers, CIPHER and UPDATE should behave the same way.
 */
static int ascon_aead128_cipher(void *vctx, unsigned char *out, size_t *outl,
                                 size_t outsize, const unsigned char *in, size_t inl)
{
    struct ascon_aead128_ctx_st *ctx = vctx;

    if (!ossl_prov_is_running())
        return 0;

    if (ctx == NULL)
        return 0;

    /* Handle final operation (in == NULL) */
    if (in == NULL) {
        size_t final_outl = 0;

        if (ascon_aead128_final(ctx, out, &final_outl, outsize) == OSSL_RV_SUCCESS) {
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
        if (ctx->assoc_data_processed) {
            ERR_raise(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER);
            return 0;
        }
        if (inl > 0) {
            ascon_aead128_assoc_data_update(ctx->internal_ctx, in, inl);
        }
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
    size_t update_outl = 0;

    if (ascon_aead128_update(ctx, out, &update_outl, outsize, in, inl)
        == OSSL_RV_SUCCESS) {
        if (outl != NULL)
            *outl = update_outl;
        return 1;
    }

    return 0;
}

/* These helper functions tell OpenSSL the IV and tag sizes for Ascon AEAD */

static size_t ascon_aead128_get_iv_length(ossl_unused void *vctx)
{
    /* Ascon-AEAD128 uses a 128-bit (16-byte) IV */
    return ASCON_AEAD_NONCE_LEN;
}

static size_t ascon_aead128_get_tag_length(ossl_unused void *vctx)
{
    /* Ascon-AEAD128 authentication tag is also 16 bytes (128 bits) */
    return FIXED_TAG_LENGTH;
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
