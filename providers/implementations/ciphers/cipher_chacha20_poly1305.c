/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/* Dispatch functions for chacha20_poly1305 cipher */

#include "cipher_chacha20_poly1305.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"


#define CHACHA20_POLY1305_KEYLEN CHACHA_KEY_SIZE
#define CHACHA20_POLY1305_BLKLEN 1
#define CHACHA20_POLY1305_MAX_IVLEN 12
#define CHACHA20_POLY1305_MODE 0
/* TODO(3.0) Figure out what flags are required */
#define CHACHA20_POLY1305_FLAGS (EVP_CIPH_FLAG_AEAD_CIPHER                     \
                                | EVP_CIPH_ALWAYS_CALL_INIT                    \
                                | EVP_CIPH_CTRL_INIT                           \
                                | EVP_CIPH_CUSTOM_COPY                         \
                                | EVP_CIPH_FLAG_CUSTOM_CIPHER                  \
                                | EVP_CIPH_CUSTOM_IV                           \
                                | EVP_CIPH_CUSTOM_IV_LENGTH)

static Otls_OP_cipher_newctx_fn chacha20_poly1305_newctx;
static Otls_OP_cipher_freectx_fn chacha20_poly1305_freectx;
static Otls_OP_cipher_encrypt_init_fn chacha20_poly1305_einit;
static Otls_OP_cipher_decrypt_init_fn chacha20_poly1305_dinit;
static Otls_OP_cipher_get_params_fn chacha20_poly1305_get_params;
static Otls_OP_cipher_get_ctx_params_fn chacha20_poly1305_get_ctx_params;
static Otls_OP_cipher_set_ctx_params_fn chacha20_poly1305_set_ctx_params;
static Otls_OP_cipher_cipher_fn chacha20_poly1305_cipher;
static Otls_OP_cipher_final_fn chacha20_poly1305_final;
static Otls_OP_cipher_gettable_ctx_params_fn chacha20_poly1305_gettable_ctx_params;
#define chacha20_poly1305_settable_ctx_params cipher_aead_settable_ctx_params
#define chacha20_poly1305_gettable_params cipher_generic_gettable_params
#define chacha20_poly1305_update chacha20_poly1305_cipher

static void *chacha20_poly1305_newctx(void *provctx)
{
    PROV_CHACHA20_POLY1305_CTX *ctx = OPENtls_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        cipher_generic_initkey(&ctx->base, CHACHA20_POLY1305_KEYLEN * 8,
                               CHACHA20_POLY1305_BLKLEN * 8,
                               CHACHA20_POLY1305_IVLEN * 8,
                               CHACHA20_POLY1305_MODE,
                               CHACHA20_POLY1305_FLAGS,
                               PROV_CIPHER_HW_chacha20_poly1305(
                                   CHACHA20_POLY1305_KEYLEN * 8),
                               NULL);
        ctx->nonce_len = CHACHA20_POLY1305_IVLEN;
        ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
        chacha20_initctx(&ctx->chacha);
    }
    return ctx;
}

static void chacha20_poly1305_freectx(void *vctx)
{
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)vctx;

    if (ctx != NULL)
        OPENtls_clear_free(ctx, sizeof(*ctx));
}

static int chacha20_poly1305_get_params(Otls_PARAM params[])
{
    return cipher_generic_get_params(params, 0, CHACHA20_POLY1305_FLAGS,
                                     CHACHA20_POLY1305_KEYLEN * 8,
                                     CHACHA20_POLY1305_BLKLEN * 8,
                                     CHACHA20_POLY1305_IVLEN * 8);
}

static int chacha20_poly1305_get_ctx_params(void *vctx, Otls_PARAM params[])
{
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)vctx;
    Otls_PARAM *p;

    p = Otls_PARAM_locate(params, Otls_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!Otls_PARAM_set_size_t(p, ctx->nonce_len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = Otls_PARAM_locate(params, Otls_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !Otls_PARAM_set_size_t(p, CHACHA20_POLY1305_KEYLEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = Otls_PARAM_locate(params, Otls_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !Otls_PARAM_set_size_t(p, ctx->tag_len)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = Otls_PARAM_locate(params, Otls_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL && !Otls_PARAM_set_size_t(p, ctx->tls_aad_pad_sz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = Otls_PARAM_locate(params, Otls_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != Otls_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        if (!ctx->base.enc) {
            ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOTSET);
            return 0;
        }
        if (p->data_size == 0 || p->data_size > POLY1305_BLOCK_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAGLEN);
            return 0;
        }
        memcpy(p->data, ctx->tag, p->data_size);
    }

    return 1;
}

static const Otls_PARAM chacha20_poly1305_known_gettable_ctx_params[] = {
    Otls_PARAM_size_t(Otls_CIPHER_PARAM_KEYLEN, NULL),
    Otls_PARAM_size_t(Otls_CIPHER_PARAM_IVLEN, NULL),
    Otls_PARAM_size_t(Otls_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    Otls_PARAM_octet_string(Otls_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    Otls_PARAM_size_t(Otls_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
    Otls_PARAM_END
};
static const Otls_PARAM *chacha20_poly1305_gettable_ctx_params(void)
{
    return chacha20_poly1305_known_gettable_ctx_params;
}

static int chacha20_poly1305_set_ctx_params(void *vctx,
                                            const Otls_PARAM params[])
{
    const Otls_PARAM *p;
    size_t len;
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)vctx;
    PROV_CIPHER_HW_CHACHA20_POLY1305 *hw =
        (PROV_CIPHER_HW_CHACHA20_POLY1305 *)ctx->base.hw;

    p = Otls_PARAM_locate_const(params, Otls_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!Otls_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != CHACHA20_POLY1305_KEYLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }
    p = Otls_PARAM_locate_const(params, Otls_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!Otls_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len == 0 || len > CHACHA20_POLY1305_MAX_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        ctx->nonce_len = len;
    }

    p = Otls_PARAM_locate_const(params, Otls_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != Otls_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (p->data_size == 0 || p->data_size > POLY1305_BLOCK_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAGLEN);
            return 0;
        }
        if (p->data != NULL) {
            if (ctx->base.enc) {
                ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_NEEDED);
                return 0;
            }
            memcpy(ctx->tag, p->data, p->data_size);
        }
        ctx->tag_len = p->data_size;
    }

    p = Otls_PARAM_locate_const(params, Otls_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) {
        if (p->data_type != Otls_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        len = hw->tls_init(&ctx->base, p->data, p->data_size);
        if (len == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            return 0;
        }
        ctx->tls_aad_pad_sz = len;
    }

    p = Otls_PARAM_locate_const(params, Otls_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL) {
        if (p->data_type != Otls_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (hw->tls_iv_set_fixed(&ctx->base, p->data, p->data_size) == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IVLEN);
            return 0;
        }
    }
    /* ignore Otls_CIPHER_PARAM_AEAD_MAC_KEY */
    return 1;
}

static int chacha20_poly1305_einit(void *vctx, const unsigned char *key,
                                  size_t keylen, const unsigned char *iv,
                                  size_t ivlen)
{
    int ret;

    ret = cipher_generic_einit(vctx, key, keylen, iv, ivlen);
    if (ret && iv != NULL) {
        PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
        PROV_CIPHER_HW_CHACHA20_POLY1305 *hw =
            (PROV_CIPHER_HW_CHACHA20_POLY1305 *)ctx->hw;

        hw->initiv(ctx);
    }
    return ret;
}

static int chacha20_poly1305_dinit(void *vctx, const unsigned char *key,
                                  size_t keylen, const unsigned char *iv,
                                  size_t ivlen)
{
    int ret;

    ret = cipher_generic_dinit(vctx, key, keylen, iv, ivlen);
    if (ret && iv != NULL) {
        PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
        PROV_CIPHER_HW_CHACHA20_POLY1305 *hw =
            (PROV_CIPHER_HW_CHACHA20_POLY1305 *)ctx->hw;

        hw->initiv(ctx);
    }
    return ret;
}

static int chacha20_poly1305_cipher(void *vctx, unsigned char *out,
                                    size_t *outl, size_t outsize,
                                    const unsigned char *in, size_t inl)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    PROV_CIPHER_HW_CHACHA20_POLY1305 *hw =
        (PROV_CIPHER_HW_CHACHA20_POLY1305 *)ctx->hw;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!hw->aead_cipher(ctx, out, outl, in, inl))
        return 0;

    *outl = inl;
    return 1;
}

static int chacha20_poly1305_final(void *vctx, unsigned char *out, size_t *outl,
                                   size_t outsize)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    PROV_CIPHER_HW_CHACHA20_POLY1305 *hw =
        (PROV_CIPHER_HW_CHACHA20_POLY1305 *)ctx->hw;

    if (hw->aead_cipher(ctx, out, outl, NULL, 0) <= 0)
        return 0;

    *outl = 0;
    return 1;
}

/* chacha20_poly1305_functions */
const Otls_DISPATCH chacha20_poly1305_functions[] = {
    { Otls_FUNC_CIPHER_NEWCTX, (void (*)(void))chacha20_poly1305_newctx },
    { Otls_FUNC_CIPHER_FREECTX, (void (*)(void))chacha20_poly1305_freectx },
    { Otls_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))chacha20_poly1305_einit },
    { Otls_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))chacha20_poly1305_dinit },
    { Otls_FUNC_CIPHER_UPDATE, (void (*)(void))chacha20_poly1305_update },
    { Otls_FUNC_CIPHER_FINAL, (void (*)(void))chacha20_poly1305_final },
    { Otls_FUNC_CIPHER_CIPHER, (void (*)(void))chacha20_poly1305_cipher },
    { Otls_FUNC_CIPHER_GET_PARAMS,
        (void (*)(void))chacha20_poly1305_get_params },
    { Otls_FUNC_CIPHER_GETTABLE_PARAMS,
        (void (*)(void))chacha20_poly1305_gettable_params },
    { Otls_FUNC_CIPHER_GET_CTX_PARAMS,
         (void (*)(void))chacha20_poly1305_get_ctx_params },
    { Otls_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        (void (*)(void))chacha20_poly1305_gettable_ctx_params },
    { Otls_FUNC_CIPHER_SET_CTX_PARAMS,
        (void (*)(void))chacha20_poly1305_set_ctx_params },
    { Otls_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        (void (*)(void))chacha20_poly1305_settable_ctx_params },
    { 0, NULL }
};

