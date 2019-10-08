/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for chacha20 cipher */

#include "cipher_chacha20.h"
#include "internal/provider_algs.h"
#include "internal/providercommonerr.h"

#define CHACHA20_KEYLEN (CHACHA_KEY_SIZE)
#define CHACHA20_BLKLEN (1)
#define CHACHA20_IVLEN (CHACHA_CTR_SIZE)
/* TODO(3.0) Figure out what flags are required */
#define CHACHA20_FLAGS (EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT)

#define chacha20_einit chacha20_init
#define chacha20_dinit chacha20_init
#define chacha20_gettable_params cipher_generic_gettable_params
#define chacha20_cipher chacha20_update

static OSSL_OP_cipher_newctx_fn chacha20_newctx;
static OSSL_OP_cipher_freectx_fn chacha20_freectx;
static OSSL_OP_cipher_encrypt_init_fn chacha20_init;
static OSSL_OP_cipher_update_fn chacha20_update;
static OSSL_OP_cipher_final_fn chacha20_final;
static OSSL_OP_cipher_get_params_fn chacha20_get_params;
static OSSL_OP_cipher_get_ctx_params_fn chacha20_get_ctx_params;
static OSSL_OP_cipher_set_ctx_params_fn chacha20_set_ctx_params;
static OSSL_OP_cipher_gettable_ctx_params_fn chacha20_gettable_ctx_params;
static OSSL_OP_cipher_settable_ctx_params_fn chacha20_settable_ctx_params;

int CHACHA20_init_key(void *vctx, const unsigned char user_key[CHACHA_KEY_SIZE],
                      const unsigned char iv[CHACHA_CTR_SIZE], int enc)
{
    PROV_CHACHA20_CTX *ctx = (PROV_CHACHA20_CTX *)vctx;
    unsigned int i;

    if (user_key != NULL)
        for (i = 0; i < CHACHA_KEY_SIZE; i += 4)
            ctx->key.d[i / 4] = CHACHA_U8TOU32(user_key + i);

    if (iv != NULL)
        for (i = 0; i < CHACHA_CTR_SIZE; i += 4)
            ctx->counter[i / 4] = CHACHA_U8TOU32(iv + i);

    ctx->partial_len = 0;
    return 1;
}

int CHACHA20_cipher(void *vctx, unsigned char *out, const unsigned char *inp,
                    size_t len)
{
    PROV_CHACHA20_CTX *ctx = (PROV_CHACHA20_CTX *)vctx;
    unsigned int n, rem, ctr32;

    n = ctx->partial_len;
    if (n > 0) {
        while (len > 0 && n < CHACHA_BLK_SIZE) {
            *out++ = *inp++ ^ ctx->buf[n++];
            len--;
        }
        ctx->partial_len = n;

        if (len == 0)
            return 1;

        if (n == CHACHA_BLK_SIZE) {
            ctx->partial_len = 0;
            ctx->counter[0]++;
            if (ctx->counter[0] == 0)
                ctx->counter[1]++;
        }
    }

    rem = (unsigned int)(len % CHACHA_BLK_SIZE);
    len -= rem;
    ctr32 = ctx->counter[0];
    while (len >= CHACHA_BLK_SIZE) {
        size_t blocks = len / CHACHA_BLK_SIZE;

        /*
         * 1<<28 is just a not-so-small yet not-so-large number...
         * Below condition is practically never met, but it has to
         * be checked for code correctness.
         */
        if (sizeof(size_t) > sizeof(unsigned int) && blocks > (1U << 28))
            blocks = (1U << 28);

        /*
         * As ChaCha20_ctr32 operates on 32-bit counter, caller
         * has to handle overflow. 'if' below detects the
         * overflow, which is then handled by limiting the
         * amount of blocks to the exact overflow point...
         */
        ctr32 += (unsigned int)blocks;
        if (ctr32 < blocks) {
            blocks -= ctr32;
            ctr32 = 0;
        }
        blocks *= CHACHA_BLK_SIZE;
        ChaCha20_ctr32(out, inp, blocks, ctx->key.d, ctx->counter);
        len -= blocks;
        inp += blocks;
        out += blocks;

        ctx->counter[0] = ctr32;
        if (ctr32 == 0) ctx->counter[1]++;
    }

    if (rem > 0) {
        memset(ctx->buf, 0, sizeof(ctx->buf));
        ChaCha20_ctr32(ctx->buf, ctx->buf, CHACHA_BLK_SIZE,
                       ctx->key.d, ctx->counter);
        for (n = 0; n < rem; n++)
            out[n] = inp[n] ^ ctx->buf[n];
        ctx->partial_len = rem;
    }

    return 1;
}

static void *chacha20_newctx(void *provctx)
{
     PROV_CHACHA20_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

     return ctx;
}

static void chacha20_freectx(void *vctx)
{
    PROV_CHACHA20_CTX *ctx = (PROV_CHACHA20_CTX *)vctx;

    if (ctx != NULL) {
        OPENSSL_clear_free(ctx, sizeof(ctx));
    }
}

static int chacha20_get_params(OSSL_PARAM params[])
{
    return cipher_generic_get_params(params, 0, CHACHA20_FLAGS,
                                     CHACHA20_KEYLEN * 8,
                                     CHACHA20_BLKLEN * 8,
                                     CHACHA20_IVLEN * 8);
}

static int chacha20_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CHACHA20_IVLEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CHACHA20_KEYLEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    return 1;
}

static const OSSL_PARAM chacha20_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_END
};
const OSSL_PARAM *chacha20_gettable_ctx_params(void)
{
    return chacha20_known_gettable_ctx_params;
}

static int chacha20_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    size_t len;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != CHACHA20_KEYLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != CHACHA20_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
    }
    return 1;
}

static const OSSL_PARAM chacha20_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_END
};
const OSSL_PARAM *chacha20_settable_ctx_params(void)
{
    return chacha20_known_settable_ctx_params;
}

static int chacha20_init(void *vctx, const unsigned char *key, size_t keylen,
                         const unsigned char *iv, size_t ivlen)
{
    if (key != NULL) {
        if (keylen != CHACHA20_KEYLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        CHACHA20_init_key(vctx, key, NULL, 1);
    }

    if (iv != NULL) {
        if (ivlen != CHACHA20_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        CHACHA20_init_key(vctx, NULL, iv, 0);
    }
    return 1;
}

static int chacha20_update(void *vctx,
                           unsigned char *out, size_t *outl, size_t outsize,
                           const unsigned char *in, size_t inl)
{
    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!CHACHA20_cipher(vctx, out, in, inl)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outl = inl;
    return 1;
}

static int chacha20_final(void *vctx, unsigned char *out, size_t *outl,
                          size_t outsize)
{
    *outl = 0;
    return 1;
}

/* chacha20_functions */
const OSSL_DISPATCH chacha20_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))chacha20_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))chacha20_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))chacha20_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))chacha20_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))chacha20_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))chacha20_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))chacha20_cipher},
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))chacha20_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,(void (*)(void))chacha20_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))chacha20_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        (void (*)(void))chacha20_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))chacha20_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        (void (*)(void))chacha20_settable_ctx_params },
    { 0, NULL }
};

