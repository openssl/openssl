/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for chacha20_poly1305 cipher */

#include "include/crypto/poly1305.h"
#include "cipher_chacha20.h"
#include "internal/provider_algs.h"
#include "internal/providercommonerr.h"

typedef struct {
    POLY1305 poly1305;
    PROV_CHACHA20_CTX chacha;
    unsigned int nonce[12 / 4];
    unsigned char tag[POLY1305_BLOCK_SIZE];
    unsigned char tls_aad[POLY1305_BLOCK_SIZE];
    struct { uint64_t aad, text; } len;
    unsigned int enc : 1;
    unsigned int aad : 1;
    unsigned int iv_set : 1;
    unsigned int mac_inited : 1;
    size_t tag_len, nonce_len;
    size_t tls_payload_length;
    size_t tls_aad_pad_sz;
} PROV_CHACHA_AEAD_CTX;

#define NO_TLS_PAYLOAD_LENGTH ((size_t)-1)
#define CHACHA20_POLY1305_KEYLEN CHACHA_KEY_SIZE
#define CHACHA20_POLY1305_BLKLEN 1
#define CHACHA20_POLY1305_IVLEN 12
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


static OSSL_OP_cipher_newctx_fn chacha20_poly1305_newctx;
static OSSL_OP_cipher_freectx_fn chacha20_poly1305_freectx;
static OSSL_OP_cipher_encrypt_init_fn chacha20_poly1305_einit;
static OSSL_OP_cipher_decrypt_init_fn chacha20_poly1305_dinit;
static OSSL_OP_cipher_update_fn chacha20_poly1305_update;
static OSSL_OP_cipher_final_fn chacha20_poly1305_final;
static OSSL_OP_cipher_cipher_fn chacha20_poly1305_cipher;
static OSSL_OP_cipher_get_params_fn chacha20_poly1305_get_params;
static OSSL_OP_cipher_get_ctx_params_fn chacha20_poly1305_get_ctx_params;
static OSSL_OP_cipher_set_ctx_params_fn chacha20_poly1305_set_ctx_params;
static OSSL_OP_cipher_gettable_ctx_params_fn chacha20_poly1305_gettable_ctx_params;
#define chacha20_poly1305_settable_ctx_params cipher_aead_settable_ctx_params
#define chacha20_poly1305_gettable_params cipher_generic_gettable_params

static void *chacha20_poly1305_newctx(void *provctx)
{
    PROV_CHACHA_AEAD_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->nonce_len = CHACHA20_POLY1305_IVLEN;
        ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
    }
    return ctx;
}

static void chacha20_poly1305_freectx(void *vctx)
{
    PROV_CHACHA_AEAD_CTX *ctx = (PROV_CHACHA_AEAD_CTX *)vctx;

    if (ctx != NULL)
        OPENSSL_clear_free(ctx, sizeof(ctx));
}

static int chacha20_poly1305_get_params(OSSL_PARAM params[])
{
    return cipher_generic_get_params(params, 0, CHACHA20_POLY1305_FLAGS,
                                     CHACHA20_POLY1305_KEYLEN * 8,
                                     CHACHA20_POLY1305_BLKLEN * 8,
                                     CHACHA20_POLY1305_IVLEN * 8);
}

static int chacha20_poly1305_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_CHACHA_AEAD_CTX *ctx = (PROV_CHACHA_AEAD_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_set_size_t(p, ctx->nonce_len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CHACHA20_POLY1305_KEYLEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tag_len)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tls_aad_pad_sz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        if (!ctx->enc) {
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

static const OSSL_PARAM chacha20_poly1305_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *chacha20_poly1305_gettable_ctx_params(void)
{
    return chacha20_poly1305_known_gettable_ctx_params;
}

static int chacha_poly1305_tls_init(PROV_CHACHA_AEAD_CTX *ctx,
                                    unsigned char *aad, size_t alen)
{
    unsigned int len;

    if (alen != EVP_AEAD_TLS1_AAD_LEN)
        return 0;

    memcpy(ctx->tls_aad, aad, EVP_AEAD_TLS1_AAD_LEN);
    len = aad[EVP_AEAD_TLS1_AAD_LEN - 2] << 8 | aad[EVP_AEAD_TLS1_AAD_LEN - 1];
    aad = ctx->tls_aad;
    if (!ctx->enc) {
        if (len < POLY1305_BLOCK_SIZE)
            return 0;
        len -= POLY1305_BLOCK_SIZE; /* discount attached tag */
        aad[EVP_AEAD_TLS1_AAD_LEN - 2] = (unsigned char)(len >> 8);
        aad[EVP_AEAD_TLS1_AAD_LEN - 1] = (unsigned char)len;
    }
    ctx->tls_payload_length = len;

    /* merge record sequence number as per RFC7905 */
    ctx->chacha.counter[1] = ctx->nonce[0];
    ctx->chacha.counter[2] = ctx->nonce[1] ^ CHACHA_U8TOU32(aad);
    ctx->chacha.counter[3] = ctx->nonce[2] ^ CHACHA_U8TOU32(aad+4);
    ctx->mac_inited = 0;

    return POLY1305_BLOCK_SIZE;         /* tag length */
}

static int chacha_poly1305_tls_iv_set_fixed(PROV_CHACHA_AEAD_CTX *ctx,
                                            unsigned char *fixed, size_t flen)
{
    if (flen != CHACHA20_POLY1305_IVLEN)
        return 0;
    ctx->nonce[0] = ctx->chacha.counter[1] = CHACHA_U8TOU32(fixed);
    ctx->nonce[1] = ctx->chacha.counter[2] = CHACHA_U8TOU32(fixed + 4);
    ctx->nonce[2] = ctx->chacha.counter[3] = CHACHA_U8TOU32(fixed + 8);
    return 1;
}

static int chacha20_poly1305_set_ctx_params(void *vctx,
                                            const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    size_t len;
    PROV_CHACHA_AEAD_CTX *ctx = (PROV_CHACHA_AEAD_CTX *)vctx;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != CHACHA20_POLY1305_KEYLEN) {
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
        if (len == 0 || len > CHACHA20_POLY1305_MAX_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        ctx->nonce_len = len;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (p->data_size == 0 || p->data_size > POLY1305_BLOCK_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAGLEN);
            return 0;
        }
        if (p->data != NULL) {
            if (ctx->enc) {
                ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_NEEDED);
                return 0;
            }
            memcpy(ctx->tag, p->data, p->data_size);
        }
        ctx->tag_len = p->data_size;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        len = chacha_poly1305_tls_init(ctx, p->data, p->data_size);
        if (len == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            return 0;
        }
        ctx->tls_aad_pad_sz = len;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (chacha_poly1305_tls_iv_set_fixed(ctx, p->data, p->data_size) == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IVLEN);
            return 0;
        }
    }
    /* ignore OSSL_CIPHER_PARAM_AEAD_MAC_KEY */
    return 1;
}

static int chacha20_poly1305_init(void *vctx, const unsigned char *key,
                                  size_t keylen, const unsigned char *iv,
                                  size_t ivlen, size_t enc)
{
    PROV_CHACHA_AEAD_CTX *ctx = (PROV_CHACHA_AEAD_CTX *)vctx;

    ctx->enc = (enc == 1);

    if (key == NULL && iv == NULL)
        return 1;

    ctx->len.aad = 0;
    ctx->len.text = 0;
    ctx->aad = 0;
    ctx->mac_inited = 0;
    ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

    if (key != NULL)
        CHACHA20_init_key(&ctx->chacha, key, NULL, enc);

    if (iv != NULL) {
        unsigned char tempiv[CHACHA_CTR_SIZE] = { 0 };

        /* pad on the left */
        if (ctx->nonce_len <= CHACHA_CTR_SIZE)
            memcpy(tempiv + CHACHA_CTR_SIZE - ctx->nonce_len, iv, ctx->nonce_len);

        CHACHA20_init_key(&ctx->chacha, NULL, tempiv, enc);
        ctx->nonce[0] = ctx->chacha.counter[1];
        ctx->nonce[1] = ctx->chacha.counter[2];
        ctx->nonce[2] = ctx->chacha.counter[3];
        ctx->iv_set = 1;
    }
    return 1;
}

static int chacha20_poly1305_einit(void *vctx, const unsigned char *key,
                                  size_t keylen, const unsigned char *iv,
                                  size_t ivlen)
{
    return chacha20_poly1305_init(vctx, key, keylen, iv, ivlen, 1);
}

static int chacha20_poly1305_dinit(void *vctx, const unsigned char *key,
                                  size_t keylen, const unsigned char *iv,
                                  size_t ivlen)
{
    return chacha20_poly1305_init(vctx, key, keylen, iv, ivlen, 0);
}

#if !defined(OPENSSL_SMALL_FOOTPRINT)

# if defined(POLY1305_ASM) && (defined(__x86_64) || defined(__x86_64__) \
     || defined(_M_AMD64) || defined(_M_X64))
#  define XOR128_HELPERS
void *xor128_encrypt_n_pad(void *out, const void *inp, void *otp, size_t len);
void *xor128_decrypt_n_pad(void *out, const void *inp, void *otp, size_t len);
static const unsigned char zero[4 * CHACHA_BLK_SIZE] = { 0 };
# else
static const unsigned char zero[2 * CHACHA_BLK_SIZE] = { 0 };
# endif

static int chacha20_poly1305_tls_cipher(void *vctx, unsigned char *out,
                                        size_t *out_padlen,
                                        const unsigned char *in, size_t len)
{
    PROV_CHACHA_AEAD_CTX *ctx = (PROV_CHACHA_AEAD_CTX *)vctx;
    POLY1305 *poly = &ctx->poly1305;
    size_t tail, tohash_len, buf_len, plen = ctx->tls_payload_length;
    unsigned char *buf, *tohash, *ctr, storage[sizeof(zero) + 32];

    const union {
        long one;
        char little;
    } is_endian = { 1 };

    if (len != plen + POLY1305_BLOCK_SIZE)
        return 0;

    buf = storage + ((0 - (size_t)storage) & 15);   /* align */
    ctr = buf + CHACHA_BLK_SIZE;
    tohash = buf + CHACHA_BLK_SIZE - POLY1305_BLOCK_SIZE;

# ifdef XOR128_HELPERS
    if (plen <= 3 * CHACHA_BLK_SIZE) {
        ctx->chacha.counter[0] = 0;
        buf_len = (plen + 2 * CHACHA_BLK_SIZE - 1) & (0 - CHACHA_BLK_SIZE);
        ChaCha20_ctr32(buf, zero, buf_len, ctx->chacha.key.d, ctx->chacha.counter);
        Poly1305_Init(poly, buf);
        ctx->chacha.partial_len = 0;
        memcpy(tohash, ctx->tls_aad, POLY1305_BLOCK_SIZE);
        tohash_len = POLY1305_BLOCK_SIZE;
        ctx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
        ctx->len.text = plen;

        if (plen) {
            if (ctx->enc)
                ctr = xor128_encrypt_n_pad(out, in, ctr, plen);
            else
                ctr = xor128_decrypt_n_pad(out, in, ctr, plen);

            in += plen;
            out += plen;
            tohash_len = (size_t)(ctr - tohash);
        }
    }
# else
    if (plen <= CHACHA_BLK_SIZE) {
        size_t i;

        ctx->chacha.counter[0] = 0;
        ChaCha20_ctr32(buf, zero, (buf_len = 2 * CHACHA_BLK_SIZE),
                       ctx->chacha.key.d, ctx->chacha.counter);
        Poly1305_Init(poly, buf);
        ctx->chacha.partial_len = 0;
        memcpy(tohash, ctx->tls_aad, POLY1305_BLOCK_SIZE);
        tohash_len = POLY1305_BLOCK_SIZE;
        ctx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
        ctx->len.text = plen;

        if (ctx->enc) {
            for (i = 0; i < plen; i++)
                out[i] = ctr[i] ^= in[i];
        } else {
            for (i = 0; i < plen; i++) {
                unsigned char c = in[i];

                out[i] = ctr[i] ^ c;
                ctr[i] = c;
            }
        }

        in += i;
        out += i;

        tail = (0 - i) & (POLY1305_BLOCK_SIZE - 1);
        memset(ctr + i, 0, tail);
        ctr += i + tail;
        tohash_len += i + tail;
    }
# endif
    else {
        ctx->chacha.counter[0] = 0;
        ChaCha20_ctr32(buf, zero, (buf_len = CHACHA_BLK_SIZE),
                       ctx->chacha.key.d, ctx->chacha.counter);
        Poly1305_Init(poly, buf);
        ctx->chacha.counter[0] = 1;
        ctx->chacha.partial_len = 0;
        Poly1305_Update(poly, ctx->tls_aad, POLY1305_BLOCK_SIZE);
        tohash = ctr;
        tohash_len = 0;
        ctx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
        ctx->len.text = plen;

        if (ctx->enc) {
            ChaCha20_ctr32(out, in, plen, ctx->chacha.key.d, ctx->chacha.counter);
            Poly1305_Update(poly, out, plen);
        } else {
            Poly1305_Update(poly, in, plen);
            ChaCha20_ctr32(out, in, plen, ctx->chacha.key.d, ctx->chacha.counter);
        }

        in += plen;
        out += plen;
        tail = (0 - plen) & (POLY1305_BLOCK_SIZE - 1);
        Poly1305_Update(poly, zero, tail);
    }

    if (is_endian.little) {
        memcpy(ctr, (unsigned char *)&ctx->len, POLY1305_BLOCK_SIZE);
    } else {
        ctr[0]  = (unsigned char)(ctx->len.aad);
        ctr[1]  = (unsigned char)(ctx->len.aad>>8);
        ctr[2]  = (unsigned char)(ctx->len.aad>>16);
        ctr[3]  = (unsigned char)(ctx->len.aad>>24);
        ctr[4]  = (unsigned char)(ctx->len.aad>>32);
        ctr[5]  = (unsigned char)(ctx->len.aad>>40);
        ctr[6]  = (unsigned char)(ctx->len.aad>>48);
        ctr[7]  = (unsigned char)(ctx->len.aad>>56);

        ctr[8]  = (unsigned char)(ctx->len.text);
        ctr[9]  = (unsigned char)(ctx->len.text>>8);
        ctr[10] = (unsigned char)(ctx->len.text>>16);
        ctr[11] = (unsigned char)(ctx->len.text>>24);
        ctr[12] = (unsigned char)(ctx->len.text>>32);
        ctr[13] = (unsigned char)(ctx->len.text>>40);
        ctr[14] = (unsigned char)(ctx->len.text>>48);
        ctr[15] = (unsigned char)(ctx->len.text>>56);
    }
    tohash_len += POLY1305_BLOCK_SIZE;

    Poly1305_Update(poly, tohash, tohash_len);
    OPENSSL_cleanse(buf, buf_len);
    Poly1305_Final(poly, ctx->enc ? ctx->tag : tohash);

    ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

    if (ctx->enc) {
        memcpy(out, ctx->tag, POLY1305_BLOCK_SIZE);
    } else {
        if (CRYPTO_memcmp(tohash, in, POLY1305_BLOCK_SIZE)) {
            memset(out - (len - POLY1305_BLOCK_SIZE), 0,
                   len - POLY1305_BLOCK_SIZE);
            return 0;
        }
    }

    *out_padlen = len;
    return 1;
}
#else
static const unsigned char zero[CHACHA_BLK_SIZE] = { 0 };
#endif /* OPENSSL_SMALL_FOOTPRINT */

static int chacha20_poly1305_cipher_internal(PROV_CHACHA_AEAD_CTX *ctx,
                                             unsigned char *out, size_t *outl,
                                             const unsigned char *in, size_t inl)
{
    POLY1305 *poly = &ctx->poly1305;
    size_t rem, plen = ctx->tls_payload_length;
    size_t olen = 0;
    int rv = 0;

    const union {
        long one;
        char little;
    } is_endian = { 1 };

    if (!ctx->mac_inited) {
#if !defined(OPENSSL_SMALL_FOOTPRINT)
        if (plen != NO_TLS_PAYLOAD_LENGTH && out != NULL) {
            return chacha20_poly1305_tls_cipher(ctx, out, outl, in, inl);
        }
#endif
        ctx->chacha.counter[0] = 0;
        ChaCha20_ctr32(ctx->chacha.buf, zero, CHACHA_BLK_SIZE,
                       ctx->chacha.key.d, ctx->chacha.counter);
        Poly1305_Init(poly, ctx->chacha.buf);
        ctx->chacha.counter[0] = 1;
        ctx->chacha.partial_len = 0;
        ctx->len.aad = ctx->len.text = 0;
        ctx->mac_inited = 1;
        if (plen != NO_TLS_PAYLOAD_LENGTH) {
            Poly1305_Update(poly, ctx->tls_aad, EVP_AEAD_TLS1_AAD_LEN);
            ctx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
            ctx->aad = 1;
        }
    }

    if (in != NULL) { /* aad or text */
        if (out == NULL) { /* aad */
            Poly1305_Update(poly, in, inl);
            ctx->len.aad += inl;
            ctx->aad = 1;
            goto finish;
        } else { /* plain- or ciphertext */
            if (ctx->aad) { /* wrap up aad */
                if ((rem = (size_t)ctx->len.aad % POLY1305_BLOCK_SIZE))
                    Poly1305_Update(poly, zero, POLY1305_BLOCK_SIZE - rem);
                ctx->aad = 0;
            }

            ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
            if (plen == NO_TLS_PAYLOAD_LENGTH)
                plen = inl;
            else if (inl != plen + POLY1305_BLOCK_SIZE)
                goto err;

            if (ctx->enc) { /* plaintext */
                CHACHA20_cipher(&ctx->chacha, out, in, plen);
                Poly1305_Update(poly, out, plen);
                in += plen;
                out += plen;
                ctx->len.text += plen;
            } else { /* ciphertext */
                Poly1305_Update(poly, in, plen);
                CHACHA20_cipher(&ctx->chacha, out, in, plen);
                in += plen;
                out += plen;
                ctx->len.text += plen;
            }
        }
    }
    /* explicit final, or tls mode */
    if (in == NULL || inl != plen) {

        unsigned char temp[POLY1305_BLOCK_SIZE];

        if (ctx->aad) {                        /* wrap up aad */
            if ((rem = (size_t)ctx->len.aad % POLY1305_BLOCK_SIZE))
                Poly1305_Update(poly, zero, POLY1305_BLOCK_SIZE - rem);
            ctx->aad = 0;
        }

        if ((rem = (size_t)ctx->len.text % POLY1305_BLOCK_SIZE))
            Poly1305_Update(poly, zero, POLY1305_BLOCK_SIZE - rem);

        if (is_endian.little) {
            Poly1305_Update(poly, (unsigned char *)&ctx->len,
                            POLY1305_BLOCK_SIZE);
        } else {
            temp[0]  = (unsigned char)(ctx->len.aad);
            temp[1]  = (unsigned char)(ctx->len.aad>>8);
            temp[2]  = (unsigned char)(ctx->len.aad>>16);
            temp[3]  = (unsigned char)(ctx->len.aad>>24);
            temp[4]  = (unsigned char)(ctx->len.aad>>32);
            temp[5]  = (unsigned char)(ctx->len.aad>>40);
            temp[6]  = (unsigned char)(ctx->len.aad>>48);
            temp[7]  = (unsigned char)(ctx->len.aad>>56);
            temp[8]  = (unsigned char)(ctx->len.text);
            temp[9]  = (unsigned char)(ctx->len.text>>8);
            temp[10] = (unsigned char)(ctx->len.text>>16);
            temp[11] = (unsigned char)(ctx->len.text>>24);
            temp[12] = (unsigned char)(ctx->len.text>>32);
            temp[13] = (unsigned char)(ctx->len.text>>40);
            temp[14] = (unsigned char)(ctx->len.text>>48);
            temp[15] = (unsigned char)(ctx->len.text>>56);
            Poly1305_Update(poly, temp, POLY1305_BLOCK_SIZE);
        }
        Poly1305_Final(poly, ctx->enc ? ctx->tag : temp);
        ctx->mac_inited = 0;

        if (in != NULL && inl != plen) {
            if (ctx->enc) {
                memcpy(out, ctx->tag, POLY1305_BLOCK_SIZE);
            } else {
                if (CRYPTO_memcmp(temp, in, POLY1305_BLOCK_SIZE)) {
                    memset(out - plen, 0, plen);
                    goto err;
                }
            }
        }
        else if (!ctx->enc) {
            if (CRYPTO_memcmp(temp, ctx->tag, ctx->tag_len))
                goto err;
        }
    }
finish:
    olen = inl;
    rv = 1;
err:
    *outl = olen;
    return rv;
}


static int chacha20_poly1305_update(void *vctx,
                           unsigned char *out, size_t *outl, size_t outsize,
                           const unsigned char *in, size_t inl)
{
    PROV_CHACHA_AEAD_CTX *ctx = (PROV_CHACHA_AEAD_CTX *)vctx;

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return -1;
    }

    if (chacha20_poly1305_cipher_internal(ctx, out, outl, in, inl) <= 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return -1;
    }
    return 1;
}

static int chacha20_poly1305_final(void *vctx, unsigned char *out, size_t *outl,
                                   size_t outsize)
{
    if (chacha20_poly1305_cipher_internal(vctx, out, outl, NULL, 0) <= 0)
        return 0;
    *outl = 0;
    return 1;
}

static int chacha20_poly1305_cipher(void *vctx, unsigned char *out,
                                    size_t *outl, size_t outsize,
                                    const unsigned char *in, size_t inl)
{
    PROV_CHACHA_AEAD_CTX *ctx = (PROV_CHACHA_AEAD_CTX *)vctx;

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return -1;
    }

    if (chacha20_poly1305_cipher_internal(ctx, out, outl, in, inl) <= 0)
        return -1;

    *outl = inl;
    return 1;
}

/* chacha20_poly1305_functions */
const OSSL_DISPATCH chacha20_poly1305_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))chacha20_poly1305_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))chacha20_poly1305_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))chacha20_poly1305_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))chacha20_poly1305_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))chacha20_poly1305_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))chacha20_poly1305_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))chacha20_poly1305_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS,
        (void (*)(void))chacha20_poly1305_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
        (void (*)(void))chacha20_poly1305_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
         (void (*)(void))chacha20_poly1305_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        (void (*)(void))chacha20_poly1305_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
        (void (*)(void))chacha20_poly1305_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        (void (*)(void))chacha20_poly1305_settable_ctx_params },
    { 0, NULL }
};

