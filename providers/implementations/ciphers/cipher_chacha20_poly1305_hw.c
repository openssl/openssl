/*
 * Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* chacha20_poly1305 cipher implementation */

#include <openssl/proverr.h>
#include "internal/endian.h"
#include "cipher_chacha20_poly1305.h"

/* Start of a message: the fused path is eligible again and holds no AAD. */
#ifdef CHACHA20_POLY1305_AVX512_CAPABLE
#define FUSE_RESET(c)                                       \
    ((c)->fuse_state = FUSE_UNDECIDED, (c)->aad_buflen = 0, \
        (c)->fuse_aad_done = 0)

#if defined(__GNUC__) && defined(__ELF__)
/*
 * The test defines this. Production leaves it unresolved, so the address
 * is NULL and the record path does not call it.
 */
extern void ossl_chacha20_poly1305_tls_fused_record(void) __attribute__((weak));
#endif
#else
#define FUSE_RESET(c) ((void)0)
#endif

static int chacha_poly1305_tls_init(PROV_CIPHER_CTX *bctx,
    unsigned char *aad, size_t alen)
{
    unsigned int len;
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)bctx;

    if (alen != EVP_AEAD_TLS1_AAD_LEN)
        return 0;

    memcpy(ctx->tls_aad, aad, EVP_AEAD_TLS1_AAD_LEN);
    len = aad[EVP_AEAD_TLS1_AAD_LEN - 2] << 8 | aad[EVP_AEAD_TLS1_AAD_LEN - 1];
    aad = ctx->tls_aad;
    if (!bctx->enc) {
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
    ctx->chacha.counter[3] = ctx->nonce[2] ^ CHACHA_U8TOU32(aad + 4);
    ctx->mac_inited = 0;
    FUSE_RESET(ctx);

    return POLY1305_BLOCK_SIZE; /* tag length */
}

static int chacha_poly1305_tls_iv_set_fixed(PROV_CIPHER_CTX *bctx,
    unsigned char *fixed, size_t flen)
{
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)bctx;

    if (flen != CHACHA20_POLY1305_IVLEN)
        return 0;
    ctx->nonce[0] = ctx->chacha.counter[1] = CHACHA_U8TOU32(fixed);
    ctx->nonce[1] = ctx->chacha.counter[2] = CHACHA_U8TOU32(fixed + 4);
    ctx->nonce[2] = ctx->chacha.counter[3] = CHACHA_U8TOU32(fixed + 8);
    return 1;
}

static int chacha20_poly1305_initkey(PROV_CIPHER_CTX *bctx,
    const unsigned char *key, size_t keylen)
{
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)bctx;

    ctx->len.aad = 0;
    ctx->len.text = 0;
    ctx->aad = 0;
    ctx->mac_inited = 0;
    FUSE_RESET(ctx);
    ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

    if (bctx->enc)
        return ossl_chacha20_einit(&ctx->chacha, key, keylen, NULL, 0, NULL);
    else
        return ossl_chacha20_dinit(&ctx->chacha, key, keylen, NULL, 0, NULL);
}

static int chacha20_poly1305_initiv(PROV_CIPHER_CTX *bctx)
{
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)bctx;
    unsigned char tempiv[CHACHA_CTR_SIZE] = { 0 };
    int ret = 1;
    size_t noncelen = CHACHA20_POLY1305_IVLEN;

    ctx->len.aad = 0;
    ctx->len.text = 0;
    ctx->aad = 0;
    ctx->mac_inited = 0;
    FUSE_RESET(ctx);
    ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

    /* pad on the left */
    memcpy(tempiv + CHACHA_CTR_SIZE - noncelen, bctx->oiv,
        noncelen);

    if (bctx->enc)
        ret = ossl_chacha20_einit(&ctx->chacha, NULL, 0,
            tempiv, sizeof(tempiv), NULL);
    else
        ret = ossl_chacha20_dinit(&ctx->chacha, NULL, 0,
            tempiv, sizeof(tempiv), NULL);
    ctx->nonce[0] = ctx->chacha.counter[1];
    ctx->nonce[1] = ctx->chacha.counter[2];
    ctx->nonce[2] = ctx->chacha.counter[3];
    bctx->iv_set = 1;
    return ret;
}

#if !defined(OPENSSL_SMALL_FOOTPRINT)

#if defined(POLY1305_ASM) && (defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64))
#define XOR128_HELPERS
void *xor128_encrypt_n_pad(void *out, const void *inp, void *otp, size_t len);
void *xor128_decrypt_n_pad(void *out, const void *inp, void *otp, size_t len);
static const unsigned char zero[4 * CHACHA_BLK_SIZE] = { 0 };
#else
static const unsigned char zero[2 * CHACHA_BLK_SIZE] = { 0 };
#endif

static int chacha20_poly1305_tls_cipher(PROV_CIPHER_CTX *bctx,
    unsigned char *out,
    size_t *out_padlen,
    const unsigned char *in, size_t len)
{
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)bctx;
    POLY1305 *poly = &ctx->poly1305;
    size_t tail, tohash_len, buf_len, plen = ctx->tls_payload_length;
    unsigned char *buf, *tohash, *ctr, storage[sizeof(zero) + 32];

    DECLARE_IS_ENDIAN;

#ifdef CHACHA20_POLY1305_AVX512_CAPABLE
    /*
     * tls_aad is the 13-byte TLS AAD; the kernel pads it.  counter[1..3]
     * is the RFC 7905 nonce.  Encrypt appends the tag.  Decrypt compares
     * it and wipes the output, without PROV_R_BAD_DECRYPT.
     */
    if (ossl_chacha20_poly1305_avx512_available()) {
        unsigned char tag[POLY1305_BLOCK_SIZE];

#if defined(__GNUC__) && defined(__ELF__)
        if (ossl_chacha20_poly1305_tls_fused_record != NULL)
            ossl_chacha20_poly1305_tls_fused_record();
#endif

        if (!ossl_chacha20_poly1305_avx512(out, in, plen, ctx->tls_aad,
                EVP_AEAD_TLS1_AAD_LEN, ctx->chacha.key.d, ctx->chacha.counter,
                tag, bctx->enc))
            return 0;

        ctx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
        ctx->len.text = plen;
        ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

        if (bctx->enc) {
            memcpy(ctx->tag, tag, POLY1305_BLOCK_SIZE);
            memcpy(out + plen, tag, POLY1305_BLOCK_SIZE);
        } else if (CRYPTO_memcmp(tag, in + plen, POLY1305_BLOCK_SIZE) != 0) {
            OPENSSL_cleanse(tag, sizeof(tag));
            if (plen != 0)
                memset(out, 0, plen);
            return 0;
        } else {
            len -= POLY1305_BLOCK_SIZE;
        }
        OPENSSL_cleanse(tag, sizeof(tag));

        *out_padlen = len;
        return 1;
    }
#endif

    buf = storage + ((0 - (size_t)storage) & 15); /* align */
    ctr = buf + CHACHA_BLK_SIZE;
    tohash = buf + CHACHA_BLK_SIZE - POLY1305_BLOCK_SIZE;

#ifdef XOR128_HELPERS
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
            if (bctx->enc)
                ctr = xor128_encrypt_n_pad(out, in, ctr, plen);
            else
                ctr = xor128_decrypt_n_pad(out, in, ctr, plen);

            in += plen;
            out += plen;
            tohash_len = (size_t)(ctr - tohash);
        }
    }
#else
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

        if (bctx->enc) {
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
#endif
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

        if (bctx->enc) {
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

    if (IS_LITTLE_ENDIAN) {
        memcpy(ctr, (unsigned char *)&ctx->len, POLY1305_BLOCK_SIZE);
    } else {
        ctr[0] = (unsigned char)(ctx->len.aad);
        ctr[1] = (unsigned char)(ctx->len.aad >> 8);
        ctr[2] = (unsigned char)(ctx->len.aad >> 16);
        ctr[3] = (unsigned char)(ctx->len.aad >> 24);
        ctr[4] = (unsigned char)(ctx->len.aad >> 32);
        ctr[5] = (unsigned char)(ctx->len.aad >> 40);
        ctr[6] = (unsigned char)(ctx->len.aad >> 48);
        ctr[7] = (unsigned char)(ctx->len.aad >> 56);

        ctr[8] = (unsigned char)(ctx->len.text);
        ctr[9] = (unsigned char)(ctx->len.text >> 8);
        ctr[10] = (unsigned char)(ctx->len.text >> 16);
        ctr[11] = (unsigned char)(ctx->len.text >> 24);
        ctr[12] = (unsigned char)(ctx->len.text >> 32);
        ctr[13] = (unsigned char)(ctx->len.text >> 40);
        ctr[14] = (unsigned char)(ctx->len.text >> 48);
        ctr[15] = (unsigned char)(ctx->len.text >> 56);
    }
    tohash_len += POLY1305_BLOCK_SIZE;

    Poly1305_Update(poly, tohash, tohash_len);
    OPENSSL_cleanse(buf, buf_len);
    Poly1305_Final(poly, bctx->enc ? ctx->tag : tohash);

    ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

    if (bctx->enc) {
        memcpy(out, ctx->tag, POLY1305_BLOCK_SIZE);
    } else {
        /* TODO: raise PROV_R_BAD_DECRYPT here too? TLS record path, silent for now */
        if (CRYPTO_memcmp(tohash, in, POLY1305_BLOCK_SIZE)) {
            if (len > POLY1305_BLOCK_SIZE)
                memset(out - (len - POLY1305_BLOCK_SIZE), 0,
                    len - POLY1305_BLOCK_SIZE);
            return 0;
        }
        /* Strip the tag */
        len -= POLY1305_BLOCK_SIZE;
    }

    *out_padlen = len;
    return 1;
}
#else
static const unsigned char zero[CHACHA_BLK_SIZE] = { 0 };
#endif /* OPENSSL_SMALL_FOOTPRINT */

#ifdef CHACHA20_POLY1305_AVX512_CAPABLE
/*
 * Fused path.  The kernel owns the MAC.  Short AAD was held so init can
 * see the payload length.  Longer AAD is streamed here with hint 0.
 */
static int chacha20_poly1305_fused_cipher(PROV_CIPHER_CTX *bctx,
    unsigned char *out, size_t *outl,
    const unsigned char *in, size_t inl)
{
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)bctx;
    size_t olen = 0;

    if (!ctx->mac_inited) {
        size_t hint = (out != NULL) ? inl : 0;

        /* Nonce is counter[1..3].  The kernel ignores counter[0]. */
        ossl_chacha20_poly1305_avx512_init(&ctx->fused, ctx->chacha.key.d,
            ctx->chacha.counter, hint);
        ctx->len.aad = ctx->aad_buflen;
        ctx->len.text = 0;
        if (ctx->aad_buflen != 0)
            ossl_chacha20_poly1305_avx512_aad(&ctx->fused, ctx->aad_buf,
                ctx->aad_buflen);
        ctx->aad_buflen = 0;
        ctx->aad = 0;
        ctx->mac_inited = 1;
        ctx->fuse_aad_done = 0;
    }

    if (in != NULL && out == NULL) {
        if (ctx->fuse_aad_done) {
            ERR_raise(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER);
            return 0;
        }
        ossl_chacha20_poly1305_avx512_aad(&ctx->fused, in, inl);
        ctx->len.aad += inl;
        *outl = 0;
        return 1;
    }

    if (!ctx->fuse_aad_done) {
        ossl_chacha20_poly1305_avx512_aad_done(&ctx->fused);
        ctx->fuse_aad_done = 1;
    }

    if (in != NULL) {
        if (!ossl_chacha20_poly1305_avx512_cipher(&ctx->fused, out, in, inl,
                bctx->enc)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
            *outl = 0;
            return 0;
        }
        ctx->len.text += inl;
        olen = inl;
    } else { /* explicit final */
        unsigned char temp[POLY1305_BLOCK_SIZE];

        ossl_chacha20_poly1305_avx512_final(&ctx->fused,
            bctx->enc ? ctx->tag : temp,
            ctx->len.aad, ctx->len.text);
        ctx->mac_inited = 0;
        FUSE_RESET(ctx);
        if (!bctx->enc && CRYPTO_memcmp(temp, ctx->tag, ctx->tag_len) != 0) {
            OPENSSL_cleanse(temp, sizeof(temp));
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
            return 0;
        }
        OPENSSL_cleanse(temp, sizeof(temp));
    }

    *outl = olen;
    return 1;
}

/*
 * One decision per message.  TLS leaves this off; tls_cipher calls the
 * one-shot when the CPU can run the kernel.  A small-footprint build
 * keeps TLS two-pass.  AAD that fits stays undecided until the first
 * payload.  Longer AAD starts the kernel with hint 0.  Without the
 * kernel the message stays two-pass.  Payload length does not select
 * two-pass.
 */
static int chacha20_poly1305_fuse_decide(PROV_CHACHA20_POLY1305_CTX *ctx,
    unsigned char *out, const unsigned char *in, size_t inl)
{
    if (ctx->tls_payload_length != NO_TLS_PAYLOAD_LENGTH
        || !ossl_chacha20_poly1305_avx512_available()) {
        ctx->fuse_state = FUSE_OFF;
    } else if (in != NULL && out == NULL) { /* aad */
        if (inl > sizeof(ctx->aad_buf) - ctx->aad_buflen) {
            ctx->fuse_state = FUSE_ON;
        } else {
            memcpy(ctx->aad_buf + ctx->aad_buflen, in, inl);
            ctx->aad_buflen += inl;
        }
    } else if (in != NULL) {
        ctx->fuse_state = FUSE_ON;
    } else {
        ctx->fuse_state = FUSE_OFF;
    }

    return ctx->fuse_state;
}
#endif /* CHACHA20_POLY1305_AVX512_CAPABLE */

static int chacha20_poly1305_aead_cipher(PROV_CIPHER_CTX *bctx,
    unsigned char *out, size_t *outl,
    const unsigned char *in, size_t inl)
{
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)bctx;
    POLY1305 *poly = &ctx->poly1305;
    size_t rem, plen = ctx->tls_payload_length;
    size_t olen = 0;
    int rv = 0;

    DECLARE_IS_ENDIAN;

#ifdef CHACHA20_POLY1305_AVX512_CAPABLE
    if (ctx->fuse_state == FUSE_UNDECIDED
        && chacha20_poly1305_fuse_decide(ctx, out, in, inl)
            == FUSE_UNDECIDED) {
        *outl = 0; /* aad buffered, nothing decided yet */
        ctx->aad = 1;
        return 1;
    }
    if (ctx->fuse_state == FUSE_ON)
        return chacha20_poly1305_fused_cipher(bctx, out, outl, in, inl);
#endif

    if (!ctx->mac_inited) {
        if (plen != NO_TLS_PAYLOAD_LENGTH && out != NULL) {
            if (inl != plen + POLY1305_BLOCK_SIZE)
                return 0;
#if !defined(OPENSSL_SMALL_FOOTPRINT)
            return chacha20_poly1305_tls_cipher(bctx, out, outl, in, inl);
#endif
        }

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

#ifdef CHACHA20_POLY1305_AVX512_CAPABLE
    if (ctx->aad_buflen != 0) { /* replay AAD held back by the fuse decision */
        Poly1305_Update(poly, ctx->aad_buf, ctx->aad_buflen);
        ctx->len.aad += ctx->aad_buflen;
        ctx->aad_buflen = 0;
        ctx->aad = 1;
    }
#endif

    if (in != NULL) { /* aad or text */
        if (out == NULL) { /* aad */
            if (ctx->len.text != 0) {
                ERR_raise(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER);
                goto err;
            }
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

            if (bctx->enc) { /* plaintext */
                ctx->chacha.base.hw->cipher(&ctx->chacha.base, out, in, plen);
                Poly1305_Update(poly, out, plen);
                in += plen;
                out += plen;
                ctx->len.text += plen;
            } else { /* ciphertext */
                Poly1305_Update(poly, in, plen);
                ctx->chacha.base.hw->cipher(&ctx->chacha.base, out, in, plen);
                in += plen;
                out += plen;
                ctx->len.text += plen;
            }
        }
    }
    /* explicit final, or tls mode */
    if (in == NULL || inl != plen) {

        unsigned char temp[POLY1305_BLOCK_SIZE];

        if (ctx->aad) { /* wrap up aad */
            if ((rem = (size_t)ctx->len.aad % POLY1305_BLOCK_SIZE))
                Poly1305_Update(poly, zero, POLY1305_BLOCK_SIZE - rem);
            ctx->aad = 0;
        }

        if ((rem = (size_t)ctx->len.text % POLY1305_BLOCK_SIZE))
            Poly1305_Update(poly, zero, POLY1305_BLOCK_SIZE - rem);

        if (IS_LITTLE_ENDIAN) {
            Poly1305_Update(poly, (unsigned char *)&ctx->len,
                POLY1305_BLOCK_SIZE);
        } else {
            temp[0] = (unsigned char)(ctx->len.aad);
            temp[1] = (unsigned char)(ctx->len.aad >> 8);
            temp[2] = (unsigned char)(ctx->len.aad >> 16);
            temp[3] = (unsigned char)(ctx->len.aad >> 24);
            temp[4] = (unsigned char)(ctx->len.aad >> 32);
            temp[5] = (unsigned char)(ctx->len.aad >> 40);
            temp[6] = (unsigned char)(ctx->len.aad >> 48);
            temp[7] = (unsigned char)(ctx->len.aad >> 56);
            temp[8] = (unsigned char)(ctx->len.text);
            temp[9] = (unsigned char)(ctx->len.text >> 8);
            temp[10] = (unsigned char)(ctx->len.text >> 16);
            temp[11] = (unsigned char)(ctx->len.text >> 24);
            temp[12] = (unsigned char)(ctx->len.text >> 32);
            temp[13] = (unsigned char)(ctx->len.text >> 40);
            temp[14] = (unsigned char)(ctx->len.text >> 48);
            temp[15] = (unsigned char)(ctx->len.text >> 56);
            Poly1305_Update(poly, temp, POLY1305_BLOCK_SIZE);
        }
        Poly1305_Final(poly, bctx->enc ? ctx->tag : temp);
        ctx->mac_inited = 0;
        FUSE_RESET(ctx);

        if (in != NULL && inl != plen) {
            if (bctx->enc) {
                memcpy(out, ctx->tag, POLY1305_BLOCK_SIZE);
            } else {
                /* TODO: raise PROV_R_BAD_DECRYPT here too? TLS record path, silent for now */
                if (CRYPTO_memcmp(temp, in, POLY1305_BLOCK_SIZE)) {
                    memset(out - plen, 0, plen);
                    goto err;
                }
                /* Strip the tag */
                inl -= POLY1305_BLOCK_SIZE;
            }
        } else if (!bctx->enc) {
            if (CRYPTO_memcmp(temp, ctx->tag, ctx->tag_len) != 0) {
                ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
                goto err;
            }
        }
    }
finish:
    olen = inl;
    rv = 1;
err:
    *outl = olen;
    return rv;
}

static const PROV_CIPHER_HW_CHACHA20_POLY1305 chacha20poly1305_hw = {
    { chacha20_poly1305_initkey, NULL },
    chacha20_poly1305_aead_cipher,
    chacha20_poly1305_initiv,
    chacha_poly1305_tls_init,
    chacha_poly1305_tls_iv_set_fixed
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_chacha20_poly1305(size_t keybits)
{
    return (const PROV_CIPHER_HW *)&chacha20poly1305_hw;
}
