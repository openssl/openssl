/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include "internal/rand_int.h"
#include "internal/provider_algs.h"
#include "internal/provider_ctx.h"
#include "internal/providercommonerr.h"
#include "ciphers_locl.h"

/* TODO(3.0) Figure out what flags are really needed */
#define AEAD_GCM_FLAGS (EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_FLAG_DEFAULT_ASN1 \
                       | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER      \
                       | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT        \
                       | EVP_CIPH_CUSTOM_COPY)

static OSSL_OP_cipher_encrypt_init_fn gcm_einit;
static OSSL_OP_cipher_decrypt_init_fn gcm_dinit;
static OSSL_OP_cipher_ctx_get_params_fn gcm_ctx_get_params;
static OSSL_OP_cipher_ctx_set_params_fn gcm_ctx_set_params;
static OSSL_OP_cipher_cipher_fn gcm_cipher;
static OSSL_OP_cipher_update_fn gcm_stream_update;
static OSSL_OP_cipher_final_fn gcm_stream_final;

static int gcm_tls_init(PROV_GCM_CTX *dat, unsigned char *aad, size_t aad_len);
static int gcm_tls_iv_set_fixed(PROV_GCM_CTX *ctx, unsigned char *iv,
                                size_t len);
static int gcm_tls_cipher(PROV_GCM_CTX *ctx, unsigned char *out, size_t *padlen,
                          const unsigned char *in, size_t len);
static int gcm_cipher_internal(PROV_GCM_CTX *ctx, unsigned char *out,
                               size_t *padlen, const unsigned char *in,
                               size_t len);

static void gcm_initctx(void *provctx, PROV_GCM_CTX *ctx, size_t keybits,
                        const PROV_GCM_HW *hw, size_t ivlen_min)
{
    ctx->pad = 1;
    ctx->mode = EVP_CIPH_GCM_MODE;
    ctx->taglen = -1;
    ctx->tls_aad_len = -1;
    ctx->ivlen_min = ivlen_min;
    ctx->ivlen = (EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN);
    ctx->keylen = keybits / 8;
    ctx->hw = hw;
    ctx->libctx = PROV_LIBRARY_CONTEXT_OF(provctx);
}

static void gcm_deinitctx(PROV_GCM_CTX *ctx)
{
    OPENSSL_cleanse(ctx->iv, sizeof(ctx->iv));
}

static int gcm_init(void *vctx, const unsigned char *key, size_t keylen,
                    const unsigned char *iv, size_t ivlen, int enc)
{
    PROV_GCM_CTX *ctx = (PROV_GCM_CTX *)vctx;

    ctx->enc = enc;

    if (iv != NULL) {
        if (ivlen < ctx->ivlen_min || ivlen > sizeof(ctx->iv)) {
            PROVerr(0, PROV_R_INVALID_IVLEN);
            return 0;
        }
        ctx->ivlen = ivlen;
        memcpy(ctx->iv, iv, ctx->ivlen);
        ctx->iv_state = IV_STATE_BUFFERED;
    }

    if (key != NULL) {
        if (keylen != ctx->keylen) {
            PROVerr(0, PROV_R_INVALID_KEYLEN);
            return 0;
        }
        return ctx->hw->setkey(ctx, key, ctx->keylen);
    }
    return 1;
}

static int gcm_einit(void *vctx, const unsigned char *key, size_t keylen,
                     const unsigned char *iv, size_t ivlen)
{
    return gcm_init(vctx, key, keylen, iv, ivlen, 1);
}

static int gcm_dinit(void *vctx, const unsigned char *key, size_t keylen,
                     const unsigned char *iv, size_t ivlen)
{
    return gcm_init(vctx, key, keylen, iv, ivlen, 0);
}

static int gcm_ctx_get_params(void *vctx, OSSL_PARAM params[])
{
    PROV_GCM_CTX *ctx = (PROV_GCM_CTX *)vctx;
    OSSL_PARAM *p;
    size_t sz;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_set_int(p, ctx->ivlen))
            return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_int(p, ctx->keylen)) {
        PROVerr(0, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL) {
        if (ctx->iv_gen != 1 && ctx->iv_gen_rand != 1)
            return 0;
        if (ctx->ivlen != (int)p->data_size) {
            PROVerr(0, PROV_R_INVALID_IVLEN);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivlen)) {
            PROVerr(0, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tls_aad_pad_sz)) {
        PROVerr(0, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        sz = p->data_size;
        if (sz == 0 || sz > EVP_GCM_TLS_TAG_LEN || !ctx->enc || ctx->taglen < 0) {
            PROVerr(0, PROV_R_INVALID_TAG);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, ctx->buf, sz)) {
            PROVerr(0, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    return 1;
}

static int gcm_ctx_set_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_GCM_CTX *ctx = (PROV_GCM_CTX *)vctx;
    const OSSL_PARAM *p;
    size_t sz;
    void *vp;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        vp = ctx->buf;
        if (!OSSL_PARAM_get_octet_string(p, &vp, EVP_GCM_TLS_TAG_LEN, &sz)) {
            PROVerr(0, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (sz == 0 || ctx->enc) {
            PROVerr(0, PROV_R_INVALID_TAG);
            return 0;
        }
        ctx->taglen = sz;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &sz)) {
            PROVerr(0, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (sz == 0 || sz > sizeof(ctx->iv)) {
            PROVerr(0, PROV_R_INVALID_IVLEN);
            return 0;
        }
        ctx->ivlen = sz;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            PROVerr(0, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        sz = gcm_tls_init(ctx, p->data, p->data_size);
        if (sz == 0) {
            PROVerr(0, PROV_R_INVALID_AAD);
            return 0;
        }
        ctx->tls_aad_pad_sz = sz;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            PROVerr(0, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (gcm_tls_iv_set_fixed(ctx, p->data, p->data_size) == 0) {
            PROVerr(0, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }

    /*
     * TODO(3.0) Temporary solution to address fuzz test crash, which will be
     * reworked once the discussion in PR #9510 is resolved. i.e- We need a
     * general solution for handling missing parameters inside set_params and
     * get_params methods.
     */
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        int keylen;

        if (!OSSL_PARAM_get_int(p, &keylen)) {
            PROVerr(0, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        /* The key length can not be modified for gcm mode */
        if (keylen != (int)ctx->keylen)
            return 0;
    }

    return 1;
}

static int gcm_stream_update(void *vctx, unsigned char *out, size_t *outl,
                             size_t outsize, const unsigned char *in,
                             size_t inl)
{
    PROV_GCM_CTX *ctx = (PROV_GCM_CTX *)vctx;

    if (outsize < inl) {
        PROVerr(0, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return -1;
    }

    if (gcm_cipher_internal(ctx, out, outl, in, inl) <= 0) {
        PROVerr(0, PROV_R_CIPHER_OPERATION_FAILED);
        return -1;
    }
    return 1;
}

static int gcm_stream_final(void *vctx, unsigned char *out, size_t *outl,
                            size_t outsize)
{
    PROV_GCM_CTX *ctx = (PROV_GCM_CTX *)vctx;
    int i;

    i = gcm_cipher_internal(ctx, out, outl, NULL, 0);
    if (i <= 0)
        return 0;

    *outl = 0;
    return 1;
}

static int gcm_cipher(void *vctx,
                      unsigned char *out, size_t *outl, size_t outsize,
                      const unsigned char *in, size_t inl)
{
    PROV_GCM_CTX *ctx = (PROV_GCM_CTX *)vctx;

    if (outsize < inl) {
        PROVerr(0, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return -1;
    }

    if (gcm_cipher_internal(ctx, out, outl, in, inl) <= 0)
        return -1;

    *outl = inl;
    return 1;
}

/*
 * See SP800-38D (GCM) Section 8 "Uniqueness requirement on IVS and keys"
 *
 * See also 8.2.2 RBG-based construction.
 * Random construction consists of a free field (which can be NULL) and a
 * random field which will use a DRBG that can return at least 96 bits of
 * entropy strength. (The DRBG must be seeded by the FIPS module).
 */
static int gcm_iv_generate(PROV_GCM_CTX *ctx, int offset)
{
    int sz = ctx->ivlen - offset;

    /* Must be at least 96 bits */
    if (sz <= 0 || ctx->ivlen < GCM_IV_DEFAULT_SIZE)
        return 0;

    /* Use DRBG to generate random iv */
    if (rand_bytes_ex(ctx->libctx, ctx->iv + offset, sz) <= 0)
        return 0;
    ctx->iv_state = IV_STATE_BUFFERED;
    ctx->iv_gen_rand = 1;
    return 1;
}

static int gcm_cipher_internal(PROV_GCM_CTX *ctx, unsigned char *out,
                               size_t *padlen, const unsigned char *in,
                               size_t len)
{
    size_t olen = 0;
    int rv = 0;
    const PROV_GCM_HW *hw = ctx->hw;

    if (ctx->tls_aad_len >= 0)
        return gcm_tls_cipher(ctx, out, padlen, in, len);

    if (!ctx->key_set || ctx->iv_state == IV_STATE_FINISHED)
        goto err;

    /*
     * FIPS requires generation of AES-GCM IV's inside the FIPS module.
     * The IV can still be set externally (the security policy will state that
     * this is not FIPS compliant). There are some applications
     * where setting the IV externally is the only option available.
     */
    if (ctx->iv_state == IV_STATE_UNINITIALISED) {
        if (!ctx->enc || !gcm_iv_generate(ctx, 0))
            goto err;
    }

    if (ctx->iv_state == IV_STATE_BUFFERED) {
        if (!hw->setiv(ctx, ctx->iv, ctx->ivlen))
            goto err;
        ctx->iv_state = IV_STATE_COPIED;
    }

    if (in != NULL) {
        /*  The input is AAD if out is NULL */
        if (out == NULL) {
            if (!hw->aadupdate(ctx, in, len))
                goto err;
        } else {
            /* The input is ciphertext OR plaintext */
            if (!hw->cipherupdate(ctx, in, len, out))
                goto err;
        }
    } else {
        /* Finished when in == NULL */
        if (!hw->cipherfinal(ctx, ctx->buf))
            goto err;
        ctx->iv_state = IV_STATE_FINISHED; /* Don't reuse the IV */
        goto finish;
    }
    olen = len;
finish:
    rv = 1;
err:
    *padlen = olen;
    return rv;
}

static int gcm_tls_init(PROV_GCM_CTX *dat, unsigned char *aad, size_t aad_len)
{
    unsigned char *buf;
    size_t len;

    if (aad_len != EVP_AEAD_TLS1_AAD_LEN)
       return 0;

    /* Save the aad for later use. */
    buf = dat->buf;
    memcpy(buf, aad, aad_len);
    dat->tls_aad_len = aad_len;
    dat->tls_enc_records = 0;

    len = buf[aad_len - 2] << 8 | buf[aad_len - 1];
    /* Correct length for explicit iv. */
    if (len < EVP_GCM_TLS_EXPLICIT_IV_LEN)
        return 0;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;

    /* If decrypting correct for tag too. */
    if (!dat->enc) {
        if (len < EVP_GCM_TLS_TAG_LEN)
            return 0;
        len -= EVP_GCM_TLS_TAG_LEN;
    }
    buf[aad_len - 2] = (unsigned char)(len >> 8);
    buf[aad_len - 1] = (unsigned char)(len & 0xff);
    /* Extra padding: tag appended to record. */
    return EVP_GCM_TLS_TAG_LEN;
}

static int gcm_tls_iv_set_fixed(PROV_GCM_CTX *ctx, unsigned char *iv,
                                size_t len)
{
    /* Special case: -1 length restores whole IV */
    if (len == (size_t)-1) {
        memcpy(ctx->iv, iv, ctx->ivlen);
        ctx->iv_gen = 1;
        ctx->iv_state = IV_STATE_BUFFERED;
        return 1;
    }
    /* Fixed field must be at least 4 bytes and invocation field at least 8 */
    if ((len < EVP_GCM_TLS_FIXED_IV_LEN)
        || (ctx->ivlen - (int)len) < EVP_GCM_TLS_EXPLICIT_IV_LEN)
            return 0;
    if (len > 0)
        memcpy(ctx->iv, iv, len);
    if (ctx->enc
        && rand_bytes_ex(ctx->libctx, ctx->iv + len, ctx->ivlen - len) <= 0)
            return 0;
    ctx->iv_gen = 1;
    ctx->iv_state = IV_STATE_BUFFERED;
    return 1;
}

/* increment counter (64-bit int) by 1 */
static void ctr64_inc(unsigned char *counter)
{
    int n = 8;
    unsigned char c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c > 0)
            return;
    } while (n > 0);
}

/*
 * Handle TLS GCM packet format. This consists of the last portion of the IV
 * followed by the payload and finally the tag. On encrypt generate IV,
 * encrypt payload and write the tag. On verify retrieve IV, decrypt payload
 * and verify tag.
 */
static int gcm_tls_cipher(PROV_GCM_CTX *ctx, unsigned char *out, size_t *padlen,
                          const unsigned char *in, size_t len)
{
    int rv = 0, arg = EVP_GCM_TLS_EXPLICIT_IV_LEN;
    size_t plen = 0;
    unsigned char *tag = NULL;

    if (!ctx->key_set)
        goto err;

    /* Encrypt/decrypt must be performed in place */
    if (out != in || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN))
        goto err;

    /*
     * Check for too many keys as per FIPS 140-2 IG A.5 "Key/IV Pair Uniqueness
     * Requirements from SP 800-38D".  The requirements is for one party to the
     * communication to fail after 2^64 - 1 keys.  We do this on the encrypting
     * side only.
     */
    if (ctx->enc && ++ctx->tls_enc_records == 0) {
        PROVerr(0, EVP_R_TOO_MANY_RECORDS);
        goto err;
    }

    if (ctx->iv_gen == 0)
        goto err;
    /*
     * Set IV from start of buffer or generate IV and write to start of
     * buffer.
     */
    if (ctx->enc) {
        if (!ctx->hw->setiv(ctx, ctx->iv, ctx->ivlen))
            goto err;
        if (arg > ctx->ivlen)
            arg = ctx->ivlen;
        memcpy(out, ctx->iv + ctx->ivlen - arg, arg);
        /*
         * Invocation field will be at least 8 bytes in size and so no need
         * to check wrap around or increment more than last 8 bytes.
         */
        ctr64_inc(ctx->iv + ctx->ivlen - 8);
    } else {
        memcpy(ctx->iv + ctx->ivlen - arg, out, arg);
        if (!ctx->hw->setiv(ctx, ctx->iv, ctx->ivlen))
            goto err;
    }
    ctx->iv_state = IV_STATE_COPIED;

    /* Fix buffer and length to point to payload */
    in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;

    tag = ctx->enc ? out + len : (unsigned char *)in + len;
    if (!ctx->hw->oneshot(ctx, ctx->buf, ctx->tls_aad_len, in, len, out, tag,
                          EVP_GCM_TLS_TAG_LEN)) {
        if (!ctx->enc)
            OPENSSL_cleanse(out, len);
        goto err;
    }
    if (ctx->enc)
        plen =  len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    else
        plen = len;

    rv = 1;
err:
    ctx->iv_state = IV_STATE_FINISHED;
    ctx->tls_aad_len = -1;
    *padlen = plen;
    return rv;
}

#define IMPLEMENT_cipher(alg, lcmode, UCMODE, flags, kbits, blkbits, ivbits)   \
    static OSSL_OP_cipher_get_params_fn alg##_##kbits##_##lcmode##_get_params; \
    static int alg##_##kbits##_##lcmode##_get_params(OSSL_PARAM params[])      \
    {                                                                          \
        return aes_get_params(params, EVP_CIPH_##UCMODE##_MODE, flags,         \
                               kbits, blkbits, ivbits);                        \
    }                                                                          \
    static OSSL_OP_cipher_newctx_fn alg##kbits##gcm_newctx;                    \
    static void *alg##kbits##gcm_newctx(void *provctx)                         \
    {                                                                          \
        return alg##_gcm_newctx(provctx, kbits);                               \
    }                                                                          \
    const OSSL_DISPATCH alg##kbits##gcm_functions[] = {                        \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))gcm_einit },          \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))gcm_dinit },          \
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))gcm_stream_update },        \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))gcm_stream_final },          \
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))gcm_cipher },               \
        { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) alg##kbits##gcm_newctx },  \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) alg##_gcm_freectx },      \
        { OSSL_FUNC_CIPHER_GET_PARAMS,                                         \
            (void (*)(void)) alg##_##kbits##_##lcmode##_get_params },          \
        { OSSL_FUNC_CIPHER_CTX_GET_PARAMS,                                     \
            (void (*)(void))gcm_ctx_get_params },                              \
        { OSSL_FUNC_CIPHER_CTX_SET_PARAMS,                                     \
            (void (*)(void))gcm_ctx_set_params },                              \
        { 0, NULL }                                                            \
    }

static void *aes_gcm_newctx(void *provctx, size_t keybits)
{
    PROV_AES_GCM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        gcm_initctx(provctx, (PROV_GCM_CTX *)ctx, keybits,
                    PROV_AES_HW_gcm(keybits), 8);
    return ctx;
}

static OSSL_OP_cipher_freectx_fn aes_gcm_freectx;
static void aes_gcm_freectx(void *vctx)
{
    PROV_AES_GCM_CTX *ctx = (PROV_AES_GCM_CTX *)vctx;

    gcm_deinitctx((PROV_GCM_CTX *)ctx);
    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

/* aes128gcm_functions */
IMPLEMENT_cipher(aes, gcm, GCM, AEAD_GCM_FLAGS, 128, 8, 96);
/* aes192gcm_functions */
IMPLEMENT_cipher(aes, gcm, GCM, AEAD_GCM_FLAGS, 192, 8, 96);
/* aes256gcm_functions */
IMPLEMENT_cipher(aes, gcm, GCM, AEAD_GCM_FLAGS, 256, 8, 96);

#if !defined(OPENSSL_NO_ARIA) && !defined(FIPS_MODE)

static void *aria_gcm_newctx(void *provctx, size_t keybits)
{
    PROV_ARIA_GCM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        gcm_initctx(provctx, (PROV_GCM_CTX *)ctx, keybits,
                    PROV_ARIA_HW_gcm(keybits), 4);
    return ctx;
}

static OSSL_OP_cipher_freectx_fn aria_gcm_freectx;
static void aria_gcm_freectx(void *vctx)
{
    PROV_ARIA_GCM_CTX *ctx = (PROV_ARIA_GCM_CTX *)vctx;

    gcm_deinitctx((PROV_GCM_CTX *)ctx);
    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

/* aria128gcm_functions */
IMPLEMENT_cipher(aria, gcm, GCM, AEAD_GCM_FLAGS, 128, 8, 96);
/* aria192gcm_functions */
IMPLEMENT_cipher(aria, gcm, GCM, AEAD_GCM_FLAGS, 192, 8, 96);
/* aria256gcm_functions */
IMPLEMENT_cipher(aria, gcm, GCM, AEAD_GCM_FLAGS, 256, 8, 96);

#endif /* !defined(OPENSSL_NO_ARIA) && !defined(FIPS_MODE) */
