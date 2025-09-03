/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * NOTE: By default CSHAKE sets secure xof lengths (OSSL_DIGEST_PARAM_XOFLEN)
 * that are used by EVP_DigestFinal_ex(). This differs from SHAKE where the
 * xof length MUST be set (since the initial implementation shipped with BAD
 * defaults - and the only safe way to fix it was to make the user set the value)
 */

/*
 * Length encoding will be a 1 byte size + length in bits (3 bytes max)
 * This gives a range of 0..0XFFFFFF bits = 2097151 bytes).
 */
#define CSHAKE_MAX_ENCODED_HEADER_LEN (1 + 3)

/*
 * Restrict the maximum length of the custom strings N & S.
 * This must not exceed 64 bits = 8k bytes.
 */
#define CSHAKE_MAX_STRING 512

/* Maximum size of both the encoded strings (N and S) */
#define CSHAKE_MAX_ENCODED_STRING (CSHAKE_MAX_STRING + CSHAKE_MAX_ENCODED_HEADER_LEN)

typedef struct cshake_ctx_st {
    KECCAK1600_CTX keccak_ctx;
    uint8_t n[CSHAKE_MAX_ENCODED_STRING];
    uint8_t s[CSHAKE_MAX_ENCODED_STRING];
    size_t nlen;
    size_t slen;
} CSHAKE_CTX;

static OSSL_FUNC_digest_freectx_fn cshake_freectx;
static OSSL_FUNC_digest_dupctx_fn cshake_dupctx;
static OSSL_FUNC_digest_copyctx_fn cshake_copyctx;
static OSSL_FUNC_digest_init_fn cshake_init;
static OSSL_FUNC_digest_update_fn cshake_update;
static OSSL_FUNC_digest_set_ctx_params_fn cshake_set_ctx_params;
static OSSL_FUNC_digest_settable_ctx_params_fn cshake_settable_ctx_params;

static int cshake_set_encode_string(const char *in,
                                    uint8_t *out, size_t outmax, size_t *outlen)
{
    size_t inlen;

    if (*outlen != 0)
        OPENSSL_cleanse(out, outmax);
    *outlen = 0;
    if (in == NULL)
        return 1;

    inlen = strlen(in);
    /*
     * Don't encode an empty string here - this is done manually later only when
     * one of the strings is not empty. If both are empty then we don't want it
     * to encode at all.
     */
    if (inlen == 0)
        return 1;
    if (inlen >= CSHAKE_MAX_STRING)
        return 0;
    return ossl_sp800_185_encode_string(out, outmax, outlen,
                                        (const unsigned char*)in, inlen);
}

/*
 * See the description above the definition of SHAKE_PADDING
 * This basically selects either SHAKE or KECCAK[c] padding.
 */
static void cshake_set_shake_mode(CSHAKE_CTX *ctx, int shake)
{
    KECCAK1600_CTX *kctx = &ctx->keccak_ctx;

    if (shake)
        kctx->pad = SHAKE_PADDING;
    else
        kctx->pad = KMAC_PADDING;
}

static void *cshake_newctx(void *provctx, size_t bitlen)
{
     CSHAKE_CTX *ctx;

    if (ossl_unlikely(!ossl_prov_is_running()))
        return NULL;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        ossl_keccak_init(&ctx->keccak_ctx, SHAKE_PADDING, bitlen, 2 * bitlen);
        ctx->keccak_ctx.meth = shake_generic_md;
    }
    return ctx;
}

static void cshake_freectx(void *vctx)
{
    CSHAKE_CTX *ctx = (CSHAKE_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void cshake_copyctx(void *voutctx, void *vinctx)
{
    CSHAKE_CTX *outctx = (CSHAKE_CTX *)voutctx;
    CSHAKE_CTX *inctx = (CSHAKE_CTX *)vinctx;

    *outctx = *inctx;
}

static void *cshake_dupctx(void *ctx)
{
    CSHAKE_CTX *in = (CSHAKE_CTX *)ctx;
    CSHAKE_CTX *ret = ossl_prov_is_running() ? OPENSSL_malloc(sizeof(*ret))
                                             : NULL;
    if (ret != NULL)
        *ret = *in;
    return ret;
}

static int cshake_init(void *vctx, const OSSL_PARAM params[])
{
    CSHAKE_CTX *ctx = (CSHAKE_CTX *)vctx;

    if (ossl_unlikely(!ossl_prov_is_running()))
        return 0;
    /* The newctx() handles most of the ctx fixed setup. */
    ossl_sha3_reset(&ctx->keccak_ctx);
    cshake_set_shake_mode(ctx, 1);
    cshake_set_encode_string(NULL, ctx->n, sizeof(ctx->n), &ctx->nlen);
    cshake_set_encode_string(NULL, ctx->s, sizeof(ctx->s), &ctx->slen);
    return cshake_set_ctx_params(vctx, params);
}

static const OSSL_PARAM *cshake_settable_ctx_params(ossl_unused void *ctx,
                                                    ossl_unused void *provctx)
{
    return cshake_set_ctx_params_list;
}

static int cshake_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct cshake_set_ctx_params_st p;
    CSHAKE_CTX *ctx = (CSHAKE_CTX *)vctx;
    KECCAK1600_CTX *kctx;

    if (ctx == NULL || !cshake_set_ctx_params_decoder(params, &p))
        return 0;

    kctx = &(ctx->keccak_ctx);
    if (ossl_unlikely(p.xoflen != NULL
            && !OSSL_PARAM_get_size_t(p.xoflen, &kctx->md_size))) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }
    if (p.N != NULL) {
        if (p.N->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        if (!cshake_set_encode_string(p.N->data, ctx->n, sizeof(ctx->n), &ctx->nlen))
            return 0;
    }
    if (p.S != NULL) {
        if (p.S->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        if (!cshake_set_encode_string(p.S->data, ctx->s, sizeof(ctx->s), &ctx->slen))
            return 0;
    }
    return 1;
}

/* Fills the rest of the keccak buffer with zeros and then absorb the full block. */
static void keccak_absorb_with_zero_pad(void *vctx)
{
    KECCAK1600_CTX *ctx = vctx;
    const size_t bsz = ctx->block_size;
    size_t num;

    if (ossl_likely((num = ctx->bufsz) != 0)) {
        memset(ctx->buf + num, 0, bsz - num);
        ctx->meth.absorb(ctx, ctx->buf, bsz);
        ctx->bufsz = 0;
    }
}

/*
 * bytepad(encode_string(N) || encode_string(S), w)
 * See SP800-185 Section 2.3.3 Padding.
 *
 * Rather than build an array and do a single keccak operation, we use the
 * internal keccak buffer to simplify the process.
 * Note that if the strings are large enough to fill the buffer, it will handle
 * this internally by absorbing full blocks. The zero padding is also simple
 * as we just fill the buffer with zeros to make it a multiple of the blocksize.
 */
static void cshake_absorb_bytepad_strings(CSHAKE_CTX *ctx)
{
    KECCAK1600_CTX *kctx = &(ctx->keccak_ctx);
    const uint8_t empty_encodestring[2] = { 0x01, 0x00 };
    uint8_t bytepad_header[2] = { 0x01, 0x00 };
    bytepad_header[1] = (uint8_t)kctx->block_size; /* w = 168 or 136 */
    const uint8_t *n = ctx->n, *s = ctx->s;
    size_t nlen = ctx->nlen, slen = ctx->slen;

    /* Empty strings are still encoded */
    if (ctx->nlen == 0) {
        n = empty_encodestring;
        nlen = 2;
    }
    if (ctx->slen == 0) {
        s = empty_encodestring;
        slen = 2;
    }
    /* left encoded(w) */
    keccak_update(kctx, bytepad_header, sizeof(bytepad_header));
    /* X = encodestring(n) || encodestring(s) */
    keccak_update(kctx, n, nlen);
    keccak_update(kctx, s, slen);
    /* Pad with zeros */
    keccak_absorb_with_zero_pad(kctx);
}

static int cshake_update(void *vctx, const unsigned char *in, size_t inlen)
{
    CSHAKE_CTX *ctx = (CSHAKE_CTX *)vctx;
    KECCAK1600_CTX *kctx = &(ctx->keccak_ctx);

    /*
     * We have to defer choosing the mode (SHAKE or KECCAK)
     * until the first update since the strings can be set at any time
     * before this point.
     * The padding value that is set is only needed when either the
     * final or squeeze is used.
     */
    if (kctx->xof_state == XOF_STATE_INIT) {
        if (ctx->nlen != 0 || ctx->slen != 0) {
            cshake_set_shake_mode(ctx, 0);
            cshake_absorb_bytepad_strings(ctx);
        } else {
            /* Use SHAKE if N and S are both empty strings */
            cshake_set_shake_mode(ctx, 1);
        }
    }
    /* Absorb the actual message */
    return keccak_update(kctx, in, inlen);
}

#define IMPLEMENT_CSHAKE_functions(bitlen)                                     \
static OSSL_FUNC_digest_newctx_fn cshake_##bitlen##_newctx;                    \
static void *cshake_##bitlen##_newctx(void *provctx)                           \
{                                                                              \
    return cshake_newctx(provctx, bitlen);                                     \
}                                                                              \
PROV_FUNC_DIGEST_GET_PARAM(cshake_##bitlen, SHA3_BLOCKSIZE(bitlen),            \
                           KMAC_MDSIZE(bitlen), SHAKE_FLAGS)                   \
const OSSL_DISPATCH ossl_cshake_##bitlen##_functions[] = {                     \
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))cshake_##bitlen##_newctx },     \
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))cshake_init },                    \
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))cshake_update },                \
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))keccak_final },                  \
    { OSSL_FUNC_DIGEST_SQUEEZE, (void (*)(void))shake_squeeze },               \
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))cshake_freectx },              \
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))cshake_dupctx },                \
    { OSSL_FUNC_DIGEST_COPYCTX, (void (*)(void))cshake_copyctx },              \
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void))cshake_set_ctx_params },\
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,                                    \
     (void (*)(void))cshake_settable_ctx_params },                             \
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (void (*)(void))shake_get_ctx_params }, \
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,                                    \
     (void (*)(void))shake_gettable_ctx_params },                              \
    PROV_DISPATCH_FUNC_DIGEST_GET_PARAMS(cshake_##bitlen),                     \
    PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_END

/* ossl_cshake_128_functions */
IMPLEMENT_CSHAKE_functions(128)
/* ossl_cshake_256_functions */
IMPLEMENT_CSHAKE_functions(256)
