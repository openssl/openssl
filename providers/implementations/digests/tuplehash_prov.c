/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h" /* including crypto/sha.h requires this */

/*
 * NOTES:
 * (1) The code is a bit complex because it needs to defer operations since it
 *  needs to fetch "CSHAKE-KECCAK" internally and this can't be done in the init()
 *  because it relies on parameters such as 'properties' and 'customization',
 *  which are set up later via a call to set_ctx_params().
 * (2) update() being passed an empty buffer is a valid input tuple. (Internally
 * this is encoded as 0x01, 0x00).
 * (3) If the update is not called then it calls update with an empty tuple in
 * either the final() or squeeze().
 * (4) This algorithm uses "CSHAKE-KECCAK" which by default sets secure xof lengths
 * (OSSL_DIGEST_PARAM_XOFLEN) that are used by EVP_DigestFinal_ex(). This differs
 * from SHAKE where the xof length MUST be set (since the initial implementation
 * shipped with BAD defaults - and the only safe way to fix it was to make the
 * user set the value)
 * (5) This code uses CSHAKE-KECCAK rather than CSHAKE as the algorithm to fetch,
 * There is not much difference in code flow other than this requires
 * bytepad_encode_custom() to be called, and has one less fetch (since CSHAKE
 * fetches CSHAKE-KECCAK also).
 */
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>
#include "crypto/sha.h"
#include "prov/provider_ctx.h"
#include "prov/digestcommon.h"
#include "prov/implementations.h"
#include "internal/common.h"
#include "internal/sha3.h"
#include "providers/implementations/digests/tuplehash_prov.inc"

/*
 * Length encoding will be a 1 byte size + length in bits (3 bytes max)
 * This gives a range of 0..0XFFFFFF bits = 2097151 bytes).
 */
#define TUPLEHASH_MAX_ENCODED_CUSTOM_HEADER_LEN (1 + 3)

/*
 * Restrict the tuple input size also to avoid overflow of size_t on
 * 32 bit systems
 */
#define TUPLEHASH_MAX_ENCODED_INPUT_HEADER_LEN (1 + 3)

/*
 * Restrict the maximum length of the custom string S.
 * This must not exceed 64 bits = 8k bytes.
 */
#define TUPLEHASH_MAX_CUSTOM_STRING 512

/* Maximum size of the encoded string S */
#define TUPLEHASH_MAX_ENCODED_CUSTOM_STRING \
    (TUPLEHASH_MAX_CUSTOM_STRING + TUPLEHASH_MAX_ENCODED_CUSTOM_HEADER_LEN)

#define TUPLEHASH_FLAGS (PROV_DIGEST_FLAG_XOF | PROV_DIGEST_FLAG_ALGID_ABSENT)

/* Fixed value of encode_string("TupleHash") */
static const unsigned char tuplehash_encoded_string[] = {
    0x01, 0x48, 0x54, 0x75, 0x70, 0x6C, 0x65, 0x48, 0x61, 0x73, 0x68
};

#define SMALLEST_BLK_SIZE CSHAKE_KECCAK_MDSIZE(125)
#define TUPLEHASH_MAX_BYTPEPAD_T            \
    ((TUPLEHASH_MAX_ENCODED_CUSTOM_STRING   \
         + sizeof(tuplehash_encoded_string) \
         + (SMALLEST_BLK_SIZE - 1))         \
        / SMALLEST_BLK_SIZE)                \
        * SMALLEST_BLK_SIZE

typedef struct tuplehash_ctx_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    EVP_MD_CTX *mdctx;
    char custom[TUPLEHASH_MAX_CUSTOM_STRING];
    size_t customlen;
    size_t xoflen;
    size_t bitlen;
    int xof_mode; /* If xof_mode = 1 then we use right_encode(0) */
    int finalized; /* set to 1 when final or squeeze is run */
    int digest_fetched; /* When this is 1 the mdctx contains a fetched digest */
} TUPLEHASH_CTX;

static OSSL_FUNC_digest_freectx_fn tuplehash_freectx;
static OSSL_FUNC_digest_dupctx_fn tuplehash_dupctx;
static OSSL_FUNC_digest_init_fn tuplehash_init;
static OSSL_FUNC_digest_update_fn tuplehash_update;
static OSSL_FUNC_digest_final_fn tuplehash_final;
static OSSL_FUNC_digest_squeeze_fn tuplehash_squeeze;
static OSSL_FUNC_digest_set_ctx_params_fn tuplehash_set_ctx_params;
static OSSL_FUNC_digest_settable_ctx_params_fn tuplehash_settable_ctx_params;
static OSSL_FUNC_digest_get_ctx_params_fn tuplehash_get_ctx_params;
static OSSL_FUNC_digest_gettable_ctx_params_fn tuplehash_gettable_ctx_params;

/* Returns out = bytepad(encode_string("TupleHash") || encode_string(s), w) */
static int bytepad_encode_custom(uint8_t *out, size_t out_maxlen,
    size_t *out_len, const uint8_t *custom, size_t custom_len, size_t w)
{
    uint8_t enc[TUPLEHASH_MAX_ENCODED_CUSTOM_STRING];
    size_t enc_len;

    return ossl_sp800_185_encode_string(enc, sizeof(enc), &enc_len, custom, custom_len)
        && ossl_sp800_185_bytepad(out, out_maxlen, out_len,
            tuplehash_encoded_string, sizeof(tuplehash_encoded_string), enc, enc_len, w);
}

/*
 * The digest setting is deferred since propq and xoflen are not set until
 * set_ctx_params() has been called.
 * So this call is run during the first update(), final() or squeeze().
 * At this point Keccak(bytepad(encode_string(“TupleHash”) || encode_string(S), w))
 * can be calculated..
 */
static int init_hash(TUPLEHASH_CTX *ctx)
{
    int ret = 1;

    if (!ctx->digest_fetched) {
        OSSL_PARAM params[5], *p = params;
        const char *name = (ctx->bitlen == 128 ? "CSHAKE-KECCAK-128" : "CSHAKE-KECCAK-256");
        EVP_MD *md = EVP_MD_fetch(ctx->libctx, name, ctx->propq);
        uint8_t out[TUPLEHASH_MAX_BYTPEPAD_T];
        size_t out_len;

        if (md == NULL)
            return 0;
        *p++ = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &ctx->xoflen);
        *p = OSSL_PARAM_construct_end();
        ret = EVP_DigestInit_ex2(ctx->mdctx, md, params);
        EVP_MD_free(md);
        if (ret) {
            ctx->digest_fetched = 1;
            ret = bytepad_encode_custom(out, sizeof(out), &out_len,
                      (const uint8_t *)ctx->custom, ctx->customlen,
                      EVP_MD_get_block_size(md))
                && EVP_DigestUpdate(ctx->mdctx, out, out_len);
        }
    }
    return ret;
}

/*
 * Set the xof length, note that if the digest has not been fetched yet then
 * it is just set into a variable and deferred to later.
 */
static int tuplehash_set_xoflen(TUPLEHASH_CTX *ctx, size_t xoflen)
{
    ctx->xoflen = xoflen;
    if (ctx->digest_fetched == 1) {
        OSSL_PARAM params[2];

        params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &xoflen);
        params[1] = OSSL_PARAM_construct_end();
        return EVP_MD_CTX_set_params(ctx->mdctx, params);
    }
    return 1;
}

static void *tuplehash_newctx(void *provctx, size_t bitlen)
{
    TUPLEHASH_CTX *ctx;

    if (ossl_unlikely(!ossl_prov_is_running()))
        return NULL;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        ctx->mdctx = EVP_MD_CTX_new();
        if (ctx->mdctx == NULL) {
            OPENSSL_free(ctx);
            return NULL;
        }
        ctx->bitlen = bitlen;
        ctx->libctx = PROV_LIBCTX_OF(provctx);
    }
    return ctx;
}

static void tuplehash_freectx(void *vctx)
{
    TUPLEHASH_CTX *ctx = (TUPLEHASH_CTX *)vctx;

    EVP_MD_CTX_free(ctx->mdctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *tuplehash_dupctx(void *ctx)
{
    TUPLEHASH_CTX *src = (TUPLEHASH_CTX *)ctx;
    TUPLEHASH_CTX *ret = ossl_prov_is_running() ? OPENSSL_malloc(sizeof(*ret))
                                                : NULL;

    if (ret != NULL) {
        *ret = *src;
        ret->mdctx = NULL;
        ret->propq = NULL;

        if (src->mdctx != NULL) {
            ret->mdctx = EVP_MD_CTX_new();
            if (ret->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(ret->mdctx, src->mdctx))
                goto err;
        }
        if (src->propq != NULL) {
            ret->propq = OPENSSL_strdup(src->propq);
            if (ret->propq == NULL)
                goto err;
        }
    }
    return ret;
err:
    tuplehash_freectx(ret);
    return NULL;
}

static int tuplehash_init(void *vctx, const OSSL_PARAM params[])
{
    TUPLEHASH_CTX *ctx = (TUPLEHASH_CTX *)vctx;

    if (ossl_unlikely(!ossl_prov_is_running()))
        return 0;

    ctx->digest_fetched = 0;
    ctx->finalized = 0;
    ctx->xoflen = (ctx->bitlen == 128) ? 32 : 64; /* Set default values here */
    ctx->customlen = 0;
    return tuplehash_set_ctx_params(vctx, params);
}

static const OSSL_PARAM *tuplehash_settable_ctx_params(ossl_unused void *ctx,
    ossl_unused void *provctx)
{
    return tuplehash_set_ctx_params_list;
}

static int set_property_query(TUPLEHASH_CTX *ctx, const char *propq)
{
    OPENSSL_free(ctx->propq);
    ctx->propq = NULL;
    if (propq != NULL) {
        ctx->propq = OPENSSL_strdup(propq);
        if (ctx->propq == NULL)
            return 0;
    }
    return 1;
}

static int tuplehash_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    TUPLEHASH_CTX *ctx = (TUPLEHASH_CTX *)vctx;
    struct tuplehash_set_ctx_params_st p;

    if (ctx == NULL || !tuplehash_set_ctx_params_decoder(params, &p))
        return 0;

    if (ossl_unlikely(p.xoflen != NULL)) {
        size_t xoflen;

        if (!OSSL_PARAM_get_size_t(p.xoflen, &xoflen)
            || !tuplehash_set_xoflen(ctx, xoflen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }
    if (p.custom != NULL) {
        char *str = ctx->custom;

        if (!OSSL_PARAM_get_utf8_string(p.custom, &str, sizeof(ctx->custom)))
            return 0;
        ctx->customlen = strlen(str);
    }
    if (p.xof != NULL && !OSSL_PARAM_get_int(p.xof, &ctx->xof_mode))
        return 0;
    if (p.propq != NULL) {
        if (p.propq->data_type != OSSL_PARAM_UTF8_STRING
            || !set_property_query(ctx, p.propq->data))
            return 0;
    }
    return 1;
}

/*
 * Each update uses a tuple as input - The tuple needs to be converted to
 * an encoded string.
 * Which does the step. z = z || encode_string(X[i]).
 * Note: The digest is not set up until the first call to the update() because
 * cshake requires the custom 'S' value to be set first..
 *
 * i.e CSHAKE = Keccak(bytepad(encoded("TupleHash") || encoded(S), blocksz)) || z || 00, L)
 */
static int tuplehash_update(void *vctx, const unsigned char *in, size_t inlen)
{
    TUPLEHASH_CTX *ctx = (TUPLEHASH_CTX *)vctx;
    uint8_t header[TUPLEHASH_MAX_ENCODED_INPUT_HEADER_LEN];
    size_t headerlen;

    return init_hash(ctx)
        && ossl_sp800_185_encode_string_header(header, sizeof(header),
            &headerlen, inlen)
        && EVP_DigestUpdate(ctx->mdctx, header, headerlen)
        && EVP_DigestUpdate(ctx->mdctx, in, inlen);
}

static int on_final(TUPLEHASH_CTX *ctx)
{
    if (!ctx->finalized) {
        unsigned char enc_outlen[TUPLEHASH_MAX_ENCODED_CUSTOM_HEADER_LEN];
        size_t len;
        /*
         * In some cases where we don't know the output the value of L
         * it may be set to zero.
         */
        size_t lbits = (ctx->xof_mode ? 0 : (ctx->xoflen * 8));

        ctx->finalized = 1;
        /* If there was no update, run the update with an empty tuple */
        if (!ctx->digest_fetched
            && !tuplehash_update(ctx, NULL, 0))
            return 0;
        /*
         * After the Tuples we need to concatenate an encoding of L
         * i.e. newX = z || right_encode(L).
         */
        return ossl_sp800_185_right_encode(enc_outlen, sizeof(enc_outlen), &len, lbits)
            && EVP_DigestUpdate(ctx->mdctx, enc_outlen, len);
    }
    return 1;
}

static int tuplehash_final(void *vctx, uint8_t *out, size_t *outl, size_t outsz)
{
    TUPLEHASH_CTX *ctx = (TUPLEHASH_CTX *)vctx;
    unsigned int der = (unsigned int)(*outl);

    if (ossl_unlikely(!ossl_prov_is_running()))
        return 0;

    if (outsz > 0) {
        if (!on_final(ctx)
            || !EVP_DigestFinal_ex(ctx->mdctx, out, &der))
            return 0;
    }
    if (outl != NULL)
        *outl = der;
    return 1;
}

static int tuplehash_squeeze(void *vctx, uint8_t *out, size_t *outl, size_t outsz)
{
    TUPLEHASH_CTX *ctx = (TUPLEHASH_CTX *)vctx;
    int ret = 1;

    if (ossl_unlikely(!ossl_prov_is_running()))
        return 0;

    if (outsz > 0) {
        ret = on_final(ctx)
            && EVP_DigestSqueeze(ctx->mdctx, out, outsz);
    }
    if (ret && outl != NULL)
        *outl = outsz;
    return ret;
}

static const OSSL_PARAM *tuplehash_gettable_ctx_params(ossl_unused void *ctx,
    ossl_unused void *provctx)
{
    return tuplehash_get_ctx_params_list;
}

static int tuplehash_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    TUPLEHASH_CTX *ctx = (TUPLEHASH_CTX *)vctx;
    struct tuplehash_get_ctx_params_st p;

    if (ctx == NULL || !tuplehash_get_ctx_params_decoder(params, &p))
        return 0;

    /* Size is an alias of xoflen */
    if (p.xoflen != NULL || p.size != NULL) {
        size_t xoflen = ctx->xoflen;

        if (ctx->digest_fetched)
            xoflen = EVP_MD_CTX_get_size_ex(ctx->mdctx);

        if (p.size != NULL && !OSSL_PARAM_set_size_t(p.size, xoflen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (p.xoflen != NULL && !OSSL_PARAM_set_size_t(p.xoflen, xoflen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }
    return 1;
}

#define IMPLEMENT_TUPLEHASH_functions(bitlen)                                          \
    static OSSL_FUNC_digest_newctx_fn tuplehash_##bitlen##_newctx;                     \
    static void *tuplehash_##bitlen##_newctx(void *provctx)                            \
    {                                                                                  \
        return tuplehash_newctx(provctx, bitlen);                                      \
    }                                                                                  \
    PROV_FUNC_DIGEST_GET_PARAM(tuplehash_##bitlen, SHA3_BLOCKSIZE(bitlen),             \
        CSHAKE_KECCAK_MDSIZE(bitlen), TUPLEHASH_FLAGS)                                 \
    const OSSL_DISPATCH ossl_tuplehash_##bitlen##_functions[] = {                      \
        { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))tuplehash_##bitlen##_newctx },      \
        { OSSL_FUNC_DIGEST_INIT, (void (*)(void))tuplehash_init },                     \
        { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))tuplehash_update },                 \
        { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))tuplehash_final },                   \
        { OSSL_FUNC_DIGEST_SQUEEZE, (void (*)(void))tuplehash_squeeze },               \
        { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))tuplehash_freectx },               \
        { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))tuplehash_dupctx },                 \
        { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void))tuplehash_set_ctx_params }, \
        { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,                                        \
            (void (*)(void))tuplehash_settable_ctx_params },                           \
        { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (void (*)(void))tuplehash_get_ctx_params }, \
        { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,                                        \
            (void (*)(void))tuplehash_gettable_ctx_params },                           \
        PROV_DISPATCH_FUNC_DIGEST_GET_PARAMS(tuplehash_##bitlen),                      \
        PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_END

/* ossl_tuplehash_128_functions */
IMPLEMENT_TUPLEHASH_functions(128)
    /* ossl_tuplehash_256_functions */
    IMPLEMENT_TUPLEHASH_functions(256)
