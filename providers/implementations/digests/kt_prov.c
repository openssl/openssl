/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include "internal/common.h"
#include "internal/numbers.h" /* includes SIZE_MAX */
#include "internal/sha3.h"
#include "prov/digestcommon.h"
#include "prov/implementations.h"
#include "turboshake_prov.h"

#define KT_FLAGS (PROV_DIGEST_FLAG_XOF | PROV_DIGEST_FLAG_ALGID_ABSENT)

#define KT_CHUNK_SIZE 8192
#define KT_MAX_CUSTOM_STRING 512
#define KT_DOMAIN_FINAL_NODE 0x06
#define KT_DOMAIN_SINGLE_NODE 0x07
#define KT_DOMAIN_INTERMEDIATE_NODE 0x0b

#include "providers/implementations/digests/kt_prov.inc"

typedef struct kt_ctx_st {
    size_t bitlen;
    size_t xoflen;
    size_t cvlen;
    unsigned char *custom;
    size_t custom_len;
    unsigned char first[KT_CHUNK_SIZE];
    size_t first_len;
    KECCAK1600_CTX root;
    KECCAK1600_CTX leaf;
    size_t leaf_len;
    size_t cv_count;
    int tree_started;
    int finalized;
} KT_CTX;

static OSSL_FUNC_digest_init_fn kt_init;
static OSSL_FUNC_digest_update_fn kt_update;
static OSSL_FUNC_digest_final_fn kt_final;
static OSSL_FUNC_digest_squeeze_fn kt_squeeze;
static OSSL_FUNC_digest_freectx_fn kt_freectx;
static OSSL_FUNC_digest_dupctx_fn kt_dupctx;
static OSSL_FUNC_digest_get_ctx_params_fn kt_get_ctx_params;
static OSSL_FUNC_digest_gettable_ctx_params_fn kt_gettable_ctx_params;
static OSSL_FUNC_digest_set_ctx_params_fn kt_set_ctx_params;
static OSSL_FUNC_digest_settable_ctx_params_fn kt_settable_ctx_params;

/*
 * RFC 9861 length_encode() is not SP800-185 right_encode(): in particular,
 * length_encode(0) is 00, not 00 01.
 */
static size_t kt_length_encode(size_t x, unsigned char *out)
{
    size_t n = 0, t = x, i;

    while (t > 0) {
        n++;
        t >>= 8;
    }
    for (i = 0; i < n; i++)
        out[n - i - 1] = (unsigned char)(x >> (8 * i));
    out[n] = (unsigned char)n;
    return n + 1;
}

static int kt_check_cv_count(const KT_CTX *ctx, size_t inlen, int final)
{
    size_t new_cvs = 0, leaf_len = ctx->leaf_len;

    if (!ctx->tree_started) {
        size_t first_space = KT_CHUNK_SIZE - ctx->first_len;

        if (inlen <= first_space)
            return 1;
        inlen -= first_space;
        leaf_len = 0;
    }

    if (inlen > 0) {
        size_t leaf_space = KT_CHUNK_SIZE - leaf_len;

        if (inlen >= leaf_space) {
            size_t full_leaves;

            new_cvs++;
            inlen -= leaf_space;
            full_leaves = inlen / KT_CHUNK_SIZE;
            if (full_leaves > SIZE_MAX - new_cvs)
                goto err;
            new_cvs += full_leaves;
            leaf_len = inlen % KT_CHUNK_SIZE;
        } else {
            leaf_len += inlen;
        }
    }

    if (final && leaf_len > 0) {
        if (new_cvs == SIZE_MAX)
            goto err;
        new_cvs++;
    }

    if (new_cvs > SIZE_MAX - ctx->cv_count)
        goto err;
    return 1;
err:
    ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
    return 0;
}

static int kt_start_tree(KT_CTX *ctx)
{
    static const unsigned char kt_tree_marker[8] = {
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    if (ctx->tree_started)
        return 1;
    if (!ossl_turboshake_init_keccak(&ctx->root, ctx->bitlen,
            KT_DOMAIN_FINAL_NODE, ctx->xoflen)
        || !ossl_sha3_absorb(&ctx->root, ctx->first, ctx->first_len)
        || !ossl_sha3_absorb(&ctx->root, kt_tree_marker,
            sizeof(kt_tree_marker))
        || !ossl_turboshake_init_keccak(&ctx->leaf, ctx->bitlen,
            KT_DOMAIN_INTERMEDIATE_NODE, ctx->cvlen))
        return 0;
    ctx->tree_started = 1;
    return 1;
}

static int kt_finish_leaf(KT_CTX *ctx)
{
    unsigned char cv[64];

    if (ctx->cv_count == SIZE_MAX) {
        ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
        return 0;
    }
    if (!ossl_sha3_final(&ctx->leaf, cv, ctx->cvlen)
        || !ossl_sha3_absorb(&ctx->root, cv, ctx->cvlen))
        return 0;
    OPENSSL_cleanse(cv, sizeof(cv));
    ctx->cv_count++;
    ctx->leaf_len = 0;
    return ossl_turboshake_init_keccak(&ctx->leaf, ctx->bitlen,
        KT_DOMAIN_INTERMEDIATE_NODE, ctx->cvlen);
}

static int kt_absorb_s(KT_CTX *ctx, const unsigned char *in, size_t inlen)
{
    size_t len;

    if (inlen == 0)
        return 1;
    if (ctx->finalized)
        return 0;
    if (!kt_check_cv_count(ctx, inlen, 0))
        return 0;

    if (!ctx->tree_started) {
        len = KT_CHUNK_SIZE - ctx->first_len;
        if (len > inlen)
            len = inlen;
        memcpy(ctx->first + ctx->first_len, in, len);
        ctx->first_len += len;
        in += len;
        inlen -= len;
        if (inlen == 0)
            return 1;
        if (!kt_start_tree(ctx))
            return 0;
    }

    while (inlen > 0) {
        len = KT_CHUNK_SIZE - ctx->leaf_len;
        if (len > inlen)
            len = inlen;
        if (!ossl_sha3_absorb(&ctx->leaf, in, len))
            return 0;
        ctx->leaf_len += len;
        in += len;
        inlen -= len;
        if (ctx->leaf_len == KT_CHUNK_SIZE && !kt_finish_leaf(ctx))
            return 0;
    }
    return 1;
}

static int kt_final_absorb(KT_CTX *ctx)
{
    unsigned char enc[sizeof(size_t) + 1];
    size_t enclen, suffix_len;
    static const unsigned char kt_final_suffix[2] = { 0xff, 0xff };

    if (ctx->finalized)
        return 1;

    enclen = kt_length_encode(ctx->custom_len, enc);
    if (ctx->custom_len > SIZE_MAX - enclen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
        return 0;
    }
    suffix_len = ctx->custom_len + enclen;
    if (!kt_check_cv_count(ctx, suffix_len, 1))
        return 0;
    if (!kt_absorb_s(ctx, ctx->custom, ctx->custom_len)
        || !kt_absorb_s(ctx, enc, enclen))
        return 0;

    if (!ctx->tree_started) {
        if (!ossl_turboshake_init_keccak(&ctx->root, ctx->bitlen,
                KT_DOMAIN_SINGLE_NODE, ctx->xoflen)
            || !ossl_sha3_absorb(&ctx->root, ctx->first, ctx->first_len))
            return 0;
    } else {
        if (ctx->leaf_len > 0 && !kt_finish_leaf(ctx))
            return 0;
        enclen = kt_length_encode(ctx->cv_count, enc);
        if (!ossl_sha3_absorb(&ctx->root, enc, enclen)
            || !ossl_sha3_absorb(&ctx->root, kt_final_suffix,
                sizeof(kt_final_suffix)))
            return 0;
    }
    ctx->finalized = 1;
    return 1;
}

static void *kt_newctx(void *provctx, size_t bitlen)
{
    KT_CTX *ctx;

    DIGEST_PROV_CHECK(provctx, SHA3_256);
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    ctx->bitlen = bitlen;
    ctx->cvlen = bitlen == 128 ? 32 : 64;
    ctx->xoflen = ctx->cvlen;
    return ctx;
}

static int kt_init(void *vctx, const OSSL_PARAM params[])
{
    KT_CTX *ctx = vctx;

    if (ossl_unlikely(!ossl_prov_is_running()))
        return 0;
    OPENSSL_clear_free(ctx->custom, ctx->custom_len);
    ctx->custom = NULL;
    ctx->custom_len = 0;
    ctx->xoflen = ctx->cvlen;
    ctx->first_len = 0;
    ctx->leaf_len = 0;
    ctx->cv_count = 0;
    ctx->tree_started = 0;
    ctx->finalized = 0;
    memset(&ctx->root, 0, sizeof(ctx->root));
    memset(&ctx->leaf, 0, sizeof(ctx->leaf));
    return kt_set_ctx_params(vctx, params);
}

static int kt_update(void *vctx, const unsigned char *in, size_t inlen)
{
    KT_CTX *ctx = vctx;

    return kt_absorb_s(ctx, in, inlen);
}

static int kt_final(void *vctx, unsigned char *out, size_t *outl,
    size_t outsz)
{
    KT_CTX *ctx = vctx;

    if (ossl_unlikely(!ossl_prov_is_running()))
        return 0;
    if (outsz < ctx->xoflen)
        return 0;
    if (ctx->xoflen > 0
        && (!kt_final_absorb(ctx)
            || !ossl_sha3_final(&ctx->root, out, ctx->xoflen)))
        return 0;
    if (outl != NULL)
        *outl = ctx->xoflen;
    return 1;
}

static int kt_squeeze(void *vctx, unsigned char *out, size_t *outl,
    size_t outsz)
{
    KT_CTX *ctx = vctx;

    if (ossl_unlikely(!ossl_prov_is_running()))
        return 0;
    if (outsz > 0
        && (!kt_final_absorb(ctx)
            || !ossl_sha3_squeeze(&ctx->root, out, outsz)))
        return 0;
    if (outl != NULL)
        *outl = outsz;
    return 1;
}

static void kt_freectx(void *vctx)
{
    KT_CTX *ctx = vctx;

    if (ctx != NULL)
        OPENSSL_clear_free(ctx->custom, ctx->custom_len);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *kt_dupctx(void *vctx)
{
    KT_CTX *in = vctx;
    KT_CTX *ret = ossl_prov_is_running() ? OPENSSL_malloc(sizeof(*ret)) : NULL;

    if (ret == NULL)
        return NULL;
    *ret = *in;
    ret->custom = NULL;
    if (in->custom_len > 0) {
        ret->custom = OPENSSL_memdup(in->custom, in->custom_len);
        if (ret->custom == NULL) {
            OPENSSL_clear_free(ret, sizeof(*ret));
            return NULL;
        }
    }
    return ret;
}

static const OSSL_PARAM *kt_gettable_ctx_params(ossl_unused void *ctx,
    ossl_unused void *provctx)
{
    return kt_get_ctx_params_list;
}

static int kt_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    KT_CTX *ctx = vctx;
    struct kt_get_ctx_params_st p;

    if (ctx == NULL || !kt_get_ctx_params_decoder(params, &p))
        return 0;

    if (p.size != NULL && !OSSL_PARAM_set_size_t(p.size, ctx->xoflen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }
    if (p.xoflen != NULL && !OSSL_PARAM_set_size_t(p.xoflen, ctx->xoflen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }
    return 1;
}

static const OSSL_PARAM *kt_settable_ctx_params(ossl_unused void *ctx,
    ossl_unused void *provctx)
{
    return kt_set_ctx_params_list;
}

static int kt_set_custom(KT_CTX *ctx, const OSSL_PARAM *p)
{
    const unsigned char *data = p->data;
    unsigned char *custom = NULL;
    size_t custom_len;

    if (p->data_type != OSSL_PARAM_OCTET_STRING)
        return 0;
    custom_len = p->data_size;

    /* Match the existing CSHAKE provider limit for customization strings. */
    if (custom_len > KT_MAX_CUSTOM_STRING) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CUSTOM_LENGTH);
        return 0;
    }

    if (custom_len > 0) {
        if (data == NULL)
            return 0;
        custom = OPENSSL_memdup(data, custom_len);
        if (custom == NULL)
            return 0;
    }
    OPENSSL_clear_free(ctx->custom, ctx->custom_len);
    ctx->custom = custom;
    ctx->custom_len = custom_len;
    return 1;
}

static int kt_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    KT_CTX *ctx = vctx;
    struct kt_set_ctx_params_st p;
    int has_change = 0;

    if (ctx == NULL || !kt_set_ctx_params_decoder(params, &p))
        return 0;

    has_change = p.xoflen != NULL || p.custom != NULL;
    if (has_change && ctx->finalized)
        return 0;

    if (p.xoflen != NULL
        && !OSSL_PARAM_get_size_t(p.xoflen, &ctx->xoflen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }

    if (p.custom != NULL && !kt_set_custom(ctx, p.custom))
        return 0;
    return 1;
}

#define IMPLEMENT_KT(bitlen)                                                    \
    static OSSL_FUNC_digest_newctx_fn kt_##bitlen##_newctx;                     \
    static void *kt_##bitlen##_newctx(void *provctx)                            \
    {                                                                           \
        return kt_newctx(provctx, bitlen);                                      \
    }                                                                           \
    PROV_FUNC_DIGEST_GET_PARAM(kt_##bitlen, SHA3_BLOCKSIZE(bitlen),             \
        bitlen == 128 ? 32 : 64, KT_FLAGS)                                      \
    const OSSL_DISPATCH ossl_kt_##bitlen##_functions[] = {                      \
        { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))kt_##bitlen##_newctx },      \
        { OSSL_FUNC_DIGEST_INIT, (void (*)(void))kt_init },                     \
        { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))kt_update },                 \
        { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))kt_final },                   \
        { OSSL_FUNC_DIGEST_SQUEEZE, (void (*)(void))kt_squeeze },               \
        { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))kt_freectx },               \
        { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))kt_dupctx },                 \
        { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void))kt_set_ctx_params }, \
        { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,                                 \
            (void (*)(void))kt_settable_ctx_params },                           \
        { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (void (*)(void))kt_get_ctx_params }, \
        { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,                                 \
            (void (*)(void))kt_gettable_ctx_params },                           \
        PROV_DISPATCH_FUNC_DIGEST_GET_PARAMS(kt_##bitlen),                      \
        PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_END

/* ossl_kt_128_functions */
IMPLEMENT_KT(128)
/* ossl_kt_256_functions */
IMPLEMENT_KT(256)
