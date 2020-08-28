/*
 * Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <limits.h>
#include <string.h>
#include <crypto/evp.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <internal/worker.h>
#include <internal/numbers.h>
#include <prov/implementations.h>
#include <prov/provider_ctx.h>
#include <prov/providercommonerr.h>
#include <prov/blake2.h>

#ifndef OPENSSL_NO_ARGON2

# define ARGON2_MIN_LANES UINT32_C(1)
# define ARGON2_MAX_LANES UINT32_C(0xFFFFFF)
# define ARGON2_MIN_THREADS UINT32_C(1)
# define ARGON2_MAX_THREADS UINT32_C(0xFFFFFF)
# define ARGON2_SYNC_POINTS UINT32_C(4)
# define ARGON2_MIN_OUTLEN UINT32_C(4)
# define ARGON2_MAX_OUTLEN UINT32_C(0xFFFFFFFF)
# define ARGON2_MIN_MEMORY (2 * ARGON2_SYNC_POINTS)
# define ARGON2_MIN(a, b) ((a) < (b) ? (a) : (b))
# define ARGON2_MAX_MEMORY_BITS                                                 \
    ARGON2_MIN(UINT32_C(32), (sizeof(void *) * CHAR_BIT - 10 - 1))
# define ARGON2_MAX_MEMORY                                                      \
    ARGON2_MIN(UINT32_C(0xFFFFFFFF), UINT64_C(1) << ARGON2_MAX_MEMORY_BITS)
# define ARGON2_MIN_TIME UINT32_C(1)
# define ARGON2_MAX_TIME UINT32_C(0xFFFFFFFF)
# define ARGON2_MIN_PWD_LENGTH UINT32_C(0)
# define ARGON2_MAX_PWD_LENGTH UINT32_C(0xFFFFFFFF)
# define ARGON2_MIN_AD_LENGTH UINT32_C(0)
# define ARGON2_MAX_AD_LENGTH UINT32_C(0xFFFFFFFF)
# define ARGON2_MIN_SALT_LENGTH UINT32_C(8)
# define ARGON2_MAX_SALT_LENGTH UINT32_C(0xFFFFFFFF)
# define ARGON2_MIN_SECRET UINT32_C(0)
# define ARGON2_MAX_SECRET UINT32_C(0xFFFFFFFF)
# define ARGON2_FLAG_CLEAR_PASSWORD (UINT32_C(1) << 0)
# define ARGON2_FLAG_CLEAR_SECRET (UINT32_C(1) << 1)
# define ARGON2_BLOCK_SIZE 1024
# define ARGON2_QWORDS_IN_BLOCK ARGON2_BLOCK_SIZE / 8
# define ARGON2_OWORDS_IN_BLOCK ARGON2_BLOCK_SIZE / 16
# define ARGON2_HWORDS_IN_BLOCK ARGON2_BLOCK_SIZE / 32
# define ARGON2_512BIT_WORDS_IN_BLOCK ARGON2_BLOCK_SIZE / 64
# define ARGON2_ADDRESSES_IN_BLOCK 128
# define ARGON2_PREHASH_DIGEST_LENGTH 64
# define ARGON2_PREHASH_SEED_LENGTH \
    (ARGON2_PREHASH_DIGEST_LENGTH + (2 * sizeof(uint32_t)))

# define ARGON2_DEFAULT_FLAGS UINT32_C(0)
# define ARGON2_DEFAULT_OUTLEN UINT32_C(64)
# define ARGON2_DEFAULT_T_COST UINT32_C(3)
# define ARGON2_DEFAULT_M_COST ARGON2_MIN_MEMORY
# define ARGON2_DEFAULT_LANES  UINT32_C(1)
# define ARGON2_DEFAULT_THREADS UINT32_C(1)
# define ARGON2_DEFAULT_VERSION ARGON2_VERSION_NUMBER

# undef G
# define G(a, b, c, d)                                                         \
    do {                                                                       \
        a = a + b + 2 * mul_lower(a, b);                                       \
        d = rotr64(d ^ a, 32);                                                 \
        c = c + d + 2 * mul_lower(c, d);                                       \
        b = rotr64(b ^ c, 24);                                                 \
        a = a + b + 2 * mul_lower(a, b);                                       \
        d = rotr64(d ^ a, 16);                                                 \
        c = c + d + 2 * mul_lower(c, d);                                       \
        b = rotr64(b ^ c, 63);                                                 \
    } while ((void)0, 0)

# undef PERMUTATION_P
# define PERMUTATION_P(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11,       \
                       v12, v13, v14, v15)                                     \
    do {                                                                       \
        G(v0, v4, v8, v12);                                                    \
        G(v1, v5, v9, v13);                                                    \
        G(v2, v6, v10, v14);                                                   \
        G(v3, v7, v11, v15);                                                   \
        G(v0, v5, v10, v15);                                                   \
        G(v1, v6, v11, v12);                                                   \
        G(v2, v7, v8, v13);                                                    \
        G(v3, v4, v9, v14);                                                    \
    } while ((void)0, 0)

# undef PERMUTATION_P_COLUMN
# define PERMUTATION_P_COLUMN(x, i)                                            \
    do {                                                                       \
        uint64_t *base = &x[16 * i];                                           \
        PERMUTATION_P(                                                         \
            *base,        *(base + 1),  *(base + 2),  *(base + 3),             \
            *(base + 4),  *(base + 5),  *(base + 6),  *(base + 7),             \
            *(base + 8),  *(base + 9),  *(base + 10), *(base + 11),            \
            *(base + 12), *(base + 13), *(base + 14), *(base + 15)             \
        );                                                                     \
    } while ((void)0, 0)

# undef PERMUTATION_P_ROW
# define PERMUTATION_P_ROW(x, i)                                               \
    do {                                                                       \
        uint64_t *base = &x[2 * i];                                            \
        PERMUTATION_P(                                                         \
            *base,        *(base + 1),  *(base + 16),  *(base + 17),           \
            *(base + 32), *(base + 33), *(base + 48),  *(base + 49),           \
            *(base + 64), *(base + 65), *(base + 80),  *(base + 81),           \
            *(base + 96), *(base + 97), *(base + 112), *(base + 113)           \
        );                                                                     \
    } while ((void)0, 0)

typedef struct {
    uint64_t v[ARGON2_QWORDS_IN_BLOCK];
} BLOCK;

typedef enum {
    ARGON2_VERSION_10 = 0x10,
    ARGON2_VERSION_13 = 0x13,
    ARGON2_VERSION_NUMBER = ARGON2_VERSION_13
} ARGON2_VERSION;

typedef enum {
    ARGON2_D  = 0,
    ARGON2_I  = 1,
    ARGON2_ID = 2
} ARGON2_TYPE;

typedef struct {
    uint8_t *out;
    uint32_t outlen;
    uint8_t *pwd;
    uint32_t pwdlen;
    uint8_t *salt;
    uint32_t saltlen;
    uint8_t *secret;
    uint32_t secretlen;
    uint8_t *ad;
    uint32_t adlen;
    uint32_t t_cost;
    uint32_t m_cost;
    uint32_t lanes;
    uint32_t threads;
    uint32_t version;
    uint32_t flags;
    ARGON2_TYPE type;
    BLOCK *memory;
    uint32_t passes;
    uint32_t memory_blocks;
    uint32_t segment_length;
    uint32_t lane_length;
    OPENSSL_CTX *libctx;
    EVP_MAC *mac;
} ARGON2_CTX;

typedef struct {
    uint32_t pass;
    uint32_t lane;
    uint8_t slice;
    uint32_t index;
} ARGON2_POS;

typedef struct {
    ARGON2_POS pos;
    ARGON2_CTX *ctx;
} ARGON2_THREAD_DATA;

union endianity_test {
    long one;
    char little;
};

static union endianity_test is_endian = { 1 };

typedef struct {
    void *provctx;
    ARGON2_CTX ctx;
} KDF_ARGON2;

static OSSL_FUNC_kdf_newctx_fn kdf_argon2i_new;
static OSSL_FUNC_kdf_newctx_fn kdf_argon2d_new;
static OSSL_FUNC_kdf_newctx_fn kdf_argon2id_new;
static OSSL_FUNC_kdf_freectx_fn kdf_argon2_free;
static OSSL_FUNC_kdf_reset_fn kdf_argon2_reset;
static OSSL_FUNC_kdf_derive_fn kdf_argon2_derive;
static OSSL_FUNC_kdf_settable_ctx_params_fn kdf_argon2_settable_ctx_params;
static OSSL_FUNC_kdf_set_ctx_params_fn kdf_argon2_set_ctx_params;

static void kdf_argon2_init(KDF_ARGON2 *ctx, ARGON2_TYPE t);
static void *kdf_argon2d_new(void *provctx);
static void *kdf_argon2i_new(void *provctx);
static void *kdf_argon2id_new(void *provctx);
static void kdf_argon2_free(void *vctx);
static int kdf_argon2_derive(void *vctx, unsigned char *out, size_t outlen);
static void kdf_argon2_reset(void *vctx);
static int kdf_argon2_ctx_set_threads(ARGON2_CTX *ctx, uint32_t threads);
static int kdf_argon2_ctx_set_lanes(ARGON2_CTX *ctx, uint32_t lanes);
static int kdf_argon2_ctx_set_t_cost(ARGON2_CTX *ctx, uint32_t t_cost);
static int kdf_argon2_ctx_set_m_cost(ARGON2_CTX *ctx, uint32_t m_cost);
static int kdf_argon2_ctx_set_digest_length(ARGON2_CTX *ctx, uint32_t outlen);
static int kdf_argon2_ctx_set_secret(ARGON2_CTX *ctx, const OSSL_PARAM *p);
static int kdf_argon2_ctx_set_pwd(ARGON2_CTX *ctx, const OSSL_PARAM *p);
static int kdf_argon2_ctx_set_salt(ARGON2_CTX *ctx, const OSSL_PARAM *p);
static int kdf_argon2_ctx_set_ad(ARGON2_CTX *ctx, const OSSL_PARAM *p);
static int kdf_argon2_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
static int kdf_argon2_get_ctx_params(void *vctx, OSSL_PARAM params[]);
static void kdf_argon2_ctx_set_flag_clear_pwd(ARGON2_CTX *ctx, uint32_t flag);
static void kdf_argon2_ctx_set_flag_clear_secret(ARGON2_CTX *ctx, uint32_t f);
static void kdf_argon2_ctx_set_version(ARGON2_CTX *ctx, uint32_t flags);
static const OSSL_PARAM *kdf_argon2_settable_ctx_params(void *provctx);
static const OSSL_PARAM *kdf_argon2_gettable_ctx_params(void *provctx);

static ossl_inline uint64_t load64(const uint8_t *src);
static ossl_inline void store32(uint8_t *dst, uint32_t w);
static ossl_inline void store64(uint8_t *dst, uint64_t w);
static ossl_inline uint64_t rotr64(const uint64_t w, const unsigned int c);
static ossl_inline uint64_t mul_lower(uint64_t x, uint64_t y);

static void init_block_value(BLOCK *b, uint8_t in);
static void copy_block(BLOCK *dst, const BLOCK *src);
static void xor_block(BLOCK *dst, const BLOCK *src);
static void load_block(BLOCK *dst, const void *input);
static void store_block(void *output, const BLOCK *src);
static void fill_first_blocks(uint8_t *blockhash, const ARGON2_CTX *ctx);
static void fill_block(const BLOCK *prev, const BLOCK *ref, BLOCK *next,
                       int with_xor);

static void next_addresses(BLOCK *address_block, BLOCK *input_block,
                           const BLOCK *zero_block);
static int data_indep_addressing(const ARGON2_CTX *ctx, uint32_t pass,
                                 uint8_t slice);
static uint32_t index_alpha(const ARGON2_CTX *ctx, uint32_t pass,
                            uint8_t slice, uint32_t index,
                            uint32_t pseudo_rand, int same_lane);

static void fill_segment(const ARGON2_CTX *ctx, uint32_t pass, uint32_t lane,
                         uint8_t slice);
static uint32_t fill_segment_thr(void *thread_data);
static int fill_mem_blocks_st(ARGON2_CTX *ctx);
static int fill_mem_blocks_mt(ARGON2_CTX *ctx);
static ossl_inline int fill_memory_blocks(ARGON2_CTX *ctx);

static int validate_inputs(const ARGON2_CTX *ctx);
static void initial_hash(uint8_t *blockhash, ARGON2_CTX *ctx);
static int initialize(ARGON2_CTX *ctx);
static void finalize(const ARGON2_CTX *ctx);

static int blake2b(EVP_MAC *mac, void *out, size_t outlen, const void *in,
                   size_t inlen, const void *key, size_t keylen);
static int blake2b_long(EVP_MAC *mac, unsigned char *out, size_t outlen,
                        const void *in, size_t inlen);

static ossl_inline uint64_t load64(const uint8_t *src)
{
    uint64_t w = 0;
    unsigned char i;

    if (is_endian.little) {
        memcpy(&w, src, sizeof(w));
        return w;
    }

    for (i = 0; i < 8; i++)
        w |= ((uint64_t)src[i] << (8 * i));

    return w;
}

static ossl_inline void store32(uint8_t *dst, uint32_t w)
{
    int i;
    uint8_t *p = (uint8_t *)dst;

    if (is_endian.little) {
        memcpy(dst, &w, sizeof(w));
        return;
    }

    for (i = 0; i < 4; i++)
        p[i] = (uint8_t)(w >> (8 * i));
}

static ossl_inline void store64(uint8_t *dst, uint64_t w)
{
    int i;
    uint8_t *p = (uint8_t *)dst;

    if (is_endian.little) {
        memcpy(dst, &w, sizeof(w));
        return;
    }

    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(w >> (8 * i));
}

static ossl_inline uint64_t rotr64(const uint64_t w, const unsigned int c)
{
    return (w >> c) | (w << (64 - c));
}

static ossl_inline uint64_t mul_lower(uint64_t x, uint64_t y)
{
    const uint64_t m = UINT64_C(0xFFFFFFFF);
    return (x & m) * (y & m);
}

static void init_block_value(BLOCK *b, uint8_t in)
{
    memset(b->v, in, sizeof(b->v));
}

static void copy_block(BLOCK *dst, const BLOCK *src)
{
    memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
}

static void xor_block(BLOCK *dst, const BLOCK *src)
{
    int i;

    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i)
        dst->v[i] ^= src->v[i];
}

static void load_block(BLOCK *dst, const void *input)
{
    unsigned i;

    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i)
        dst->v[i] = load64((const uint8_t *)input + i * sizeof(dst->v[i]));
}

static void store_block(void *output, const BLOCK *src)
{
    unsigned i;

    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i)
        store64((uint8_t *)output + i * sizeof(src->v[i]), src->v[i]);
}

static void fill_first_blocks(uint8_t *blockhash, const ARGON2_CTX *ctx)
{
    uint32_t l;
    uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];

    /*
     * Make the first and second block in each lane as G(H0||0||i)
     * or G(H0||1||i).
     */
    for (l = 0; l < ctx->lanes; ++l) {
        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 0);
        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH + 4, l);
        blake2b_long(ctx->mac, blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash,
                     ARGON2_PREHASH_SEED_LENGTH);
        load_block(&ctx->memory[l * ctx->lane_length + 0],
                   blockhash_bytes);
        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 1);
        blake2b_long(ctx->mac, blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash,
                     ARGON2_PREHASH_SEED_LENGTH);
        load_block(&ctx->memory[l * ctx->lane_length + 1],
                   blockhash_bytes);
    }
    OPENSSL_cleanse(blockhash_bytes, ARGON2_BLOCK_SIZE);
}

static void fill_block(const BLOCK *prev, const BLOCK *ref,
                       BLOCK *next, int with_xor)
{
    BLOCK blockR, tmp;
    unsigned i;

    copy_block(&blockR, ref);
    xor_block(&blockR, prev);
    copy_block(&tmp, &blockR);

    if (with_xor)
        xor_block(&tmp, next);

    for (i = 0; i < 8; ++i)
        PERMUTATION_P_COLUMN(blockR.v, i);

    for (i = 0; i < 8; ++i)
        PERMUTATION_P_ROW(blockR.v, i);

    copy_block(next, &tmp);
    xor_block(next, &blockR);
}

static void next_addresses(BLOCK *address_block, BLOCK *input_block,
                           const BLOCK *zero_block) {
    input_block->v[6]++;
    fill_block(zero_block, input_block, address_block, 0);
    fill_block(zero_block, address_block, address_block, 0);
}

static int data_indep_addressing(const ARGON2_CTX *ctx, uint32_t pass,
                                 uint8_t slice)
{
    switch (ctx->type) {
    case ARGON2_I:
        return 1;
    case ARGON2_ID:
        return (pass == 0) && (slice < ARGON2_SYNC_POINTS / 2);
    case ARGON2_D:
    default:
        return 0;
    }
}

/*
 * Pass 0 (pass = 0):
 * This lane: all already finished segments plus already constructed blocks
 *            in this segment
 * Other lanes: all already finished segments
 *
 * Pass 1+:
 * This lane: (SYNC_POINTS - 1) last segments plus already constructed
 *            blocks in this segment
 * Other lanes: (SYNC_POINTS - 1) last segments
 */
static uint32_t index_alpha(const ARGON2_CTX *ctx, uint32_t pass,
                            uint8_t slice, uint32_t index,
                            uint32_t pseudo_rand, int same_lane)
{
    uint32_t ref_area_sz;
    uint64_t rel_pos;
    uint32_t start_pos, abs_pos;

    start_pos = 0;
    switch (pass){
    case 0:
        if (slice == 0) {
            ref_area_sz = index - 1;
        } else {
            if (same_lane)
                ref_area_sz = slice * ctx->segment_length + index - 1;
            else
                ref_area_sz = slice * ctx->segment_length +
                    ((index == 0) ? (-1) : 0);
        }
        break;
    default:
        if (same_lane)
            ref_area_sz = ctx->lane_length - ctx->segment_length + index - 1;
        else
            ref_area_sz = ctx->lane_length - ctx->segment_length +
                ((index == 0) ? (-1) : 0);
        if (slice != ARGON2_SYNC_POINTS - 1)
            start_pos = (slice + 1) * ctx->segment_length;
        break;
    }

    rel_pos = pseudo_rand;
    rel_pos = rel_pos * rel_pos >> 32;
    rel_pos = ref_area_sz - 1 - (ref_area_sz * rel_pos >> 32);
    abs_pos = (start_pos+ rel_pos) % ctx->lane_length;

    return abs_pos;
}

static void fill_segment(const ARGON2_CTX *ctx, uint32_t pass, uint32_t lane,
                         uint8_t slice)
{
    BLOCK *ref_block = NULL, *curr_block = NULL;
    BLOCK address_block, input_block, zero_block;
    uint64_t rnd, ref_index, ref_lane;
    uint32_t prev_offset;
    uint32_t start_idx;
    uint32_t j;
    uint32_t curr_offset; /* Offset of the current block */

    if (ctx == NULL)
        return;

    if (data_indep_addressing(ctx, pass, slice)) {
        init_block_value(&zero_block, 0);
        init_block_value(&input_block, 0);

        input_block.v[0] = pass;
        input_block.v[1] = lane;
        input_block.v[2] = slice;
        input_block.v[3] = ctx->memory_blocks;
        input_block.v[4] = ctx->passes;
        input_block.v[5] = ctx->type;
    }

    start_idx = 0;

    /* We've generated the first two blocks. Generate the 1st block of addrs. */
    if ((pass == 0) && (slice == 0)) {
        start_idx = 2;
        if (data_indep_addressing(ctx, pass, slice))
            next_addresses(&address_block, &input_block, &zero_block);
    }

    curr_offset = lane * ctx->lane_length + slice * ctx->segment_length
                  + start_idx;

    if ((curr_offset % ctx->lane_length) == 0)
        prev_offset = curr_offset + ctx->lane_length - 1;
    else
        prev_offset = curr_offset - 1;

    for (j = start_idx; j < ctx->segment_length; ++j, ++curr_offset, ++prev_offset) {
        if (curr_offset % ctx->lane_length == 1)
            prev_offset = curr_offset - 1;

        /* Taking pseudo-random value from the previous block. */
        if (data_indep_addressing(ctx, pass, slice)) {
            if (j % ARGON2_ADDRESSES_IN_BLOCK == 0)
                next_addresses(&address_block, &input_block, &zero_block);
            rnd = address_block.v[j % ARGON2_ADDRESSES_IN_BLOCK];
        } else {
            rnd = ctx->memory[prev_offset].v[0];
        }

        /* Computing the lane of the reference block */
        ref_lane = ((rnd >> 32)) % ctx->lanes;
        /* Can not reference other lanes yet */
        if ((pass == 0) && (slice == 0))
            ref_lane = lane;

        /* Computing the number of possible reference block within the lane. */
        ref_index = index_alpha(ctx, pass, slice, j, rnd & 0xFFFFFFFF,
                                ref_lane == lane);

        /* Creating a new block */
        ref_block = ctx->memory + ctx->lane_length * ref_lane + ref_index;
        curr_block = ctx->memory + curr_offset;
        if (ARGON2_VERSION_10 == ctx->version) {
            /* Version 1.2.1 and earlier: overwrite, not XOR */
            fill_block(ctx->memory + prev_offset, ref_block, curr_block, 0);
            continue;
        }

        fill_block(ctx->memory + prev_offset, ref_block, curr_block,
                   pass == 0 ? 0 : 1);
    }
}



#if !defined(ARGON2_NO_THREADS) && defined(OPENSSL_THREADS)

static uint32_t fill_segment_thr(void *thread_data)
{
    ARGON2_THREAD_DATA *my_data;

    my_data = (ARGON2_THREAD_DATA *) thread_data;
    fill_segment(my_data->ctx, my_data->pos.pass, my_data->pos.lane, my_data->pos.slice);
    return 0;
}

static int fill_mem_blocks_mt(ARGON2_CTX *ctx) {
    uint32_t r, s, l, ll;
    void **t;
    ARGON2_THREAD_DATA *t_data;

    t = OPENSSL_zalloc(sizeof(void*)*ctx->lanes);
    t_data = OPENSSL_zalloc(ctx->lanes * sizeof(ARGON2_THREAD_DATA));

    if (t == NULL || t_data == NULL)
        goto fail;

    for (r = 0; r < ctx->passes; ++r) {
        for (s = 0; s < ARGON2_SYNC_POINTS; ++s) {
            for (l = 0; l < ctx->lanes; ++l) {
                ARGON2_POS p;
                if (l >= ctx->threads)
                    if (crypto_thread_join(ctx->libctx, t[l - ctx->threads],
                                           NULL) == 0)
                        goto fail;

                p.pass = r;
                p.lane = l;
                p.slice = (uint8_t)s;
                p.index = 0;

                t_data[l].ctx = ctx;
                memcpy(&(t_data[l].pos), &p, sizeof(ARGON2_POS));
                t[l] = crypto_thread_start(ctx->libctx, &fill_segment_thr,
                                           (void*) &t_data[l],
                                           CRYPTO_THREAD_START_AWAIT);
                if (t[l] == NULL) {
                    for (ll = 0; ll < l; ++ll)
                        crypto_thread_join(ctx->libctx, t[ll], NULL);
                    t[ll] = NULL;
                    goto fail;
                }
            }
            for (l = ctx->lanes - ctx->threads; l < ctx->lanes; ++l) {
                if (crypto_thread_join(ctx->libctx, t[l], NULL) == 0)
                    goto fail;
                t[l] = NULL;
            }
        }
    }

    crypto_thread_clean(ctx->libctx, NULL);

    OPENSSL_free(t_data);
    OPENSSL_free(t);

    return 1;

fail:
    if (t_data != NULL)
        OPENSSL_free(t_data);
    if (t != NULL)
        OPENSSL_free(t);
    return 0;
}

#endif /* ARGON2_NO_THREADS OPENSSL_THREADS */

static int fill_mem_blocks_st(ARGON2_CTX *ctx)
{
    uint32_t r, s, l;

    for (r = 0; r < ctx->passes; ++r)
        for (s = 0; s < ARGON2_SYNC_POINTS; ++s)
            for (l = 0; l < ctx->lanes; ++l)
                fill_segment(ctx, r, l, s);
    return 1;
}

static ossl_inline int fill_memory_blocks(ARGON2_CTX *ctx)
{
    return ctx->threads == 1 ? fill_mem_blocks_st(ctx) : fill_mem_blocks_mt(ctx);
}

static int validate_inputs(const ARGON2_CTX *ctx)
{
    int ret;

    /*
     * due to -Werror=type-limits, some of the comparisons are made as
     * X+1 > Y+1 rather than X > Y, as this caused problems when some
     * lower limits were set to zero.
     */

    if (ctx == NULL)
        return 0;

    switch (ctx->type) {
    case ARGON2_D:
    case ARGON2_I:
    case ARGON2_ID:
        break;
    default:
        return 0;
    }

    ret = ctx->outlen < ARGON2_MIN_OUTLEN
          || ctx->outlen > ARGON2_MAX_OUTLEN
          || ctx->pwdlen + 1 < ARGON2_MIN_PWD_LENGTH + 1
          || ctx->pwdlen > ARGON2_MAX_PWD_LENGTH
          || ctx->saltlen < ARGON2_MIN_SALT_LENGTH
          || ctx->saltlen > ARGON2_MAX_SALT_LENGTH
          || ctx->m_cost < ARGON2_MIN_MEMORY
          || ctx->m_cost < 8 * ctx->lanes
          || ctx->t_cost < ARGON2_MIN_TIME
          || ctx->t_cost > ARGON2_MAX_TIME
          || ctx->lanes < ARGON2_MIN_LANES
          || ctx->lanes > ARGON2_MAX_LANES
          || (ctx->secret != NULL
              && ARGON2_MIN_SECRET + 1 > ctx->secretlen + 1
              && ARGON2_MAX_SECRET < ctx->secretlen)
          || (ctx->ad != NULL
              && ARGON2_MIN_AD_LENGTH + 1 > ctx->adlen + 1
              && ARGON2_MAX_AD_LENGTH < ctx->adlen)
          || (ctx->m_cost >= (uint64_t) ARGON2_MAX_MEMORY
              && ctx->m_cost != (uint64_t) ARGON2_MAX_MEMORY);

#if !defined(ARGON2_NO_THREADS) && defined(OPENSSL_THREADS)
    ret |= ctx->threads < ARGON2_MIN_THREADS
           || ctx->threads > ARGON2_MAX_THREADS
           || (ctx->threads > 1 && CRYPTO_THREAD_enabled(ctx->libctx) != 1)
           || (ctx->threads > 1 && ctx->threads >
                crypto_thread_get_available_threads(ctx->libctx));
#else
    ret |= ctx->threads != 1;
#endif

    return !ret;
}

static void initial_hash(uint8_t *blockhash, ARGON2_CTX *ctx)
{
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    uint8_t value[sizeof(uint32_t)];
    unsigned int tmp;
    uint32_t args[7];

    if (ctx == NULL || blockhash == NULL)
        return;

    args[0] = ctx->lanes;
    args[1] = ctx->outlen;
    args[2] = ctx->m_cost;
    args[3] = ctx->t_cost;
    args[4] = ctx->version;
    args[5] = (uint32_t) ctx->type;
    args[6] = ctx->pwdlen;

    md = EVP_MD_fetch(ctx->libctx, "blake2b512", NULL);
    if (md == NULL)
        return;

    mdctx = EVP_MD_CTX_create();
    if (mdctx == NULL || EVP_DigestInit_ex(mdctx, md, NULL) != 1)
        goto fail;

    for(tmp = 0; tmp < sizeof(args)/sizeof(uint32_t); ++tmp) {
        store32((uint8_t *) &value, args[tmp]);
        if (EVP_DigestUpdate(mdctx, &value, sizeof(value)) != 1)
            goto fail;
    }

    if (ctx->pwd != NULL) {
        if (EVP_DigestUpdate(mdctx, ctx->pwd, ctx->pwdlen) != 1)
            goto fail;
        if ((ctx->flags & ARGON2_FLAG_CLEAR_PASSWORD) != 0) {
            OPENSSL_cleanse(ctx->pwd, ctx->pwdlen);
            ctx->pwdlen = 0;
        }
    }

    store32((uint8_t *) &value, ctx->saltlen);
    if (EVP_DigestUpdate(mdctx, &value, sizeof(value)) != 1)
        goto fail;

    if (ctx->salt != NULL)
        if (EVP_DigestUpdate(mdctx, ctx->salt, ctx->saltlen) != 1)
            goto fail;

    store32((uint8_t *) &value, ctx->secretlen);
    if(EVP_DigestUpdate(mdctx, &value, sizeof(value)) != 1)
        goto fail;

    if (ctx->secret != NULL) {
        if (EVP_DigestUpdate(mdctx, ctx->secret, ctx->secretlen) != 1)
            goto fail;
        if ((ctx->flags & ARGON2_FLAG_CLEAR_SECRET) != 0) {
            OPENSSL_cleanse(ctx->secret, ctx->secretlen);
            ctx->secretlen = 0;
        }
    }

    store32((uint8_t *) &value, ctx->adlen);
    if (EVP_DigestUpdate(mdctx, &value, sizeof(value)) != 1)
        goto fail;

    if (ctx->ad != NULL)
        if (EVP_DigestUpdate(mdctx, ctx->ad, ctx->adlen) != 1)
            goto fail;

    tmp = ARGON2_PREHASH_DIGEST_LENGTH;
    if (EVP_DigestFinal_ex(mdctx, blockhash, &tmp) != 1)
        goto fail;

fail:
    EVP_MD_CTX_destroy(mdctx);
    EVP_MD_free(md);
}

static int initialize(ARGON2_CTX *ctx)
{
    uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH];

    if (ctx == NULL)
        return 0;

    if (ctx->memory_blocks * sizeof(BLOCK) / sizeof(BLOCK)
            != ctx->memory_blocks)
        return 0;

    if (ctx->type != ARGON2_D)
        ctx->memory = OPENSSL_secure_zalloc(ctx->memory_blocks *
                                            sizeof(BLOCK));
    else
        ctx->memory = OPENSSL_zalloc(ctx->memory_blocks *
                                     sizeof(BLOCK));

    if (ctx->memory == NULL)
        return 0;

    initial_hash(blockhash, ctx);
    OPENSSL_cleanse(blockhash + ARGON2_PREHASH_DIGEST_LENGTH,
        ARGON2_PREHASH_SEED_LENGTH - ARGON2_PREHASH_DIGEST_LENGTH);
    fill_first_blocks(blockhash, ctx);
    OPENSSL_cleanse(blockhash, ARGON2_PREHASH_SEED_LENGTH);

    return 1;
}

static void finalize(const ARGON2_CTX *ctx)
{
    BLOCK blockhash;
    uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
    uint32_t last_block_in_lane;
    uint32_t l;

    if (ctx == NULL)
        return;

    copy_block(&blockhash, ctx->memory + ctx->lane_length - 1);

    /* XOR the last blocks */
    for (l = 1; l < ctx->lanes; ++l) {
        last_block_in_lane = l * ctx->lane_length + (ctx->lane_length - 1);
        xor_block(&blockhash, ctx->memory + last_block_in_lane);
    }

    /* Hash the result */
    store_block(blockhash_bytes, &blockhash);
    blake2b_long(ctx->mac, ctx->out, ctx->outlen, blockhash_bytes,
                 ARGON2_BLOCK_SIZE);
    OPENSSL_cleanse(blockhash.v, ARGON2_BLOCK_SIZE);
    OPENSSL_cleanse(blockhash_bytes, ARGON2_BLOCK_SIZE);

    if (ctx->type != ARGON2_D)
        OPENSSL_secure_clear_free(ctx->memory,
                                  ctx->memory_blocks * sizeof(BLOCK));
    else
        OPENSSL_clear_free(ctx->memory,
                           ctx->memory_blocks * sizeof(BLOCK));
}

static int blake2b(EVP_MAC *mac, void *out, size_t outlen, const void *in,
                   size_t inlen, const void *key, size_t keylen)
{
    int ret = 0;
    size_t par_n = 0, out_written;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM par[3];

    if (out == NULL || outlen == 0)
        goto fail;

    if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
        goto fail;

    if (key != NULL && keylen != 0)
        par[par_n++] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                        (void *) key, keylen);
    par[par_n++] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &outlen);
    par[par_n++] = OSSL_PARAM_construct_end();

    ret = EVP_MAC_CTX_set_params(ctx, par) == 1
          && EVP_MAC_init(ctx) == 1
          && EVP_MAC_update(ctx, in, inlen) == 1
          && EVP_MAC_final(ctx, out, (size_t *) &out_written, outlen) == 1;

    if (ret == 0)
        goto fail;

fail:
    EVP_MAC_CTX_free(ctx);
    return ret;
}

static int blake2b_long(EVP_MAC *mac, unsigned char *out, size_t outlen,
                        const void *in, size_t inlen)
{
    int ret;
    EVP_MAC_CTX *ctx;
    OSSL_PARAM par[2];
    size_t par_n, out_written, blake_outlen;
    uint32_t outlen_curr;
    uint8_t outbuf[BLAKE2B_OUTBYTES];
    uint8_t inbuf[BLAKE2B_OUTBYTES];
    uint8_t outlen_bytes[sizeof(uint32_t)] = {0};

    ctx = NULL;
    ret = 0;
    par_n = 0;
    blake_outlen = outlen;

    if (out == NULL || outlen == 0)
        goto fail;

    if (outlen > BLAKE2B_OUTBYTES)
        blake_outlen = BLAKE2B_OUTBYTES;

    /* Ensure little-endian byte order */
    store32(outlen_bytes, (uint32_t)outlen);

    if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
        goto fail;

    par[par_n++] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &blake_outlen);
    par[par_n++] = OSSL_PARAM_construct_end();

    ret = EVP_MAC_CTX_set_params(ctx, par)
          && EVP_MAC_init(ctx) == 1
          && EVP_MAC_update(ctx, outlen_bytes, sizeof(outlen_bytes)) == 1
          && EVP_MAC_update(ctx, in, inlen) == 1;

    if (ret == 0)
        goto fail;

    if (outlen <= BLAKE2B_OUTBYTES) {
        if (EVP_MAC_final(ctx, out, (size_t *) &out_written, outlen) != 1)
            goto fail;
    } else {
        if (EVP_MAC_final(ctx, outbuf, (size_t *) &out_written,
                          BLAKE2B_OUTBYTES) != 1)
            goto fail;

        memcpy(out, outbuf, BLAKE2B_OUTBYTES / 2);
        out += BLAKE2B_OUTBYTES / 2;
        outlen_curr = (uint32_t) outlen - BLAKE2B_OUTBYTES / 2;

        while(outlen_curr > BLAKE2B_OUTBYTES) {
            memcpy(inbuf, outbuf, BLAKE2B_OUTBYTES);
            if (blake2b(mac, outbuf, BLAKE2B_OUTBYTES, inbuf,
                        BLAKE2B_OUTBYTES, NULL, 0) != 1)
                goto fail;
            memcpy(out, outbuf, BLAKE2B_OUTBYTES / 2);
            out += BLAKE2B_OUTBYTES / 2;
            outlen_curr -= BLAKE2B_OUTBYTES / 2;
        }

        memcpy(inbuf, outbuf, BLAKE2B_OUTBYTES);
        if (blake2b(mac, outbuf, outlen_curr, inbuf, BLAKE2B_OUTBYTES, NULL,
                    0) != 1)
            goto fail;
        memcpy(out, outbuf, outlen_curr);
    }
    ret = 1;

fail:
    EVP_MAC_CTX_free(ctx);
    return ret;
}

static void kdf_argon2_init(KDF_ARGON2 *ctx, ARGON2_TYPE type)
{
    ARGON2_CTX *c;

    c = &ctx->ctx;
    memset(c, 0, sizeof(*c));
    c->outlen = ARGON2_DEFAULT_OUTLEN;
    c->t_cost = ARGON2_DEFAULT_T_COST;
    c->m_cost = ARGON2_DEFAULT_M_COST;
    c->lanes = ARGON2_DEFAULT_LANES;
    c->threads = ARGON2_DEFAULT_THREADS;
    c->flags = ARGON2_DEFAULT_FLAGS;
    c->version = ARGON2_DEFAULT_VERSION;
    c->type = type;
    c->libctx = PROV_LIBRARY_CONTEXT_OF(ctx->provctx);
    c->mac = EVP_MAC_fetch(c->libctx, "blake2bmac", NULL);
}

static void *kdf_argon2d_new(void *provctx)
{
    KDF_ARGON2 *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->provctx = provctx;

    kdf_argon2_init(ctx, ARGON2_D);
    return ctx;
}

static void *kdf_argon2i_new(void *provctx)
{
    KDF_ARGON2 *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->provctx = provctx;

    kdf_argon2_init(ctx, ARGON2_I);
    return ctx;
}

static void *kdf_argon2id_new(void *provctx)
{
    KDF_ARGON2 *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->provctx = provctx;

    kdf_argon2_init(ctx, ARGON2_ID);
    return ctx;
}

static void kdf_argon2_free(void *vctx)
{
    ARGON2_CTX *ctx;
    KDF_ARGON2 *ctx_wrap;

    ctx_wrap = (KDF_ARGON2 *) vctx;
    ctx = &ctx_wrap->ctx;
    if (ctx->out != NULL)
        OPENSSL_clear_free(ctx->out, ctx->outlen);

    if (ctx->pwd != NULL)
        OPENSSL_clear_free(ctx->pwd, ctx->pwdlen);

    if (ctx->salt != NULL)
        OPENSSL_clear_free(ctx->salt, ctx->saltlen);

    if (ctx->secret != NULL)
        OPENSSL_clear_free(ctx->secret, ctx->secretlen);

    if (ctx->ad != NULL)
        OPENSSL_clear_free(ctx->ad, ctx->adlen);

    if (ctx->mac != NULL) {
        EVP_MAC_free(ctx->mac);
        ctx->mac = NULL;
    }

    memset(ctx, 0, sizeof(*ctx));
    OPENSSL_free(ctx_wrap);
}

static int kdf_argon2_derive(void *vctx, unsigned char *out, size_t outlen)
{
    ARGON2_CTX *ctx;
    KDF_ARGON2 *ctx_wrap;
    uint32_t memory_blocks, segment_length;

    ctx_wrap = (KDF_ARGON2 *)vctx;
    ctx = &ctx_wrap->ctx;

    if (ctx->mac == NULL)
        return 0;

    if (ctx->pwd == NULL || ctx->pwdlen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_PASS);
        return 0;
    }

    if (ctx->salt == NULL || ctx->saltlen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SALT);
        return 0;
    }

    if (outlen == 0)
        return 0;

    if (outlen != ctx->outlen)
        kdf_argon2_ctx_set_digest_length(ctx, (uint32_t) outlen);

    if (ctx->type != ARGON2_D)
        ctx->out = OPENSSL_secure_zalloc(ctx->outlen + 1);
    else
        ctx->out = OPENSSL_zalloc(ctx->outlen + 1);

    if (validate_inputs(ctx) != 1)
        goto fail;

    memory_blocks = ctx->m_cost;
    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * ctx->lanes)
        memory_blocks = 2 * ARGON2_SYNC_POINTS * ctx->lanes;

    /* Ensure that all segments have equal length */
    segment_length = memory_blocks / (ctx->lanes * ARGON2_SYNC_POINTS);
    memory_blocks = segment_length * (ctx->lanes * ARGON2_SYNC_POINTS);

    ctx->memory = NULL;
    ctx->memory_blocks = memory_blocks;
    ctx->segment_length = segment_length;
    ctx->passes = ctx->t_cost;
    ctx->lane_length = segment_length * ARGON2_SYNC_POINTS;

    if (ctx->threads > ctx->lanes)
        ctx->threads = ctx->lanes;

    if (initialize(ctx) != 1)
        goto fail;

    if (fill_memory_blocks(ctx) != 1)
        goto fail;

    finalize(ctx);
    memcpy(out, ctx->out, outlen);

    return 1;

 fail:
    if (ctx->type != ARGON2_D)
        OPENSSL_secure_clear_free(ctx->out, ctx->outlen + 1);
    else
        OPENSSL_clear_free(ctx->out, ctx->outlen + 1);
    ctx->out = NULL;
    return 0;
}

static void kdf_argon2_reset(void *vctx)
{
    EVP_MAC *mac;
    OPENSSL_CTX *libctx;
    KDF_ARGON2 *ctx_wrap;
    ARGON2_CTX *ctx;
    ARGON2_TYPE type;

    ctx_wrap = (KDF_ARGON2 *) vctx;
    ctx = &ctx_wrap->ctx;
    type = ctx->type;
    libctx = ctx->libctx;
    mac = ctx->mac;

    if (mac == NULL)
        mac = EVP_MAC_fetch(libctx, "blake2bmac", NULL);

    if (ctx->out != NULL)
        OPENSSL_clear_free(ctx->out, ctx->outlen);

    if (ctx->pwd != NULL)
        OPENSSL_clear_free(ctx->pwd, ctx->pwdlen);

    if (ctx->salt != NULL)
        OPENSSL_clear_free(ctx->salt, ctx->saltlen);

    if (ctx->secret != NULL)
        OPENSSL_clear_free(ctx->secret, ctx->secretlen);

    if (ctx->ad != NULL)
        OPENSSL_clear_free(ctx->ad, ctx->adlen);

    memset(ctx, 0, sizeof(*ctx));
    ctx->libctx = libctx;
    ctx->mac = mac;
    kdf_argon2_init(ctx_wrap, type);
}

static int kdf_argon2_ctx_set_threads(ARGON2_CTX *ctx, uint32_t threads)
{
    if (threads > ARGON2_MAX_THREADS || threads < ARGON2_MIN_THREADS)
        return 0;

    ctx->threads = threads;
    return 1;
}


static int kdf_argon2_ctx_set_lanes(ARGON2_CTX *ctx, uint32_t lanes)
{
    if (lanes > ARGON2_MAX_LANES || lanes < ARGON2_MIN_LANES)
        return 0;

    ctx->lanes = lanes;
    return 1;
}

static int kdf_argon2_ctx_set_t_cost(ARGON2_CTX *ctx, uint32_t t_cost)
{
    if (t_cost < ARGON2_MIN_TIME || t_cost > ARGON2_MAX_TIME)
        return 0;

    ctx->t_cost = t_cost;
    return 1;
}

static int kdf_argon2_ctx_set_m_cost(ARGON2_CTX *ctx, uint32_t m_cost)
{
    /* comparison convoluted due to Werror=type-limits */
    if (m_cost + 1 < ARGON2_MIN_MEMORY + 1 || m_cost >= ARGON2_MAX_MEMORY)
        if (m_cost != ARGON2_MAX_MEMORY)
            return 0;

    ctx->m_cost = m_cost;
    return 1;
}

static int kdf_argon2_ctx_set_digest_length(ARGON2_CTX *ctx,
                                            uint32_t outlen)
{
    if (outlen < ARGON2_MIN_OUTLEN || outlen > ARGON2_MAX_OUTLEN)
        return 0;

    ctx->outlen = outlen;
    return 1;
}

static int kdf_argon2_ctx_set_secret(ARGON2_CTX *ctx,
                                     const OSSL_PARAM *p)
{
    size_t buflen;

    if (p->data == NULL)
        return 0;

    if (ctx->secret != NULL) {
        OPENSSL_clear_free(ctx->secret, ctx->secretlen);
        ctx->secret = NULL;
        ctx->secretlen = 0U;
    }

    if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->secret, 0, &buflen))
        return 0;

    if (buflen + 1 < ARGON2_MIN_SECRET + 1 || buflen > ARGON2_MAX_SECRET) {
        OPENSSL_free(ctx->secret);
        ctx->secret = NULL;
        ctx->secretlen = 0U;
        return 0;
    }

    ctx->secretlen = (uint32_t) buflen;
    return 1;
}

static int kdf_argon2_ctx_set_pwd(ARGON2_CTX *ctx, const OSSL_PARAM *p)
{
    size_t buflen;

    if (p->data == NULL)
        return 0;

    if (ctx->pwd != NULL) {
        OPENSSL_clear_free(ctx->pwd, ctx->pwdlen);
        ctx->pwd = NULL;
        ctx->pwdlen = 0U;
    }

    if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->pwd, 0, &buflen))
        return 0;

    if (buflen + 1 < ARGON2_MIN_PWD_LENGTH + 1 || buflen > ARGON2_MAX_PWD_LENGTH) {
        OPENSSL_free(ctx->pwd);
        ctx->pwd = NULL;
        ctx->pwdlen = 0U;
        return 0;
    }

    ctx->pwdlen = (uint32_t) buflen;
    return 1;
}

static int kdf_argon2_ctx_set_salt(ARGON2_CTX *ctx, const OSSL_PARAM *p)
{
    size_t buflen;

    if (p->data == NULL)
        return 0;

    if (ctx->salt != NULL) {
        OPENSSL_clear_free(ctx->salt, ctx->saltlen);
        ctx->salt = NULL;
        ctx->saltlen = 0U;
    }

    if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->salt, 0, &buflen))
        return 0;

    if (buflen < ARGON2_MIN_SALT_LENGTH || buflen > ARGON2_MAX_SALT_LENGTH) {
        OPENSSL_free(ctx->salt);
        ctx->salt = NULL;
        ctx->saltlen = 0U;
        return 0;
    }

    ctx->saltlen = (uint32_t) buflen;
    return 1;
}

static int kdf_argon2_ctx_set_ad(ARGON2_CTX *ctx, const OSSL_PARAM *p)
{
    size_t buflen;

    if (p->data == NULL)
        return 0;

    if (ctx->ad != NULL) {
        OPENSSL_clear_free(ctx->ad, ctx->adlen);
        ctx->ad = NULL;
        ctx->adlen = 0U;
    }

    if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->ad, 0, &buflen))
        return 0;

    if (buflen > ARGON2_MAX_AD_LENGTH) {
        OPENSSL_free(ctx->ad);
        ctx->ad = NULL;
        ctx->adlen = 0U;
        return 0;
    }

    ctx->adlen = (uint32_t) buflen;
    return 1;
}

static void kdf_argon2_ctx_set_flag_clear_secret(ARGON2_CTX *ctx, uint32_t f)
{
    if (f)
        ctx->flags |= ARGON2_FLAG_CLEAR_SECRET;
    else
        ctx->flags &= ~ARGON2_FLAG_CLEAR_SECRET;
}

static void kdf_argon2_ctx_set_flag_clear_pwd(ARGON2_CTX *ctx, uint32_t flag)
{
    if (flag)
        ctx->flags |= ARGON2_FLAG_CLEAR_PASSWORD;
    else
        ctx->flags &= ~ARGON2_FLAG_CLEAR_PASSWORD;
}

static void kdf_argon2_ctx_set_version(ARGON2_CTX *ctx, uint32_t version)
{
    ctx->version = version;
}

static int kdf_argon2_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    KDF_ARGON2 *ctx;
    uint32_t u32_value;

    ctx = (KDF_ARGON2 *) vctx;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PASSWORD)) != NULL)
        if (!kdf_argon2_ctx_set_pwd(&ctx->ctx, p))
            return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT)) != NULL)
        if (!kdf_argon2_ctx_set_salt(&ctx->ctx, p))
            return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SECRET)) != NULL)
        if (!kdf_argon2_ctx_set_secret(&ctx->ctx, p))
            return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ARGON2_AD)) != NULL)
        if (!kdf_argon2_ctx_set_ad(&ctx->ctx, p))
            return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ARGON2_SZ))
          != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &u32_value))
            return 0;
        if (!kdf_argon2_ctx_set_digest_length(&ctx->ctx, u32_value))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ITER)) != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &u32_value))
            return 0;
        if (!kdf_argon2_ctx_set_t_cost(&ctx->ctx, u32_value))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_THREADS)) != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &u32_value))
            return 0;
        if (!kdf_argon2_ctx_set_threads(&ctx->ctx, u32_value))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ARGON2_LANES))
          != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &u32_value))
            return 0;
        if (!kdf_argon2_ctx_set_lanes(&ctx->ctx, u32_value))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ARGON2_MEMCOST))
          != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &u32_value))
            return 0;
        if (!kdf_argon2_ctx_set_m_cost(&ctx->ctx, u32_value))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ARGON2_FLAG_CLEAR_PWD))
          != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &u32_value))
            return 0;
        kdf_argon2_ctx_set_flag_clear_pwd(&ctx->ctx, u32_value);
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ARGON2_FLAG_CLEAR_SECRET))
          != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &u32_value))
            return 0;
        kdf_argon2_ctx_set_flag_clear_secret(&ctx->ctx, u32_value);
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ARGON2_VERSION))
          != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &u32_value))
            return 0;
        kdf_argon2_ctx_set_version(&ctx->ctx, u32_value);
    }

    return 1;
}

static const OSSL_PARAM *kdf_argon2_settable_ctx_params(void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_ARGON2_AD, NULL, 0),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_ARGON2_SZ, NULL),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_ITER, NULL),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_THREADS, NULL),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_ARGON2_LANES, NULL),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, NULL),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_ARGON2_FLAG_CLEAR_PWD, NULL),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_ARGON2_FLAG_CLEAR_SECRET, NULL),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, NULL),
        OSSL_PARAM_END
    };

    (void) provctx;
    return known_settable_ctx_params;
}

static int kdf_argon2_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    (void) vctx;
    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL)
        return OSSL_PARAM_set_size_t(p, SIZE_MAX);

    return -2;
}

static const OSSL_PARAM *kdf_argon2_gettable_ctx_params(void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };

    (void) provctx;
    return known_gettable_ctx_params;
}

const OSSL_DISPATCH kdf_argon2i_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void(*)(void))kdf_argon2i_new },
    { OSSL_FUNC_KDF_FREECTX, (void(*)(void))kdf_argon2_free },
    { OSSL_FUNC_KDF_RESET, (void(*)(void))kdf_argon2_reset },
    { OSSL_FUNC_KDF_DERIVE, (void(*)(void))kdf_argon2_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_argon2_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void(*)(void))kdf_argon2_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_argon2_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void(*)(void))kdf_argon2_get_ctx_params },
    { 0, NULL }
};

const OSSL_DISPATCH kdf_argon2d_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void(*)(void))kdf_argon2d_new },
    { OSSL_FUNC_KDF_FREECTX, (void(*)(void))kdf_argon2_free },
    { OSSL_FUNC_KDF_RESET, (void(*)(void))kdf_argon2_reset },
    { OSSL_FUNC_KDF_DERIVE, (void(*)(void))kdf_argon2_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_argon2_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void(*)(void))kdf_argon2_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_argon2_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void(*)(void))kdf_argon2_get_ctx_params },
    { 0, NULL }
};

const OSSL_DISPATCH kdf_argon2id_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void(*)(void))kdf_argon2id_new },
    { OSSL_FUNC_KDF_FREECTX, (void(*)(void))kdf_argon2_free },
    { OSSL_FUNC_KDF_RESET, (void(*)(void))kdf_argon2_reset },
    { OSSL_FUNC_KDF_DERIVE, (void(*)(void))kdf_argon2_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_argon2_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void(*)(void))kdf_argon2_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_argon2_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void(*)(void))kdf_argon2_get_ctx_params },
    { 0, NULL }
};

#endif
