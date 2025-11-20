/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "testutil.h"
#include <openssl/evp.h>
#include "internal/cryptlib.h"
#include "crypto/evp.h"
#include "evp_local.h"

#define MAX_INPUT_LEN 3000

static void fuzz_fill_encode_ctx(EVP_ENCODE_CTX *ctx, int max_fill)
{
    static int seeded = 0;

    if (!seeded) {
        srand((unsigned)time(NULL));
        seeded = 1;
    }

    int num = rand() % (max_fill + 1);
    ctx->num = num;

    for (int i = 0; i < num; i++)
        ctx->enc_data[i] = (unsigned char)(rand() & 0xFF);
    ctx->length = (rand() % 80) + 1;
    ctx->line_num = rand() % (ctx->length + 1);
}
static inline uint32_t next_u32(uint32_t *state)
{
    *state = (*state * 1664525u) + 1013904223u;
    return *state;
}

static const unsigned char data_bin2ascii[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/* SRP uses a different base64 alphabet */
static const unsigned char srpdata_bin2ascii[65] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./";

#ifndef CHARSET_EBCDIC
# define conv_bin2ascii(a, table)       ((table)[(a)&0x3f])
#else
/*
 * We assume that PEM encoded files are EBCDIC files (i.e., printable text
 * files). Convert them here while decoding. When encoding, output is EBCDIC
 * (text) format again. (No need for conversion in the conv_bin2ascii macro,
 * as the underlying textstring data_bin2ascii[] is already EBCDIC)
 */
# define conv_bin2ascii(a, table)       ((table)[(a)&0x3f])
#endif

static int evp_encodeblock_int_old(EVP_ENCODE_CTX *ctx, unsigned char *t,
                                   const unsigned char *f, int dlen)
{
    int i, ret = 0;
    unsigned long l;
    const unsigned char *table;

    if (ctx != NULL && (ctx->flags & EVP_ENCODE_CTX_USE_SRP_ALPHABET) != 0)
        table = srpdata_bin2ascii;
    else
        table = data_bin2ascii;

    for (i = dlen; i > 0; i -= 3) {
        if (i >= 3) {
            l = (((unsigned long)f[0]) << 16L) |
                (((unsigned long)f[1]) << 8L) | f[2];
            *(t++) = conv_bin2ascii(l >> 18L, table);
            *(t++) = conv_bin2ascii(l >> 12L, table);
            *(t++) = conv_bin2ascii(l >> 6L, table);
            *(t++) = conv_bin2ascii(l, table);
        } else {
            l = ((unsigned long)f[0]) << 16L;
            if (i == 2)
                l |= ((unsigned long)f[1] << 8L);

            *(t++) = conv_bin2ascii(l >> 18L, table);
            *(t++) = conv_bin2ascii(l >> 12L, table);
            *(t++) = (i == 1) ? '=' : conv_bin2ascii(l >> 6L, table);
            *(t++) = '=';
        }
        ret += 4;
        f += 3;
    }

    *t = '\0';
    return ret;
}
static int evp_encodeupdate_old(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
                                const unsigned char *in, int inl)
{
    int i, j;
    int total = 0;

    *outl = 0;
    if (inl <= 0)
        return 0;
    OPENSSL_assert(ctx->length <= (int)sizeof(ctx->enc_data));
    if (ctx->length - ctx->num > inl) {
        memcpy(&(ctx->enc_data[ctx->num]), in, inl);
        ctx->num += inl;
        return 1;
    }
    if (ctx->num != 0) {
        i = ctx->length - ctx->num;
        memcpy(&(ctx->enc_data[ctx->num]), in, i);
        in += i;
        inl -= i;
        j = evp_encodeblock_int_old(ctx, out, ctx->enc_data, ctx->length);
        ctx->num = 0;
        out += j;
        total = j;
        if ((ctx->flags & EVP_ENCODE_CTX_NO_NEWLINES) == 0) {
            *(out++) = '\n';
            total++;
        }
        *out = '\0';
    }
    while (inl >= ctx->length && total <= INT_MAX) {
        j = evp_encodeblock_int_old(ctx, out, in, ctx->length);
        in += ctx->length;
        inl -= ctx->length;
        out += j;
        total += j;
        if ((ctx->flags & EVP_ENCODE_CTX_NO_NEWLINES) == 0) {
            *(out++) = '\n';
            total++;
        }
        *out = '\0';
    }
    if (total > INT_MAX) {
        /* Too much output data! */
        *outl = 0;
        return 0;
    }
    if (inl != 0)
        memcpy(&(ctx->enc_data[0]), in, inl);
    ctx->num = inl;
    *outl = total;

    return 1;
}

static void evp_encodefinal_old(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl)
{
    unsigned int ret = 0;

    if (ctx->num != 0) {
        ret = evp_encodeblock_int_old(ctx, out, ctx->enc_data, ctx->num);
        if ((ctx->flags & EVP_ENCODE_CTX_NO_NEWLINES) == 0)
            out[ret++] = '\n';
        out[ret] = '\0';
        ctx->num = 0;
    }
    *outl = ret;
}
static int test_encode_line_lengths_reinforced(void)
{
    const int trials = 50;
    uint32_t seed = 12345;
    /* Generous output buffers (Update + Final + newlines), plus a guard byte */
    unsigned char out_simd[9000 * 2 + 1] = { 0 };
    unsigned char out_ref[9000 * 2 + 1] = { 0 };

    for (int t = 0; t < trials; t++) {
        uint32_t r = next_u32(&seed);
        int inl = r % MAX_INPUT_LEN;
        /* Fresh random input */
        unsigned char input[MAX_INPUT_LEN];

        for (int i = 0; i < inl; i++)
            input[i] = (unsigned char)(r % 256);

        for (int partial_ctx_fill = 0; partial_ctx_fill <= 80;
             partial_ctx_fill += 1) {
            for (int ctx_len = 1; ctx_len <= 80; ctx_len += 1) {
                printf
                ("Trial %d, input length %d, ctx length %d, partial ctx fill %d\n",
                 t + 1, inl, ctx_len, partial_ctx_fill);
                EVP_ENCODE_CTX *ctx_simd = EVP_ENCODE_CTX_new();
                EVP_ENCODE_CTX *ctx_ref = EVP_ENCODE_CTX_new();

                fuzz_fill_encode_ctx(ctx_simd, partial_ctx_fill);

                memset(out_simd, 0xCC, sizeof(out_simd)); /* poison to catch short writes */
                memset(out_ref, 0xDD, sizeof(out_ref));

                int outlen_simd = 0, outlen_ref = 0; /* bytes produced by Update */
                int finlen_simd = 0, finlen_ref = 0; /* bytes produced by Final */

                if (!ctx_simd || !ctx_ref) {
                    EVP_ENCODE_CTX_free(ctx_simd);
                    EVP_ENCODE_CTX_free(ctx_ref);
                    TEST_error("Out of memory for contexts");
                    return 0;
                }

                EVP_EncodeInit(ctx_simd);
                EVP_EncodeInit(ctx_ref);
                ctx_simd->length = ctx_len;
                ctx_ref->length = ctx_len;

                for (int i = 0; i < 2; i++) {
                    if (i % 2 == 0) {
                        /* Turn SRP alphabet OFF */
                        ctx_simd->flags &= ~EVP_ENCODE_CTX_USE_SRP_ALPHABET;
                        ctx_ref->flags &= ~EVP_ENCODE_CTX_USE_SRP_ALPHABET;
                    } else {
                        /* Turn SRP alphabet ON */
                        ctx_simd->flags |= EVP_ENCODE_CTX_USE_SRP_ALPHABET;
                        ctx_ref->flags |= EVP_ENCODE_CTX_USE_SRP_ALPHABET;
                    }

                    int ret_simd =
                        EVP_EncodeUpdate(ctx_simd, out_simd, &outlen_simd,
                                         input, (int)inl);
                    int ret_ref =
                        evp_encodeupdate_old(ctx_ref, out_ref, &outlen_ref,
                                             input, (int)inl);

                    if (!TEST_int_eq(ret_simd, ret_ref)
                        || !TEST_mem_eq(out_ref,outlen_ref, out_simd, outlen_simd)
                        || !TEST_int_eq(outlen_simd, outlen_ref))
                    return 0;

                    EVP_EncodeFinal(ctx_simd, out_simd + outlen_simd,
                                    &finlen_simd);
                    evp_encodefinal_old(ctx_ref, out_ref + outlen_ref,
                                        &finlen_ref);

                    int total_ref = outlen_ref + finlen_ref;
                    int total_simd = outlen_simd + finlen_simd;

                    if (!TEST_int_eq(finlen_simd, finlen_ref)
                            || !TEST_mem_eq(out_ref, total_ref, out_simd, total_simd))
                        return 0;
                }

                EVP_ENCODE_CTX_free(ctx_simd);
                EVP_ENCODE_CTX_free(ctx_ref);
            }
        }
    }

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(test_encode_line_lengths_reinforced);

    return 1;
}
