/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/objects.h>
#include "internal/evp_int.h"
#include "evp_locl.h"

size_t SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len,
                   size_t r);
void SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r);

#define KECCAK1600_WIDTH 1600

typedef struct {
    uint64_t A[5][5];
    size_t block_size;          /* cached ctx->digest->block_size */
    size_t md_size;             /* output length, variable in XOF */
    size_t num;                 /* used bytes in below buffer */
    unsigned char buf[KECCAK1600_WIDTH / 8 - 32];
    unsigned char pad;
} KECCAK1600_CTX;

static int init(EVP_MD_CTX *evp_ctx, unsigned char pad)
{
    KECCAK1600_CTX *ctx = evp_ctx->md_data;
    size_t bsz = evp_ctx->digest->block_size;

    if (bsz <= sizeof(ctx->buf)) {
        memset(ctx->A, 0, sizeof(ctx->A));

        ctx->num = 0;
        ctx->block_size = bsz;
        ctx->md_size = evp_ctx->digest->md_size;
        ctx->pad = pad;

        return 1;
    }

    return 0;
}

static int sha3_init(EVP_MD_CTX *evp_ctx)
{
    return init(evp_ctx, '\x06');
}

static int shake_init(EVP_MD_CTX *evp_ctx)
{
    return init(evp_ctx, '\x1f');
}

static int sha3_update(EVP_MD_CTX *evp_ctx, const void *_inp, size_t len)
{
    KECCAK1600_CTX *ctx = evp_ctx->md_data;
    const unsigned char *inp = _inp;
    size_t bsz = ctx->block_size;
    size_t num, rem;

    if ((num = ctx->num) != 0) {      /* process intermediate buffer? */
        rem = bsz - num;

        if (len < rem) {
            memcpy(ctx->buf + num, inp, len);
            ctx->num += len;
            return 1;
        }
        /*
         * We have enough data to fill or overflow the intermediate
         * buffer. So we append |rem| bytes and process the block,
         * leaving the rest for later processing...
         */
        memcpy(ctx->buf + num, inp, rem);
        inp += rem, len -= rem;
        (void)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        ctx->num = 0;
        /* ctx->buf is processed, ctx->num is guaranteed to be zero */
    }

    if (len >= bsz)
        rem = SHA3_absorb(ctx->A, inp, len, bsz);
    else
        rem = len;

    if (rem) {
        memcpy(ctx->buf, inp + len - rem, rem);
        ctx->num = rem;
    }

    return 1;
}

static int sha3_final(EVP_MD_CTX *evp_ctx, unsigned char *md)
{
    KECCAK1600_CTX *ctx = evp_ctx->md_data;
    size_t bsz = ctx->block_size;
    size_t num = ctx->num;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    memset(ctx->buf + num, 0, bsz - num);
    ctx->buf[num] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (void)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, md, ctx->md_size, bsz);

    return 1;
}

static int shake_ctrl(EVP_MD_CTX *evp_ctx, int cmd, int p1, void *p2)
{
    KECCAK1600_CTX *ctx = evp_ctx->md_data;

    switch (cmd) {
    case EVP_MD_CTRL_XOF_LEN:
        ctx->md_size = p1;
        return 1;
    default:
        return 0;
    }
}

#define EVP_MD_SHA3(bitlen)                     \
const EVP_MD *EVP_sha3_##bitlen(void)           \
{                                               \
    static const EVP_MD sha3_##bitlen##_md = {  \
        NID_sha3_##bitlen,                      \
        NID_RSA_SHA3_##bitlen,                  \
        bitlen / 8,                             \
        EVP_MD_FLAG_DIGALGID_ABSENT,            \
        sha3_init,                              \
        sha3_update,                            \
        sha3_final,                             \
        NULL,                                   \
        NULL,                                   \
        (KECCAK1600_WIDTH - bitlen * 2) / 8,    \
        sizeof(KECCAK1600_CTX),                 \
    };                                          \
    return &sha3_##bitlen##_md;                 \
}

EVP_MD_SHA3(224)
EVP_MD_SHA3(256)
EVP_MD_SHA3(384)
EVP_MD_SHA3(512)

#define EVP_MD_SHAKE(bitlen)                    \
const EVP_MD *EVP_shake##bitlen(void)           \
{                                               \
    static const EVP_MD shake##bitlen##_md = {  \
        NID_shake##bitlen,                      \
        0,                                      \
        bitlen / 8,                             \
        EVP_MD_FLAG_XOF,                        \
        shake_init,                             \
        sha3_update,                            \
        sha3_final,                             \
        NULL,                                   \
        NULL,                                   \
        (KECCAK1600_WIDTH - bitlen * 2) / 8,    \
        sizeof(KECCAK1600_CTX),                 \
        shake_ctrl                              \
    };                                          \
    return &shake##bitlen##_md;                 \
}

EVP_MD_SHAKE(128)
EVP_MD_SHAKE(256)
