/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/objects.h>
#include "crypto/evp.h"
#include "internal/sha3.h"
#include "evp_local.h"

static int init(EVP_MD_CTX *ctx)
{
    return sha3_init(EVP_MD_CTX_md_data(ctx), '\x06', ctx->digest->md_size * 8);
}

static int update(EVP_MD_CTX *ctx, const void *_inp, size_t len)
{
    return sha3_update(EVP_MD_CTX_md_data(ctx), _inp, len);
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return sha3_final(md, EVP_MD_CTX_md_data(ctx));
}

static int shake_init(EVP_MD_CTX *ctx)
{
    return sha3_init(EVP_MD_CTX_md_data(ctx), '\x1f', ctx->digest->md_size * 8);
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

#if defined(OPENSSL_CPUID_OBJ) && defined(__s390__) && defined(KECCAK1600_ASM)
/*
 * IBM S390X support
 */
# include "s390x_arch.h"

# define S390X_SHA3_FC(ctx)     ((ctx)->pad)

# define S390X_sha3_224_CAPABLE ((OPENSSL_s390xcap_P.kimd[0] &      \
                                  S390X_CAPBIT(S390X_SHA3_224)) &&  \
                                 (OPENSSL_s390xcap_P.klmd[0] &      \
                                  S390X_CAPBIT(S390X_SHA3_224)))
# define S390X_sha3_256_CAPABLE ((OPENSSL_s390xcap_P.kimd[0] &      \
                                  S390X_CAPBIT(S390X_SHA3_256)) &&  \
                                 (OPENSSL_s390xcap_P.klmd[0] &      \
                                  S390X_CAPBIT(S390X_SHA3_256)))
# define S390X_sha3_384_CAPABLE ((OPENSSL_s390xcap_P.kimd[0] &      \
                                  S390X_CAPBIT(S390X_SHA3_384)) &&  \
                                 (OPENSSL_s390xcap_P.klmd[0] &      \
                                  S390X_CAPBIT(S390X_SHA3_384)))
# define S390X_sha3_512_CAPABLE ((OPENSSL_s390xcap_P.kimd[0] &      \
                                  S390X_CAPBIT(S390X_SHA3_512)) &&  \
                                 (OPENSSL_s390xcap_P.klmd[0] &      \
                                  S390X_CAPBIT(S390X_SHA3_512)))
# define S390X_shake128_CAPABLE ((OPENSSL_s390xcap_P.kimd[0] &      \
                                  S390X_CAPBIT(S390X_SHAKE_128)) && \
                                 (OPENSSL_s390xcap_P.klmd[0] &      \
                                  S390X_CAPBIT(S390X_SHAKE_128)))
# define S390X_shake256_CAPABLE ((OPENSSL_s390xcap_P.kimd[0] &      \
                                  S390X_CAPBIT(S390X_SHAKE_256)) && \
                                 (OPENSSL_s390xcap_P.klmd[0] &      \
                                  S390X_CAPBIT(S390X_SHAKE_256)))

/* Convert md-size to block-size. */
# define S390X_KECCAK1600_BSZ(n) ((KECCAK1600_WIDTH - ((n) << 1)) >> 3)

static int s390x_sha3_init(EVP_MD_CTX *evp_ctx)
{
    KECCAK1600_CTX *ctx = evp_ctx->md_data;
    const size_t bsz = evp_ctx->digest->block_size;

    /*-
     * KECCAK1600_CTX structure's pad field is used to store the KIMD/KLMD
     * function code.
     */
    switch (bsz) {
    case S390X_KECCAK1600_BSZ(224):
        ctx->pad = S390X_SHA3_224;
        break;
    case S390X_KECCAK1600_BSZ(256):
        ctx->pad = S390X_SHA3_256;
        break;
    case S390X_KECCAK1600_BSZ(384):
        ctx->pad = S390X_SHA3_384;
        break;
    case S390X_KECCAK1600_BSZ(512):
        ctx->pad = S390X_SHA3_512;
        break;
    default:
        return 0;
    }

    memset(ctx->A, 0, sizeof(ctx->A));
    ctx->bufsz = 0;
    ctx->block_size = bsz;
    ctx->md_size = evp_ctx->digest->md_size;
    return 1;
}

static int s390x_shake_init(EVP_MD_CTX *evp_ctx)
{
    KECCAK1600_CTX *ctx = evp_ctx->md_data;
    const size_t bsz = evp_ctx->digest->block_size;

    /*-
     * KECCAK1600_CTX structure's pad field is used to store the KIMD/KLMD
     * function code.
     */
    switch (bsz) {
    case S390X_KECCAK1600_BSZ(128):
        ctx->pad = S390X_SHAKE_128;
        break;
    case S390X_KECCAK1600_BSZ(256):
        ctx->pad = S390X_SHAKE_256;
        break;
    default:
        return 0;
    }

    memset(ctx->A, 0, sizeof(ctx->A));
    ctx->bufsz = 0;
    ctx->block_size = bsz;
    ctx->md_size = evp_ctx->digest->md_size;
    return 1;
}

static int s390x_sha3_update(EVP_MD_CTX *evp_ctx, const void *_inp, size_t len)
{
    KECCAK1600_CTX *ctx = evp_ctx->md_data;
    const unsigned char *inp = _inp;
    const size_t bsz = ctx->block_size;
    size_t num, rem;

    if (len == 0)
        return 1;

    if ((num = ctx->bufsz) != 0) {
        rem = bsz - num;

        if (len < rem) {
            memcpy(ctx->buf + num, inp, len);
            ctx->bufsz += len;
            return 1;
        }
        memcpy(ctx->buf + num, inp, rem);
        inp += rem;
        len -= rem;
        s390x_kimd(ctx->buf, bsz, ctx->pad, ctx->A);
        ctx->bufsz = 0;
    }
    rem = len % bsz;

    s390x_kimd(inp, len - rem, ctx->pad, ctx->A);

    if (rem) {
        memcpy(ctx->buf, inp + len - rem, rem);
        ctx->bufsz = rem;
    }
    return 1;
}

static int s390x_sha3_final(EVP_MD_CTX *evp_ctx, unsigned char *md)
{
    KECCAK1600_CTX *ctx = evp_ctx->md_data;

    s390x_klmd(ctx->buf, ctx->bufsz, NULL, 0, ctx->pad, ctx->A);
    memcpy(md, ctx->A, ctx->md_size);
    return 1;
}

static int s390x_shake_final(EVP_MD_CTX *evp_ctx, unsigned char *md)
{
    KECCAK1600_CTX *ctx = evp_ctx->md_data;

    s390x_klmd(ctx->buf, ctx->bufsz, md, ctx->md_size, ctx->pad, ctx->A);
    return 1;
}

# define EVP_MD_SHA3(bitlen)                         \
const EVP_MD *EVP_sha3_##bitlen(void)                \
{                                                    \
    static const EVP_MD s390x_sha3_##bitlen##_md = { \
        NID_sha3_##bitlen,                           \
        NID_RSA_SHA3_##bitlen,                       \
        bitlen / 8,                                  \
        EVP_MD_FLAG_DIGALGID_ABSENT,                 \
        s390x_sha3_init,                             \
        s390x_sha3_update,                           \
        s390x_sha3_final,                            \
        NULL,                                        \
        NULL,                                        \
        (KECCAK1600_WIDTH - bitlen * 2) / 8,         \
        sizeof(KECCAK1600_CTX),                      \
    };                                               \
    static const EVP_MD sha3_##bitlen##_md = {       \
        NID_sha3_##bitlen,                           \
        NID_RSA_SHA3_##bitlen,                       \
        bitlen / 8,                                  \
        EVP_MD_FLAG_DIGALGID_ABSENT,                 \
        init,                                        \
        update,                                      \
        final,                                       \
        NULL,                                        \
        NULL,                                        \
        (KECCAK1600_WIDTH - bitlen * 2) / 8,         \
        sizeof(KECCAK1600_CTX),                      \
    };                                               \
    return S390X_sha3_##bitlen##_CAPABLE ?           \
           &s390x_sha3_##bitlen##_md :               \
           &sha3_##bitlen##_md;                      \
}

# define EVP_MD_SHAKE(bitlen)                        \
const EVP_MD *EVP_shake##bitlen(void)                \
{                                                    \
    static const EVP_MD s390x_shake##bitlen##_md = { \
        NID_shake##bitlen,                           \
        0,                                           \
        bitlen / 8,                                  \
        EVP_MD_FLAG_XOF,                             \
        s390x_shake_init,                            \
        s390x_sha3_update,                           \
        s390x_shake_final,                           \
        NULL,                                        \
        NULL,                                        \
        (KECCAK1600_WIDTH - bitlen * 2) / 8,         \
        sizeof(KECCAK1600_CTX),                      \
        shake_ctrl                                   \
    };                                               \
    static const EVP_MD shake##bitlen##_md = {       \
        NID_shake##bitlen,                           \
        0,                                           \
        bitlen / 8,                                  \
        EVP_MD_FLAG_XOF,                             \
        shake_init,                                  \
        update,                                      \
        final,                                       \
        NULL,                                        \
        NULL,                                        \
        (KECCAK1600_WIDTH - bitlen * 2) / 8,         \
        sizeof(KECCAK1600_CTX),                      \
        shake_ctrl                                   \
    };                                               \
    return S390X_shake##bitlen##_CAPABLE ?           \
           &s390x_shake##bitlen##_md :               \
           &shake##bitlen##_md;                      \
}

#else

# define EVP_MD_SHA3(bitlen)                    \
const EVP_MD *EVP_sha3_##bitlen(void)           \
{                                               \
    static const EVP_MD sha3_##bitlen##_md = {  \
        NID_sha3_##bitlen,                      \
        NID_RSA_SHA3_##bitlen,                  \
        bitlen / 8,                             \
        EVP_MD_FLAG_DIGALGID_ABSENT,            \
        init,                                   \
        update,                                 \
        final,                                  \
        NULL,                                   \
        NULL,                                   \
        (KECCAK1600_WIDTH - bitlen * 2) / 8,    \
        sizeof(KECCAK1600_CTX),                 \
    };                                          \
    return &sha3_##bitlen##_md;                 \
}

# define EVP_MD_SHAKE(bitlen)                   \
const EVP_MD *EVP_shake##bitlen(void)           \
{                                               \
    static const EVP_MD shake##bitlen##_md = {  \
        NID_shake##bitlen,                      \
        0,                                      \
        bitlen / 8,                             \
        EVP_MD_FLAG_XOF,                        \
        shake_init,                             \
        update,                                 \
        final,                                  \
        NULL,                                   \
        NULL,                                   \
        (KECCAK1600_WIDTH - bitlen * 2) / 8,    \
        sizeof(KECCAK1600_CTX),                 \
        shake_ctrl                              \
    };                                          \
    return &shake##bitlen##_md;                 \
}

#endif

EVP_MD_SHA3(224)
EVP_MD_SHA3(256)
EVP_MD_SHA3(384)
EVP_MD_SHA3(512)

EVP_MD_SHAKE(128)
EVP_MD_SHAKE(256)
