/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"

#include <openssl/evp.h>
#include <openssl/objects.h>
#include "internal/evp_int.h"

size_t SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len,
                   size_t r);
void SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r);

struct keccak1600_ctx_st
{
    uint64_t A[5][5];
};

typedef struct keccak1600_ctx_st KECCAK1600_CTX;

#define SHA3_256_D (256/8)
#define SHA3_256_R ((1600-512)/8)

static int init(EVP_MD_CTX *evp_ctx)
{
    KECCAK1600_CTX *ctx = EVP_MD_CTX_md_data(evp_ctx);

    memset(ctx->A, 0, sizeof(ctx->A));
    return 1;
}

static int update_256(EVP_MD_CTX *evp_ctx, const void *data, size_t count)
{
    KECCAK1600_CTX *ctx = EVP_MD_CTX_md_data(evp_ctx);

    /* TODO: subblock buffering, padding */
    SHA3_absorb(ctx->A, data, count, SHA3_256_R);
    return 1;
}

static int final_256(EVP_MD_CTX *evp_ctx, unsigned char *md)
{
    KECCAK1600_CTX *ctx = EVP_MD_CTX_md_data(evp_ctx);

    SHA3_squeeze(ctx->A, md, SHA3_256_D, SHA3_256_R);
    return 1;
}

static const EVP_MD sha3_256_md = {
    NID_sha3_256,
    0,
    SHA3_256_D,
    0,
    init,
    update_256,
    final_256,
    NULL,
    NULL,
    0,
    sizeof(EVP_MD *) + sizeof(KECCAK1600_CTX),
};

const EVP_MD *EVP_sha3_256(void)
{
    return (&sha3_256_md);
}

