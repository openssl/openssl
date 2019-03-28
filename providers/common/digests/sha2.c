/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/core_numbers.h>

static int sha256_final(void *ctx, unsigned char *md, size_t *size)
{
    if (SHA256_Final(md, ctx)) {
        *size = SHA256_DIGEST_LENGTH;
        return 1;
    }

    return 0;
}

static void *sha256_newctx(void)
{
    SHA256_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    return ctx;
}

static void sha256_freectx(void *vctx)
{
    SHA256_CTX *ctx = (SHA256_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *sha256_dupctx(void *ctx)
{
    SHA256_CTX *in = (SHA256_CTX *)ctx;
    SHA256_CTX *ret = OPENSSL_malloc(sizeof(*ret));

    *ret = *in;

    return ret;
}

static size_t sha256_size(void)
{
    return SHA256_DIGEST_LENGTH;
}

static size_t sha256_block_size(void)
{
    return SHA256_CBLOCK;
}

extern const OSSL_DISPATCH sha256_functions[];
const OSSL_DISPATCH sha256_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))sha256_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))SHA256_Init },
    { OSSL_FUNC_DIGEST_UPDDATE, (void (*)(void))SHA256_Update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))sha256_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))sha256_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))sha256_dupctx },
    { OSSL_FUNC_DIGEST_SIZE, (void (*)(void))sha256_size },
    { OSSL_FUNC_DIGEST_BLOCK_SIZE, (void (*)(void))sha256_block_size },
    { 0, NULL }
};
