/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/md2.h>
#include <openssl/crypto.h>
#include <openssl/core_numbers.h>

static int md2_final(void *ctx, unsigned char *md, size_t *size)
{
    if (MD2_Final(md, ctx)) {
        *size = MD2_DIGEST_LENGTH;
        return 1;
    }

    return 0;
}

static void *md2_newctx(void)
{
    MD2_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    return ctx;
}

static void md2_freectx(void *vctx)
{
    MD2_CTX *ctx = (MD2_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *md2_dupctx(void *ctx)
{
    MD2_CTX *in = (MD2_CTX *)ctx;
    MD2_CTX *ret = OPENSSL_malloc(sizeof(*ret));

    *ret = *in;

    return ret;
}

static size_t md2_size(void)
{
    return MD2_DIGEST_LENGTH;
}

extern const OSSL_DISPATCH md2_functions[];
const OSSL_DISPATCH md2_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))md2_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))MD2_Init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))MD2_Update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))md2_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))md2_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))md2_dupctx },
    { OSSL_FUNC_DIGEST_SIZE, (void (*)(void))md2_size },
    { 0, NULL }
};
