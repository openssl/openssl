/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include <openssl/serializer.h>
#include "serializer_local.h"

int OSSL_SERIALIZER_CTX_set0_object(OSSL_SERIALIZER_CTX *ctx,
                                    const void *object)
{
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    ctx->object = object;
    return 1;
}

const void *OSSL_SERIALIZER_CTX_get0_object(OSSL_SERIALIZER_CTX *ctx)
{
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return ctx->object;
}

int OSSL_SERIALIZER_CTX_set_do_output(OSSL_SERIALIZER_CTX *ctx,
                                      int (*do_output)(OSSL_SERIALIZER_CTX *ctx,
                                                       BIO *out))
{
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    ctx->do_output = do_output;
    return 1;
}

int OSSL_SERIALIZER_to_bio(OSSL_SERIALIZER_CTX *ctx, BIO *out)
{
    return ctx->do_output(ctx, out);
}

#ifndef OPENSSL_NO_STDIO
static BIO *bio_from_file(FILE *fp)
{
    BIO *b;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_BUF_LIB);
        return NULL;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    return b;
}

int OSSL_SERIALIZER_to_fp(OSSL_SERIALIZER_CTX *ctx, FILE *fp)
{
    BIO *b = bio_from_file(fp);
    int ret = 0;

    if (b != NULL)
        ret = OSSL_SERIALIZER_to_bio(ctx, b);

    BIO_free(b);
    return ret;
}
#endif
