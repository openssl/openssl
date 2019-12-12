/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/core_numbers.h>
#include <openssl/evperr.h>
#include <openssl/err.h>
#include "prov/provider_ctx.h"
#include "prov/providercommonerr.h"
#include "prov/implementations.h"
#include "prov/provider_util.h"

static OSSL_OP_rand_newctx_fn seed_rand_new;
static OSSL_OP_rand_freectx_fn seed_rand_free;
static OSSL_OP_rand_generate_fn seed_rand_generate;
static OSSL_OP_rand_gettable_params_fn seed_rand_gettable_params;
static OSSL_OP_rand_get_params_fn seed_rand_get_params;

typedef struct {
    void *provctx;
    unsigned long long int n;
} SEED_RAND;

static void *seed_rand_new(void *provctx, int secure, int df)
{
    SEED_RAND *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    else
        ctx->provctx = provctx;
    return ctx;
}

static void seed_rand_free(void *vctx)
{
    SEED_RAND *ctx = (SEED_RAND *)vctx;

    OPENSSL_free(ctx);
}

static int seed_rand_generate(void *vctx,
                              unsigned char *out, size_t outlen,
                              const unsigned char *adin, size_t adin_len)
{
    SEED_RAND *ctx = vctx;
    unsigned char *p = out;
    size_t n;

    while (outlen > 0) {
        ++ctx->n;
        n = sizeof(ctx->n) > outlen ? outlen : sizeof(ctx->n);
        if (n > outlen)
            n = outlen;
        memcpy(p, &ctx->n, n);   /* endian issue here */
        outlen -= n;
        p += n;
    }
    return 1;
}

static int seed_rand_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH)) != NULL)
        return OSSL_PARAM_set_uint(p, UINT_MAX);
    return -2;
}

static const OSSL_PARAM *seed_rand_gettable_params(void)
{
    static const OSSL_PARAM known_gettable_params[] = {
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_params;
}

const OSSL_DISPATCH seed_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void(*)(void))seed_rand_new },
    { OSSL_FUNC_RAND_FREECTX, (void(*)(void))seed_rand_free },
    { OSSL_FUNC_RAND_GENERATE, (void(*)(void))seed_rand_generate },
    { OSSL_FUNC_RAND_GETTABLE_PARAMS,
      (void(*)(void))seed_rand_gettable_params },
    { OSSL_FUNC_RAND_GET_PARAMS, (void(*)(void))seed_rand_get_params },
    { 0, NULL }
};
