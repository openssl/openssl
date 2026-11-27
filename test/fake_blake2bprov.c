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
#include <openssl/evp.h>
#include <openssl/params.h>
#include "fake_blake2bprov.h"

#define FAKE_BLAKE2B_SIZE 64
#define FAKE_BLAKE2B_BLOCK_SIZE 128

typedef struct {
    EVP_MD_CTX *mdctx;
    int failing;
} FAKE_BLAKE2B_CTX;

/* The real digest, from a library context of the provider's own */
static EVP_MD *fake_blake2b_md(void *provctx)
{
    return EVP_MD_fetch((OSSL_LIB_CTX *)provctx, "BLAKE2B-512", NULL);
}

static void *fake_blake2b_newctx(void *provctx, int failing)
{
    FAKE_BLAKE2B_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    EVP_MD *md = fake_blake2b_md(provctx);

    if (ctx == NULL || md == NULL
        || (ctx->mdctx = EVP_MD_CTX_new()) == NULL
        || !EVP_DigestInit_ex2(ctx->mdctx, md, NULL)) {
        EVP_MD_free(md);
        if (ctx != NULL)
            EVP_MD_CTX_free(ctx->mdctx);
        OPENSSL_free(ctx);
        return NULL;
    }
    EVP_MD_free(md);
    ctx->failing = failing;
    return ctx;
}

static void *fake_blake2b_fixed_newctx(void *provctx)
{
    return fake_blake2b_newctx(provctx, 0);
}

static void *fake_blake2b_failing_newctx(void *provctx)
{
    return fake_blake2b_newctx(provctx, 1);
}

static void fake_blake2b_freectx(void *vctx)
{
    FAKE_BLAKE2B_CTX *ctx = vctx;

    if (ctx != NULL)
        EVP_MD_CTX_free(ctx->mdctx);
    OPENSSL_free(ctx);
}

static int fake_blake2b_init(void *vctx, const OSSL_PARAM params[])
{
    FAKE_BLAKE2B_CTX *ctx = vctx;
    const OSSL_PARAM *p;
    size_t size;

    p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SIZE);
    if (ctx->failing && p != NULL
        && (!OSSL_PARAM_get_size_t(p, &size) || size != FAKE_BLAKE2B_SIZE))
        return 0;
    /* Otherwise unknown parameters are ignored, as providers are expected to */
    return EVP_DigestInit_ex2(ctx->mdctx, NULL, NULL);
}

static int fake_blake2b_update(void *vctx, const unsigned char *in, size_t inl)
{
    return EVP_DigestUpdate(((FAKE_BLAKE2B_CTX *)vctx)->mdctx, in, inl);
}

static int fake_blake2b_final(void *vctx, unsigned char *out, size_t *outl,
    size_t outsz)
{
    unsigned char md[FAKE_BLAKE2B_SIZE];

    if (outsz < FAKE_BLAKE2B_SIZE
        || !EVP_DigestFinal_ex(((FAKE_BLAKE2B_CTX *)vctx)->mdctx, md, NULL))
        return 0;
    memcpy(out, md, sizeof(md));
    *outl = sizeof(md);
    return 1;
}

static int fake_blake2b_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, FAKE_BLAKE2B_SIZE))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, FAKE_BLAKE2B_BLOCK_SIZE))
        return 0;
    return 1;
}

static const OSSL_PARAM *fake_blake2b_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettables[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_END
    };

    return gettables;
}

static const OSSL_DISPATCH fake_blake2b_fixed_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))fake_blake2b_fixed_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))fake_blake2b_freectx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))fake_blake2b_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))fake_blake2b_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))fake_blake2b_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))fake_blake2b_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,
        (void (*)(void))fake_blake2b_gettable_params },
    OSSL_DISPATCH_END
};

static const OSSL_DISPATCH fake_blake2b_failing_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))fake_blake2b_failing_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))fake_blake2b_freectx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))fake_blake2b_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))fake_blake2b_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))fake_blake2b_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))fake_blake2b_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,
        (void (*)(void))fake_blake2b_gettable_params },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM fake_blake2b_digests[] = {
    { "BLAKE2B-512:BLAKE2b512", "provider=fake-blake2b,fake.blake2b=fixed",
        fake_blake2b_fixed_functions, "BLAKE2b-512 without size parameter" },
    { "BLAKE2B-512:BLAKE2b512", "provider=fake-blake2b,fake.blake2b=failing",
        fake_blake2b_failing_functions, "BLAKE2b-512 rejecting other sizes" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *fake_blake2b_query(void *provctx,
    int operation_id,
    int *no_cache)
{
    *no_cache = 0;
    return operation_id == OSSL_OP_DIGEST ? fake_blake2b_digests : NULL;
}

static void fake_blake2b_teardown(void *provctx)
{
    OSSL_LIB_CTX_free((OSSL_LIB_CTX *)provctx);
}

static const OSSL_DISPATCH fake_blake2b_method[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))fake_blake2b_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fake_blake2b_query },
    OSSL_DISPATCH_END
};

static int fake_blake2b_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out, void **provctx)
{
    if ((*provctx = OSSL_LIB_CTX_new()) == NULL)
        return 0;
    *out = fake_blake2b_method;
    return 1;
}

OSSL_PROVIDER *fake_blake2b_start(OSSL_LIB_CTX *libctx)
{
    if (!OSSL_PROVIDER_add_builtin(libctx, FAKE_BLAKE2B_PROV_NAME,
            fake_blake2b_provider_init))
        return NULL;
    return OSSL_PROVIDER_try_load(libctx, FAKE_BLAKE2B_PROV_NAME, 1);
}

void fake_blake2b_finish(OSSL_PROVIDER *p)
{
    OSSL_PROVIDER_unload(p);
}
