/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PROVIDERS_DIGESTCOMMON_H
# define OSSL_PROVIDERS_DIGESTCOMMON_H

# include <openssl/core_numbers.h>
# include <openssl/core_names.h>
# include <openssl/params.h>

# ifdef __cplusplus
extern "C" {
# endif

#define PROV_FUNC_DIGEST_GET_PARAM(name, blksize, dgstsize, flags)             \
static OSSL_OP_digest_get_params_fn name##_get_params;                         \
static int name##_get_params(OSSL_PARAM params[])                              \
{                                                                              \
    return digest_default_get_params(params, blksize, dgstsize, flags);        \
}

#define PROV_DISPATCH_FUNC_DIGEST_GET_PARAMS(name)                             \
{ OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))name##_get_params },            \
{ OSSL_FUNC_DIGEST_GETTABLE_PARAMS,                                            \
  (void (*)(void))digest_default_gettable_params }

# define PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_START(                            \
    name, CTX, blksize, dgstsize, flags, init, upd, fin)                       \
static OSSL_OP_digest_newctx_fn name##_newctx;                                 \
static OSSL_OP_digest_freectx_fn name##_freectx;                               \
static OSSL_OP_digest_dupctx_fn name##_dupctx;                                 \
static void *name##_newctx(void *prov_ctx)                                     \
{                                                                              \
    CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));                                   \
    return ctx;                                                                \
}                                                                              \
static void name##_freectx(void *vctx)                                         \
{                                                                              \
    CTX *ctx = (CTX *)vctx;                                                    \
    OPENSSL_clear_free(ctx,  sizeof(*ctx));                                    \
}                                                                              \
static void *name##_dupctx(void *ctx)                                          \
{                                                                              \
    CTX *in = (CTX *)ctx;                                                      \
    CTX *ret = OPENSSL_malloc(sizeof(*ret));                                   \
    *ret = *in;                                                                \
    return ret;                                                                \
}                                                                              \
static OSSL_OP_digest_final_fn name##_internal_final;                          \
static int name##_internal_final(void *ctx, unsigned char *out, size_t *outl,  \
                                 size_t outsz)                                 \
{                                                                              \
    if (outsz >= dgstsize && fin(out, ctx)) {                                  \
        *outl = dgstsize;                                                      \
        return 1;                                                              \
    }                                                                          \
    return 0;                                                                  \
}                                                                              \
PROV_FUNC_DIGEST_GET_PARAM(name, blksize, dgstsize, flags)                     \
const OSSL_DISPATCH name##_functions[] = {                                     \
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))name##_newctx },                \
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))init },                           \
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))upd },                          \
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))name##_internal_final },         \
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))name##_freectx },              \
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))name##_dupctx },                \
    PROV_DISPATCH_FUNC_DIGEST_GET_PARAMS(name)

# define PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_END                               \
    { 0, NULL }                                                                \
};

# define IMPLEMENT_digest_functions(                                           \
    name, CTX, blksize, dgstsize, flags, init, upd, fin)                       \
PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_START(name, CTX, blksize, dgstsize, flags, \
                                          init, upd, fin),                     \
PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_END

# define IMPLEMENT_digest_functions_with_settable_ctx(                         \
    name, CTX, blksize, dgstsize, flags, init, upd, fin,                       \
    settable_ctx_params, set_ctx_params)                                       \
PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_START(name, CTX, blksize, dgstsize, flags, \
                                          init, upd, fin),                     \
{ OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (void (*)(void))settable_ctx_params }, \
{ OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void))set_ctx_params },           \
PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_END


const OSSL_PARAM *digest_default_gettable_params(void);
int digest_default_get_params(OSSL_PARAM params[], size_t blksz, size_t paramsz,
                              unsigned long flags);

# ifdef __cplusplus
}
# endif

#endif /* OSSL_PROVIDERS_DIGESTCOMMON_H */
