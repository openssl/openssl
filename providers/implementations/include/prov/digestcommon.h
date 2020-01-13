/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_PROVIDERS_DIGESTCOMMON_H
# define Otls_PROVIDERS_DIGESTCOMMON_H

# include <opentls/core_numbers.h>
# include <opentls/core_names.h>
# include <opentls/params.h>

# ifdef __cplusplus
extern "C" {
# endif

#define PROV_FUNC_DIGEST_GET_PARAM(name, blksize, dgstsize, flags)             \
static Otls_OP_digest_get_params_fn name##_get_params;                         \
static int name##_get_params(Otls_PARAM params[])                              \
{                                                                              \
    return digest_default_get_params(params, blksize, dgstsize, flags);        \
}

#define PROV_DISPATCH_FUNC_DIGEST_GET_PARAMS(name)                             \
{ Otls_FUNC_DIGEST_GET_PARAMS, (void (*)(void))name##_get_params },            \
{ Otls_FUNC_DIGEST_GETTABLE_PARAMS,                                            \
  (void (*)(void))digest_default_gettable_params }

# define PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_START(                            \
    name, CTX, blksize, dgstsize, flags, init, upd, fin)                       \
static Otls_OP_digest_newctx_fn name##_newctx;                                 \
static Otls_OP_digest_freectx_fn name##_freectx;                               \
static Otls_OP_digest_dupctx_fn name##_dupctx;                                 \
static void *name##_newctx(void *prov_ctx)                                     \
{                                                                              \
    CTX *ctx = OPENtls_zalloc(sizeof(*ctx));                                   \
    return ctx;                                                                \
}                                                                              \
static void name##_freectx(void *vctx)                                         \
{                                                                              \
    CTX *ctx = (CTX *)vctx;                                                    \
    OPENtls_clear_free(ctx,  sizeof(*ctx));                                    \
}                                                                              \
static void *name##_dupctx(void *ctx)                                          \
{                                                                              \
    CTX *in = (CTX *)ctx;                                                      \
    CTX *ret = OPENtls_malloc(sizeof(*ret));                                   \
    if (ret != NULL)                                                           \
        *ret = *in;                                                            \
    return ret;                                                                \
}                                                                              \
static Otls_OP_digest_final_fn name##_internal_final;                          \
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
const Otls_DISPATCH name##_functions[] = {                                     \
    { Otls_FUNC_DIGEST_NEWCTX, (void (*)(void))name##_newctx },                \
    { Otls_FUNC_DIGEST_INIT, (void (*)(void))init },                           \
    { Otls_FUNC_DIGEST_UPDATE, (void (*)(void))upd },                          \
    { Otls_FUNC_DIGEST_FINAL, (void (*)(void))name##_internal_final },         \
    { Otls_FUNC_DIGEST_FREECTX, (void (*)(void))name##_freectx },              \
    { Otls_FUNC_DIGEST_DUPCTX, (void (*)(void))name##_dupctx },                \
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
{ Otls_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (void (*)(void))settable_ctx_params }, \
{ Otls_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void))set_ctx_params },           \
PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_END


const Otls_PARAM *digest_default_gettable_params(void);
int digest_default_get_params(Otls_PARAM params[], size_t blksz, size_t paramsz,
                              unsigned long flags);

# ifdef __cplusplus
}
# endif

#endif /* Otls_PROVIDERS_DIGESTCOMMON_H */
