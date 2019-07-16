/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CORE_MKDIGEST_H
# define OSSL_CORE_MKDIGEST_H

# include <openssl/core_numbers.h>
# include <openssl/core_names.h>
# include <openssl/params.h>

# ifdef __cplusplus
extern "C" {
# endif

# define OSSL_FUNC_DIGEST_ALLOC_METHODS(name, CTX_NAME) \
static OSSL_OP_digest_newctx_fn name##_newctx; \
static OSSL_OP_digest_freectx_fn name##_freectx; \
static OSSL_OP_digest_dupctx_fn name##_dupctx; \
static void *name##_newctx(void *prov_ctx) \
{ \
    CTX_NAME *ctx = OPENSSL_zalloc(sizeof(*ctx)); \
    return ctx; \
} \
static void name##_freectx(void *vctx) \
{ \
    CTX_NAME *ctx = (CTX_NAME *)vctx; \
    OPENSSL_clear_free(ctx,  sizeof(*ctx)); \
} \
static void *name##_dupctx(void *ctx) \
{ \
    CTX_NAME *in = (CTX_NAME *)ctx; \
    CTX_NAME *ret = OPENSSL_malloc(sizeof(*ret)); \
    *ret = *in; \
    return ret; \
}

# define OSSL_FUNC_DIGEST_GET_PARAM(name, blksize, dgstsize, flags)     \
static OSSL_OP_digest_get_params_fn name##_get_params;                  \
static int name##_get_params(OSSL_PARAM params[])                       \
{                                                                       \
    OSSL_PARAM *p = NULL;                                               \
                                                                        \
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);        \
    if (p != NULL && !OSSL_PARAM_set_int(p, (blksize)))                 \
        return 0;                                                       \
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);              \
    if (p != NULL && !OSSL_PARAM_set_int(p, (dgstsize)))                \
        return 0;                                                       \
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_FLAGS);             \
    if (p != NULL && !OSSL_PARAM_set_ulong(p, (flags)))                 \
        return 0;                                                       \
    return 1;                                                           \
}

# define OSSL_FUNC_DIGEST_SET_FINAL(name, dgstsize, fin) \
static OSSL_OP_digest_final_fn name##_wrapfinal; \
static int name##_wrapfinal(void *ctx, unsigned char *out, size_t *outl, size_t outsz) \
{ \
    if (outsz >= dgstsize && fin(out, ctx)) { \
        *outl = dgstsize; \
        return 1; \
    } \
    return 0; \
}

# define OSSL_FUNC_DIGEST_COMMON(name, init, upd) \
const OSSL_DISPATCH name##_functions[] = { \
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))name##_newctx }, \
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))init }, \
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))upd }, \
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))name##_wrapfinal }, \
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))name##_freectx }, \
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))name##_dupctx }, \
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))name##_get_params },

# define OSSL_FUNC_DIGEST_CONSTRUCT_END \
    { 0, NULL } \
};

# define OSSL_FUNC_DIGEST_CONSTRUCT_START(name, CTX,                    \
                                          blksize, dgstsize, flags,     \
                                          init, upd, fin)               \
OSSL_FUNC_DIGEST_ALLOC_METHODS(name, CTX)                               \
OSSL_FUNC_DIGEST_SET_FINAL(name, dgstsize, fin)                         \
OSSL_FUNC_DIGEST_GET_PARAM(name, blksize, dgstsize, flags)              \
OSSL_FUNC_DIGEST_COMMON(name, init, upd)

# define OSSL_FUNC_DIGEST_CONSTRUCT(name, CTX, blksize, dgstsize, flags, \
                                    init, upd, fin)                     \
OSSL_FUNC_DIGEST_CONSTRUCT_START(name, CTX, blksize, dgstsize, flags,   \
                                 init, upd, fin)                        \
OSSL_FUNC_DIGEST_CONSTRUCT_END

# define OSSL_FUNC_DIGEST_CONSTRUCT_PARAMS(name, CTX,                   \
                                           blksize, dgstsize, flags,    \
                                           init, upd, fin, setparams)   \
OSSL_FUNC_DIGEST_CONSTRUCT_START(name, CTX, blksize, dgstsize, flags,   \
                                 init, upd, fin)                        \
    { OSSL_FUNC_DIGEST_CTX_SET_PARAMS, (void (*)(void))setparams },     \
OSSL_FUNC_DIGEST_CONSTRUCT_END

# ifdef __cplusplus
}
# endif

#endif /* OSSL_CORE_MKDIGEST_H */
