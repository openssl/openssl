/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal EVP utility functions */

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/asn1.h>        /* evp_local.h needs it */
#include <openssl/safestack.h>   /* evp_local.h needs it */
#include <openssl/x509.h>
#include "internal/sizes.h"
#include "crypto/evp.h"    /* evp_local.h needs it */
#include "evp_local.h"

/*
 * EVP_CTRL_RET_UNSUPPORTED = -1 is the returned value from any ctrl function
 * where the control command isn't supported, and an alternative code path
 * may be chosen.
 * Since these functions are used to implement ctrl functionality, we
 * use the same value, and other callers will have to compensate.
 */
#define PARAM_CHECK(obj, func, errfunc)                                        \
    if (obj == NULL)                                                           \
        return 0;                                                              \
    if (obj->prov == NULL)                                                     \
        return EVP_CTRL_RET_UNSUPPORTED;                                       \
    if (obj->func == NULL) {                                                   \
        errfunc();                                                             \
        return 0;                                                              \
    }

#define PARAM_FUNC(name, func, type, err)                                      \
int name (const type *obj, OSSL_PARAM params[])                                \
{                                                                              \
    PARAM_CHECK(obj, func, err)                                                \
    return obj->func(params);                                                  \
}

#define PARAM_CTX_FUNC(name, func, type, err)                                  \
int name (const type *obj, void *provctx, OSSL_PARAM params[])                 \
{                                                                              \
    PARAM_CHECK(obj, func, err)                                                \
    return obj->func(provctx, params);                                         \
}

#define PARAM_FUNCTIONS(type,                                                  \
                        getname, getfunc,                                      \
                        getctxname, getctxfunc,                                \
                        setctxname, setctxfunc)                                \
    PARAM_FUNC(getname, getfunc, type, geterr)                                 \
    PARAM_CTX_FUNC(getctxname, getctxfunc, type, geterr)                       \
    PARAM_CTX_FUNC(setctxname, setctxfunc, type, seterr)

/*
 * These error functions are a workaround for the error scripts, which
 * currently require that XXXerr method appears inside a function (not a macro).
 */
static void geterr(void)
{
    EVPerr(0, EVP_R_CANNOT_GET_PARAMETERS);
}

static void seterr(void)
{
    EVPerr(0, EVP_R_CANNOT_SET_PARAMETERS);
}

PARAM_FUNCTIONS(EVP_CIPHER,
                evp_do_ciph_getparams, get_params,
                evp_do_ciph_ctx_getparams, get_ctx_params,
                evp_do_ciph_ctx_setparams, set_ctx_params)

PARAM_FUNCTIONS(EVP_MD,
                evp_do_md_getparams, get_params,
                evp_do_md_ctx_getparams, get_ctx_params,
                evp_do_md_ctx_setparams, set_ctx_params)


#ifndef FIPS_MODE
static X509_ALGOR *evp_generic_get_algid(const char *keyname,
                                         int (*get_params)(const void *thing,
                                                           OSSL_PARAM params[]),
                                         const void *thing)
{
    unsigned char aid[OSSL_MAX_ALGORITHM_ID_SIZE] = "";
    const unsigned char *p = aid; /* for d2i_X509_ALGOR */
    size_t aid_len = 0;
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] = OSSL_PARAM_construct_octet_string(keyname, aid, sizeof(aid));
    /* Magic value to indicate that the value is untouched.  Wrapping is ok */
    params[0].return_size = sizeof(aid) + 1;

    if (!get_params(thing, params))
        return NULL;

    if ((aid_len = params[0].return_size) == sizeof(aid) + 1) {
        ERR_raise(ERR_LIB_EVP, EVP_R_ALGORITHM_IDENTIFIER_NOT_SUPPORTED);
        return NULL;
    }
    return d2i_X509_ALGOR(NULL, &p, params[0].return_size);
}

static int evp_md_ctx_get_params_int(const void *ctx, OSSL_PARAM params[])
{
    return EVP_MD_CTX_get_params((void *)ctx, params);
}

X509_ALGOR *evp_md_ctx_get_algid(const EVP_MD_CTX *ctx, const char *name)
{
    return evp_generic_get_algid(name, evp_md_ctx_get_params_int, ctx);
}

static int evp_md_get_params_int(const void *md, OSSL_PARAM params[])
{
    return EVP_MD_get_params(md, params);
}

X509_ALGOR *evp_md_get_algid(const EVP_MD *md, const char *name)
{
    return evp_generic_get_algid(name, evp_md_get_params_int, md);
}

static int evp_cipher_ctx_get_params_int(const void *ctx, OSSL_PARAM params[])
{
    return EVP_CIPHER_CTX_get_params((void *)ctx, params);
}

X509_ALGOR *evp_cipher_ctx_get_algid(const EVP_CIPHER_CTX *ctx,
                                     const char *name)
{
    return evp_generic_get_algid(name, evp_cipher_ctx_get_params_int, ctx);
}

static int evp_cipher_get_params_int(const void *cipher, OSSL_PARAM params[])
{
    return EVP_CIPHER_get_params((void *)cipher, params);
}

X509_ALGOR *evp_cipher_get_algid(const EVP_CIPHER *cipher, const char *name)
{
    return evp_generic_get_algid(name, evp_cipher_get_params_int, cipher);
}

static int evp_pkey_ctx_get_params_int(const void *ctx, OSSL_PARAM params[])
{
    return EVP_PKEY_CTX_get_params((void *)ctx, params);
}

X509_ALGOR *evp_pkey_ctx_get_algid(const EVP_PKEY_CTX *ctx, const char *name)
{
    return evp_generic_get_algid(name, evp_pkey_ctx_get_params_int, ctx);
}

static int evp_pkey_get_params_int(const void *pkey, OSSL_PARAM params[])
{
    return EVP_PKEY_get_params((void *)pkey, params);
}

X509_ALGOR *evp_pkey_get_algid(const EVP_PKEY *pkey, const char *name)
{
    return evp_generic_get_algid(name, evp_pkey_get_params_int, pkey);
}
#endif  /* !FIPS */
