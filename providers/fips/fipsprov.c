/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* XXX MOVE THIS TO A COMMON HEADER */
typedef void *(*CRYPTO_malloc_fn)(size_t num, const char *file, int line);
typedef void *(*CRYPTO_zalloc_fn)(size_t num, const char *file, int line);
typedef void *(*CRYPTO_realloc_fn)(void *str, size_t num, const char *file, int line);
typedef void *(*CRYPTO_clear_realloc_fn)(void *str, size_t old_len, size_t num, const char *file, int line);
typedef void (*CRYPTO_free_fn)(void *str, const char *file, int line);
typedef void (*CRYPTO_clear_free_fn)(void *str, size_t num, const char *file, int line);

typedef void* (*CRYPTO_secure_malloc_fn)(size_t num, const char *file, int line);
typedef void* (*CRYPTO_secure_zalloc_fn)(size_t num, const char *file, int line);
typedef void (*CRYPTO_secure_free_fn)(void *ptr, const char *file, int line);
typedef void (*CRYPTO_secure_clear_free_fn)(void *ptr, size_t num, const char *file, int line);
typedef int (*CRYPTO_secure_malloc_initialized_fn)(void);

/* Functions provided by the core */
static OSSL_core_get_param_types_fn *c_get_param_types = NULL;
static OSSL_core_get_params_fn *c_get_params = NULL;
static OSSL_core_get_exdata_index_fn *c_get_exdata_index = NULL;
static CRYPTO_malloc_fn *c_CRYPTO_malloc = NULL;
static CRYPTO_zalloc_fn *c_CRYPTO_zalloc = NULL;
static CRYPTO_realloc_fn *c_CRYPTO_realloc = NULL;
static CRYPTO_clear_realloc_fn *c_CRYPTO_clear_realloc = NULL;
static CRYPTO_free_fn *c_CRYPTO_free = NULL;
static CRYPTO_clear_free_fn *c_CRYPTO_clear_free = NULL;
static CRYPTO_secure_malloc_fn *c_CRYPTO_secure_malloc = NULL;
static CRYPTO_secure_zalloc_fn *c_CRYPTO_secure_zalloc = NULL;
static CRYPTO_secure_free_fn *c_CRYPTO_secure_free = NULL;
static CRYPTO_secure_clear_free_fn *c_CRYPTO_secure_clear_free = NULL;
static CRYPTO_secure_malloc_initialized_fn *c_CRYPTO_secure_malloc_initialized = NULL;


/* Parameters we provide to the core */
static const OSSL_ITEM fips_param_types[] = {
    { OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_NAME },
    { OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_VERSION },
    { OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_BUILDINFO },
    { 0, NULL }
};

static const OSSL_ITEM *fips_get_param_types(const OSSL_PROVIDER *prov)
{
    return fips_param_types;
}

static int fips_get_params(const OSSL_PROVIDER *prov,
                            const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL FIPS Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;

    return 1;
}

extern const OSSL_DISPATCH sha256_functions[];

static const OSSL_ALGORITHM fips_digests[] = {
    { "SHA256", "fips=yes", sha256_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *fips_query(OSSL_PROVIDER *prov,
                                         int operation_id,
                                         int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return fips_digests;
    }
    return NULL;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH fips_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GET_PARAM_TYPES, (void (*)(void))fips_get_param_types },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))fips_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fips_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_PROVIDER *provider,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_PARAM_TYPES:
            c_get_param_types = OSSL_get_core_get_param_types(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_get_core_get_params(in);
            break;
        case OSSL_FUNC_PROVIDER_EXDATA_NEW:
            c_get_exdata_index = OSSL_get_core_get_exdata_index(in);
            break;
        /* Just ignore anything we don't understand */
        default:
            break;
        }
    }

    *out = fips_dispatch_table;
    return 1;
}

/*
 * SHIM routines that just callback to the core.
 */

int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
                            CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
                            CRYPTO_EX_free *free_func)
{
    return (*c_get_exdata_index)(class_index, argl, argp,
                                 new_func, dup_func, free_func);
}

void *CRYPTO_malloc(size_t num, const char *file, int line)
{
    return (*c_CRYPTO_malloc)(num, file, line);
}

void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    return (*c_CRYPTO_zalloc)(num, file, line);
}

void *CRYPTO_realloc(void *str, size_t num, const char *file, int line)
{
    return (*c_CRYPTO_realloc)(str, num, file, line);
}

void *CRYPTO_clear_realloc(void *str, size_t old_len, size_t num,
                           const char *file, int line)
{
    return (*c_CRYPTO_clear_realloc)(str, old_len, num, file, line);
}

void CRYPTO_free(void *str, const char *file, int line)
{
    (*c_CRYPTO_free)(str, file, line);
}

void CRYPTO_clear_free(void *str, size_t num, const char *file, int line)
{
    (*c_CRYPTO_clear_free)(str, num, file, line);
}

void *CRYPTO_secure_malloc(size_t num, const char *file, int line)
{
    return (*c_CRYPTO_secure_malloc)(num, file, line);
}

void *CRYPTO_secure_zalloc(size_t num, const char *file, int line)
{
    return (*c_CRYPTO_secure_zalloc)(num, file, line);
}

void CRYPTO_secure_free(void *ptr, const char *file, int line)
{
    (*c_CRYPTO_secure_free)(ptr, file, line);
}

void CRYPTO_secure_clear_free(void *ptr, size_t num,
                              const char *file, int line)
{
    (*c_CRYPTO_secure_clear_free)(ptr, num, file, line);
}

int CRYPTO_secure_malloc_initialized(void)
{
    return (*c_CRYPTO_secure_malloc_initialized)();
}
