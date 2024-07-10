/*
 * Copyright 2019-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include "prov/provider_ctx.h"
#include "prov/implementations.h"
#include "prov/names.h"
#include "prov/providercommon.h"

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn jitter_gettable_params;
static OSSL_FUNC_provider_get_params_fn jitter_get_params;
static OSSL_FUNC_provider_query_operation_fn jitter_query;

/* Functions provided by the core */
static OSSL_FUNC_core_new_error_fn *c_new_error;
static OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug;
static OSSL_FUNC_core_vset_error_fn *c_vset_error;
static OSSL_FUNC_core_set_error_mark_fn *c_set_error_mark;
static OSSL_FUNC_core_clear_last_error_mark_fn *c_clear_last_error_mark;
static OSSL_FUNC_core_pop_error_to_mark_fn *c_pop_error_to_mark;

/* Parameters we provide to the core */
static const OSSL_PARAM jitter_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    /* TODO maybe expose jent_version() in buildinfo */
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *jitter_gettable_params(void *provctx)
{
    return jitter_param_types;
}

static int jitter_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Jitter Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
    return 1;
}

static const OSSL_ALGORITHM jitter_rands[] = {
    { PROV_NAMES_SEED_SRC_JITTER, "provider=jitter", ossl_jitter_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *jitter_query(void *provctx, int operation_id,
                                          int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_RAND:
        return jitter_rands;
    }
    return NULL;
}

static void jitter_teardown(void *provctx)
{
    OSSL_LIB_CTX_free(PROV_LIBCTX_OF(provctx));
    ossl_prov_ctx_free(provctx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH jitter_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))jitter_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
      (void (*)(void))jitter_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))jitter_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))jitter_query },
    OSSL_DISPATCH_END
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    OSSL_LIB_CTX *libctx = NULL;
    const OSSL_DISPATCH *tmp;

    for (tmp = in; tmp->function_id != 0; tmp++) {
        /*
         * We do not support the scenario of an application linked against
         * multiple versions of libcrypto (e.g. one static and one dynamic),
         * but sharing a single jitter.so. We do a simple sanity check here.
         */
#define set_func(c, f) if (c == NULL) c = f; else if (c != f) return 0;
        switch (tmp->function_id) {
        case OSSL_FUNC_CORE_NEW_ERROR:
            set_func(c_new_error, OSSL_FUNC_core_new_error(tmp));
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            set_func(c_set_error_debug, OSSL_FUNC_core_set_error_debug(tmp));
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            set_func(c_vset_error, OSSL_FUNC_core_vset_error(tmp));
            break;
        case OSSL_FUNC_CORE_SET_ERROR_MARK:
            set_func(c_set_error_mark, OSSL_FUNC_core_set_error_mark(tmp));
            break;
        case OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK:
            set_func(c_clear_last_error_mark,
                     OSSL_FUNC_core_clear_last_error_mark(tmp));
            break;
        case OSSL_FUNC_CORE_POP_ERROR_TO_MARK:
            set_func(c_pop_error_to_mark,
                     OSSL_FUNC_core_pop_error_to_mark(tmp));
            break;
        }
    }

    if ((*provctx = ossl_prov_ctx_new()) == NULL
        || (libctx = OSSL_LIB_CTX_new_child(handle, in)) == NULL) {
        OSSL_LIB_CTX_free(libctx);
        jitter_teardown(*provctx);
        *provctx = NULL;
        return 0;
    }
    ossl_prov_ctx_set0_libctx(*provctx, libctx);
    ossl_prov_ctx_set0_handle(*provctx, handle);

    *out = jitter_dispatch_table;

    return 1;
}

/*
 * Provider specific implementation of libcrypto functions in terms of
 * upcalls.
 */

/*
 * For ERR functions, we pass a NULL context.  This is valid to do as long
 * as only error codes that the calling libcrypto supports are used.
 */
void ERR_new(void)
{
    c_new_error(NULL);
}

void ERR_set_debug(const char *file, int line, const char *func)
{
    c_set_error_debug(NULL, file, line, func);
}

void ERR_set_error(int lib, int reason, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    c_vset_error(NULL, ERR_PACK(lib, 0, reason), fmt, args);
    va_end(args);
}

void ERR_vset_error(int lib, int reason, const char *fmt, va_list args)
{
    c_vset_error(NULL, ERR_PACK(lib, 0, reason), fmt, args);
}

int ERR_set_mark(void)
{
    return c_set_error_mark(NULL);
}

int ERR_clear_last_mark(void)
{
    return c_clear_last_error_mark(NULL);
}

int ERR_pop_to_mark(void)
{
    return c_pop_error_to_mark(NULL);
}
