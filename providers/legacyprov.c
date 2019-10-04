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
#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "prov/implementations.h"

#ifdef STATIC_LEGACY
OSSL_provider_init_fn ossl_legacy_provider_init;
# define OSSL_provider_init ossl_legacy_provider_init
#endif

/* Functions provided by the core */
static OSSL_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_ITEM legacy_param_types[] = {
    { OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_NAME },
    { OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_VERSION },
    { OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_BUILDINFO },
    { 0, NULL }
};

static const OSSL_ITEM *legacy_gettable_params(const OSSL_PROVIDER *prov)
{
    return legacy_param_types;
}

static int legacy_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Legacy Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;

    return 1;
}

static const OSSL_ALGORITHM legacy_digests[] = {
#ifndef OPENSSL_NO_MD2
    { "MD2", "legacy=yes", md2_functions },
#endif

#ifndef OPENSSL_NO_MD4
    { "MD4", "legacy=yes", md4_functions },
#endif

#ifndef OPENSSL_NO_MDC2
    { "MDC2", "legacy=yes", mdc2_functions },
#endif /* OPENSSL_NO_MDC2 */

#ifndef OPENSSL_NO_WHIRLPOOL
    { "whirlpool", "legacy=yes", wp_functions },
#endif /* OPENSSL_NO_WHIRLPOOL */

#ifndef OPENSSL_NO_RMD160
    { "RIPEMD160:RIPEMD:RMD160", "legacy=yes", ripemd160_functions },
#endif /* OPENSSL_NO_RMD160 */

    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *legacy_query(OSSL_PROVIDER *prov,
                                          int operation_id,
                                          int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return legacy_digests;
    }
    return NULL;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH legacy_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))legacy_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))legacy_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))legacy_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_PROVIDER *provider,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    OSSL_core_get_library_context_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_get_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_get_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBRARY_CONTEXT:
            c_get_libctx = OSSL_get_core_get_library_context(in);
            break;
        /* Just ignore anything we don't understand */
        default:
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    *out = legacy_dispatch_table;

    /*
     * We want to make sure that all calls from this provider that requires
     * a library context use the same context as the one used to call our
     * functions.  We do that by passing it along as the provider context.
     */
    *provctx = c_get_libctx(provider);
    return 1;
}
