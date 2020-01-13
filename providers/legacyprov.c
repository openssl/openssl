/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <opentls/core.h>
#include <opentls/core_numbers.h>
#include <opentls/core_names.h>
#include <opentls/params.h>
#include "prov/implementations.h"

#ifdef STATIC_LEGACY
Otls_provider_init_fn otls_legacy_provider_init;
# define Otls_provider_init otls_legacy_provider_init
#endif

/* Functions provided by the core */
static Otls_core_gettable_params_fn *c_gettable_params = NULL;
static Otls_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const Otls_ITEM legacy_param_types[] = {
    { Otls_PARAM_UTF8_PTR, Otls_PROV_PARAM_NAME },
    { Otls_PARAM_UTF8_PTR, Otls_PROV_PARAM_VERSION },
    { Otls_PARAM_UTF8_PTR, Otls_PROV_PARAM_BUILDINFO },
    { 0, NULL }
};

static const Otls_ITEM *legacy_gettable_params(const Otls_PROVIDER *prov)
{
    return legacy_param_types;
}

static int legacy_get_params(const Otls_PROVIDER *prov, Otls_PARAM params[])
{
    Otls_PARAM *p;

    p = Otls_PARAM_locate(params, Otls_PROV_PARAM_NAME);
    if (p != NULL && !Otls_PARAM_set_utf8_ptr(p, "Opentls Legacy Provider"))
        return 0;
    p = Otls_PARAM_locate(params, Otls_PROV_PARAM_VERSION);
    if (p != NULL && !Otls_PARAM_set_utf8_ptr(p, OPENtls_VERSION_STR))
        return 0;
    p = Otls_PARAM_locate(params, Otls_PROV_PARAM_BUILDINFO);
    if (p != NULL && !Otls_PARAM_set_utf8_ptr(p, OPENtls_FULL_VERSION_STR))
        return 0;

    return 1;
}

static const Otls_ALGORITHM legacy_digests[] = {
#ifndef OPENtls_NO_MD2
    { "MD2", "legacy=yes", md2_functions },
#endif

#ifndef OPENtls_NO_MD4
    { "MD4", "legacy=yes", md4_functions },
#endif

#ifndef OPENtls_NO_MDC2
    { "MDC2", "legacy=yes", mdc2_functions },
#endif /* OPENtls_NO_MDC2 */

#ifndef OPENtls_NO_WHIRLPOOL
    { "WHIRLPOOL", "legacy=yes", wp_functions },
#endif /* OPENtls_NO_WHIRLPOOL */

#ifndef OPENtls_NO_RMD160
    { "RIPEMD-160:RIPEMD160:RIPEMD:RMD160", "legacy=yes", ripemd160_functions },
#endif /* OPENtls_NO_RMD160 */

    { NULL, NULL, NULL }
};

static const Otls_ALGORITHM *legacy_query(Otls_PROVIDER *prov,
                                          int operation_id,
                                          int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case Otls_OP_DIGEST:
        return legacy_digests;
    }
    return NULL;
}

/* Functions we provide to the core */
static const Otls_DISPATCH legacy_dispatch_table[] = {
    { Otls_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))legacy_gettable_params },
    { Otls_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))legacy_get_params },
    { Otls_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))legacy_query },
    { 0, NULL }
};

int Otls_provider_init(const Otls_PROVIDER *provider,
                       const Otls_DISPATCH *in,
                       const Otls_DISPATCH **out,
                       void **provctx)
{
    Otls_core_get_library_context_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case Otls_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = Otls_get_core_gettable_params(in);
            break;
        case Otls_FUNC_CORE_GET_PARAMS:
            c_get_params = Otls_get_core_get_params(in);
            break;
        case Otls_FUNC_CORE_GET_LIBRARY_CONTEXT:
            c_get_libctx = Otls_get_core_get_library_context(in);
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
