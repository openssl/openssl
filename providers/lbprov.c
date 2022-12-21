/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include "prov/names.h"
#include "prov/providercommon.h"
#include "prov/digestcommon.h"
#include "prov/provider_ctx.h"

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_teardown_fn lbprov_teardown;
static OSSL_FUNC_provider_gettable_params_fn lbprov_gettable_params;
static OSSL_FUNC_provider_get_params_fn lbprov_get_params;
static OSSL_FUNC_provider_query_operation_fn lbprov_query;

#define ALG(NAMES, FUNC) { NAMES, "provider=loadbalance", FUNC , "dummy implementation by lbprov" }

/* Parameters we provide to the core */
static const OSSL_PARAM lbprov_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *lbprov_gettable_params(void *provctx)
{
    return lbprov_param_types;
}

static int lbprov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "a built-in loadbalance provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "0.1"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "rc0"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
    return 1;
}

/* dummy functions
 * Actual computing should never happen in this provider itself. Actual
 * computing should be delegated to the child providers.
 *
 * Return: NULL or 0 on error
 */
static int dummy_int_ret_err(void)
{
    return 0;
}

static int dummy_int_ret_succ(void)
{
    return 1;
}

static void *dummy_ptr_ret(void)
{
    return NULL;
}

static const OSSL_DISPATCH lbprov_dummy_md5_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,  (void (*)(void))dummy_ptr_ret },
    { OSSL_FUNC_DIGEST_UPDATE,  (void (*)(void))dummy_int_ret_err },
    { OSSL_FUNC_DIGEST_FINAL,   (void (*)(void))dummy_int_ret_err },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))dummy_ptr_ret },
    { OSSL_FUNC_DIGEST_DUPCTX,  (void (*)(void))dummy_ptr_ret },
    { OSSL_FUNC_DIGEST_INIT,    (void (*)(void))dummy_int_ret_err },
    /*
     * OSSL_FUNC_DIGEST_GET_PARAMS must return 1 success.
     * Otherwise ossl_method_construct() fails at evp_md_cache_constants()
     */
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))dummy_int_ret_succ },
    { 0, NULL }
};

static const OSSL_ALGORITHM lbprov_digests[] = {
    ALG(PROV_NAMES_MD5, lbprov_dummy_md5_functions),
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM lbprov_ciphers[] = {
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM lbprov_kdfs[] = {
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *lbprov_query(void *provctx, int operation_id,
                                          int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return lbprov_digests;
    case OSSL_OP_CIPHER:
        return lbprov_ciphers;
    case OSSL_OP_KDF:
        return lbprov_kdfs;
    }
    return NULL;
}

static void lbprov_teardown(void *provctx)
{
    OSSL_LIB_CTX_free(PROV_LIBCTX_OF(provctx));
    ossl_prov_ctx_free(provctx);
}

/* The base dispatch table */
static const OSSL_DISPATCH lbprov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))lbprov_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))lbprov_query },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))lbprov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))lbprov_get_params },
    { 0, NULL }
};

typedef struct lbprov_conf_st {
    int strategy;
} LBPROV_CONF;

static LBPROV_CONF lbprov_conf;

static int lbprov_get_params_from_core(OSSL_FUNC_core_get_params_fn *c_get_params,
                                       const OSSL_CORE_HANDLE *handle)
{
    /*
    * Parameters to retrieve from the configuration
    * NOTE: inside c_get_params() these will be loaded from config items
    * stored inside prov->parameters
    */

    OSSL_PARAM core_params[2], *p = core_params;
    const char *strategy_string = "\0";
    int conf_strategy = 0;

    /* NOTE: config parameter values are always treated as string
     * refer to ossl_provider_add_parameter()
     */
    *p++ = OSSL_PARAM_construct_utf8_ptr("lb-strategy",
                                         (char **)&strategy_string,
                                         sizeof(strategy_string));
    *p = OSSL_PARAM_construct_end();

    if (!c_get_params(handle, core_params)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }

    if (strategy_string[0] != '\0')
        conf_strategy = atoi(strategy_string);
    else                /* no strategy config from core */
        return 1;

    /* validate the returned value */
    if ((conf_strategy < LB_STRATEGY_ROUND_ROBIN) || (conf_strategy >= LB_STRATEGY_MAX))
        lbprov_conf.strategy = LB_STRATEGY_ROUND_ROBIN;
    else
        lbprov_conf.strategy = conf_strategy;

    return 1;
}

OSSL_provider_init_fn ossl_lb_provider_init;

int ossl_lb_provider_init(const OSSL_CORE_HANDLE *handle,
                          const OSSL_DISPATCH *in,
                          const OSSL_DISPATCH **out,
                          void **provctx)
{
    OSSL_LIB_CTX *libctx = NULL;
    const OSSL_DISPATCH *tmp = in;
    OSSL_FUNC_provider_set_load_balancer_fn *c_set_load_balancer = NULL;
    OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_PROVIDER_SET_LOAD_BALANCER:
            c_set_load_balancer = OSSL_FUNC_provider_set_load_balancer(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    /* initialize load balance configurations */
    lbprov_conf.strategy = LB_STRATEGY_ROUND_ROBIN;

    /* get configuration from core */
    if ((c_get_params == NULL)
            || (lbprov_get_params_from_core(c_get_params, handle) == 0))
        return 0;

    /* mark self as a loadbalancer provider */
    if ((c_set_load_balancer == NULL) || (c_set_load_balancer(handle) == 0))
        return 0;

    /* create load_balancer libctx */
    if ((*provctx = ossl_prov_ctx_new()) == NULL
        || (libctx = OSSL_LIB_CTX_new_load_balancer(handle, tmp,
                                                    lbprov_conf.strategy)) == NULL) {
        OSSL_LIB_CTX_free(libctx);
        goto err;
    }

    /* set up provctx */
    ossl_prov_ctx_set0_libctx(*provctx, libctx);
    ossl_prov_ctx_set0_handle(*provctx, handle);

    *out = lbprov_dispatch_table;
    return 1;

err:
    lbprov_teardown(*provctx);
    *provctx = NULL;
    return 0;
}
