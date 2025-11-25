/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * DSMIL Policy Provider for OpenSSL
 *
 * This provider enforces security profiles (WORLD_COMPAT, DSMIL_SECURE, ATOMAL)
 * and emits telemetry events for DEFRAMEWORK integration.
 *
 * See: OPENSSL_SECURE_SPEC.md Section 5 (Provider Architecture)
 *      IMPLEMENTATION_PLAN.md Phase 2
 */

#include <string.h>
#include <stdio.h>
#include <openssl/opensslconf.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "policy.h"

/*
 * Forward declarations
 */
static OSSL_FUNC_provider_gettable_params_fn dsmil_gettable_params;
static OSSL_FUNC_provider_get_params_fn dsmil_get_params;
static OSSL_FUNC_provider_query_operation_fn dsmil_query;
static OSSL_FUNC_provider_teardown_fn dsmil_teardown;

/* Core functions */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

/* Provider context */
typedef struct dsmil_prov_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    DSMIL_POLICY_CTX *policy_ctx;
    /* Event telemetry will be added in Phase 3 */
    /* EVENT_CTX *event_ctx; */
} DSMIL_PROV_CTX;

/* Parameters we provide to the core */
static const OSSL_PARAM dsmil_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *dsmil_gettable_params(void *provctx)
{
    return dsmil_param_types;
}

static int dsmil_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL
            && !OSSL_PARAM_set_utf8_ptr(p, "DSMIL Policy Provider"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))  /* Always running */
        return 0;

    return 1;
}

/*
 * Algorithm query function
 *
 * This provider doesn't implement crypto algorithms; it enforces policy.
 * It operates by intercepting property queries and modifying/blocking
 * algorithm selection based on the active security profile.
 *
 * TODO (Phase 2): Implement property query interception
 */
static const OSSL_ALGORITHM *dsmil_query(void *provctx,
                                          int operation_id,
                                          int *no_cache)
{
    *no_cache = 0;

    /*
     * This policy provider doesn't provide algorithm implementations.
     * It influences algorithm selection via property queries.
     *
     * Future: May provide wrapper algorithms that enforce policy
     */
    return NULL;
}

/*
 * Provider teardown
 */
static void dsmil_teardown(void *provctx)
{
    DSMIL_PROV_CTX *ctx = (DSMIL_PROV_CTX *)provctx;

    if (ctx == NULL)
        return;

    /* Cleanup policy context */
    if (ctx->policy_ctx != NULL)
        dsmil_policy_ctx_free(ctx->policy_ctx);

    /* Future: Cleanup event context */
    /* if (ctx->event_ctx != NULL)
        dsmil_event_ctx_free(ctx->event_ctx); */

    OPENSSL_free(ctx);
}

/*
 * Provider initialization
 */
static int dsmil_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    DSMIL_PROV_CTX *ctx;
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;

    /* Extract core functions */
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        default:
            /* Unknown function */
            break;
        }
    }

    if (c_gettable_params == NULL || c_get_params == NULL) {
        return 0;
    }

    /* Allocate provider context */
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;

    ctx->handle = handle;

    /* Initialize policy context */
    ctx->policy_ctx = dsmil_policy_ctx_new(c_get_libctx(handle));
    if (ctx->policy_ctx == NULL) {
        OPENSSL_free(ctx);
        return 0;
    }

    /* Future (Phase 3): Initialize event telemetry */
    /* ctx->event_ctx = dsmil_event_ctx_new(); */

    *provctx = ctx;
    *out = NULL;  /* No dispatch table yet */

    fprintf(stderr, "DSMIL Policy Provider initialized (profile: %s)\n",
            dsmil_policy_get_profile_name(ctx->policy_ctx));

    return 1;
}

/* Provider dispatch table */
static const OSSL_DISPATCH dsmil_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))dsmil_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))dsmil_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))dsmil_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))dsmil_query },
    { 0, NULL }
};

/*
 * Provider entry point
 */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    if (!dsmil_init(handle, in, out, provctx))
        return 0;

    *out = dsmil_dispatch_table;
    return 1;
}

/*
 * Implementation Notes:
 *
 * Phase 2 TODO:
 *  - Implement property query interception
 *  - Add algorithm filtering based on profile
 *  - Implement SNI/IP-based profile selection
 *  - Add THREATCON integration
 *
 * Phase 3 TODO:
 *  - Add event telemetry (events.c/events.h)
 *  - Implement Unix socket event emission
 *  - CBOR/JSON event formatting
 *
 * Phase 6 TODO:
 *  - Add CSNA constant-time enforcement hooks
 *  - Side-channel alert integration
 */
