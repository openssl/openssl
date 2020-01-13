/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*
 * MDC2 low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <opentls/crypto.h>
#include <opentls/params.h>
#include <opentls/mdc2.h>
#include <opentls/core_names.h>
#include <opentls/err.h>
#include "prov/digestcommon.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"

static Otls_OP_digest_set_ctx_params_fn mdc2_set_ctx_params;
static Otls_OP_digest_settable_ctx_params_fn mdc2_settable_ctx_params;

static const Otls_PARAM known_mdc2_settable_ctx_params[] = {
    Otls_PARAM_uint(Otls_DIGEST_PARAM_PAD_TYPE, NULL),
    Otls_PARAM_END
};

static const Otls_PARAM *mdc2_settable_ctx_params(void)
{
    return known_mdc2_settable_ctx_params;
}

static int mdc2_set_ctx_params(void *vctx, const Otls_PARAM params[])
{
    const Otls_PARAM *p;
    MDC2_CTX *ctx = (MDC2_CTX *)vctx;

    if (ctx != NULL && params != NULL) {
        p = Otls_PARAM_locate_const(params, Otls_DIGEST_PARAM_PAD_TYPE);
        if (p != NULL && !Otls_PARAM_get_uint(p, &ctx->pad_type)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        return 1;
    }
    return 0; /* Null Parameter */
}

/* mdc2_functions */
IMPLEMENT_digest_functions_with_settable_ctx(
    mdc2, MDC2_CTX, MDC2_BLOCK, MDC2_DIGEST_LENGTH, 0,
    MDC2_Init, MDC2_Update, MDC2_Final,
    mdc2_settable_ctx_params, mdc2_set_ctx_params)
