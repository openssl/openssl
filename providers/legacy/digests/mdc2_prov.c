/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/mdc2.h>
#include <openssl/core_names.h>

#include "internal/core_mkdigest.h"
#include "internal/provider_algs.h"

static OSSL_OP_digest_set_ctx_params_fn mdc2_set_ctx_params;
static OSSL_OP_digest_settable_ctx_params_fn mdc2_settable_ctx_params;

static const OSSL_PARAM known_mdc2_settable_ctx_params[] = {
    {OSSL_DIGEST_PARAM_PAD_TYPE, OSSL_PARAM_INTEGER, NULL, sizeof(int), 0},
    OSSL_PARAM_END
};

static const OSSL_PARAM *mdc2_settable_ctx_params(void)
{
    return known_mdc2_settable_ctx_params;
}

static int mdc2_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    MDC2_CTX *ctx = (MDC2_CTX *)vctx;

    if (ctx != NULL && params != NULL) {
        p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_PAD_TYPE);
        if (p != NULL && !OSSL_PARAM_get_int(p, &ctx->pad_type))
            return 0;
        return 1;
    }
    return 0; /* Null Parameter */
}

OSSL_FUNC_DIGEST_CONSTRUCT_PARAMS(mdc2, MDC2_CTX,
                                  MDC2_BLOCK, MDC2_DIGEST_LENGTH, 0,
                                  MDC2_Init, MDC2_Update, MDC2_Final,
                                  mdc2_settable_ctx_params, mdc2_set_ctx_params)
