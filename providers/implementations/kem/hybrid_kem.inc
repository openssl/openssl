/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"

#ifndef PREFIX
# define PREFIX  kem
#endif

#include "prov/hybrid_pkey_defines.h"
#include "hybrid_kem_local.h"
#include "prov/implementations.h"

static OSSL_FUNC_kem_newctx_fn NAME(newctx);
static OSSL_FUNC_kem_gettable_ctx_params_fn NAME(ctx_gettable_params);
static OSSL_FUNC_kem_settable_ctx_params_fn NAME(ctx_settable_params);

extern const OSSL_PARAM OSSL_NAME(ctx_gettable_params)[];
extern const OSSL_PARAM OSSL_NAME(ctx_settable_params)[];

static void *NAME(newctx)(void *provctx)
{
    return ossl_hybrid_kem_newctx(provctx, &COMMON_NAME(info));
}

static const OSSL_PARAM *NAME(ctx_gettable_params)(void *vctx, void *provctx) {
    return ossl_hybrid_gettable_common(OSSL_NAME(ctx_gettable_params));
}

static const OSSL_PARAM *NAME(ctx_settable_params)(void *vctx, void *provctx) {
    return ossl_hybrid_settable_common(OSSL_NAME(ctx_settable_params));
}

const OSSL_DISPATCH OSSL_NAME(functions)[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))NAME(newctx) },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))ossl_hybrid_pkey_ctx_free },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))ossl_hybrid_kem_dupctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
      (void (*)(void))ossl_hybrid_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))ossl_hybrid_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
      (void (*)(void))ossl_hybrid_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))ossl_hybrid_kem_decapsulate },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS,
      (void (*)(void))ossl_hybrid_kem_get_ctx_params },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS,
      (void (*)(void))NAME(ctx_gettable_params) },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS,
      (void (*)(void))ossl_hybrid_kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
      (void (*)(void))NAME(ctx_settable_params) },
    { OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT,
      (void (*)(void))ossl_hybrid_kem_auth_encapsulate_init },
    { OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT,
      (void (*)(void))ossl_hybrid_kem_auth_decapsulate_init },
    OSSL_DISPATCH_END
};
