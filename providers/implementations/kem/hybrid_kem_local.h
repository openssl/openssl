/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>

HYBRID_PKEY_CTX *ossl_hybrid_kem_newctx(void *provctx,
                                        const HYBRID_ALG_INFO *info);

OSSL_FUNC_kem_dupctx_fn                  ossl_hybrid_kem_dupctx;
OSSL_FUNC_kem_freectx_fn                 ossl_hybrid_kem_freectx;
OSSL_FUNC_kem_encapsulate_init_fn        ossl_hybrid_kem_encapsulate_init;
OSSL_FUNC_kem_encapsulate_fn             ossl_hybrid_kem_encapsulate;
OSSL_FUNC_kem_decapsulate_init_fn        ossl_hybrid_kem_decapsulate_init;
OSSL_FUNC_kem_decapsulate_fn             ossl_hybrid_kem_decapsulate;
OSSL_FUNC_kem_auth_encapsulate_init_fn   ossl_hybrid_kem_auth_encapsulate_init;
OSSL_FUNC_kem_auth_decapsulate_init_fn   ossl_hybrid_kem_auth_decapsulate_init;
OSSL_FUNC_kem_get_ctx_params_fn          ossl_hybrid_kem_get_ctx_params;
OSSL_FUNC_kem_set_ctx_params_fn          ossl_hybrid_kem_set_ctx_params;
