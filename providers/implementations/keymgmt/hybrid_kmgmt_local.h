/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>

HYBRID_PKEY_CTX *ossl_hybrid_kmgmt_gen_init(void *provctx, int selection,
                                            const OSSL_PARAM params[],
                                            const HYBRID_ALG_INFO *info);

OSSL_FUNC_keymgmt_free_fn ossl_hybrid_kmgmt_free;
OSSL_FUNC_keymgmt_gen_fn ossl_hybrid_kmgmt_gen;
OSSL_FUNC_keymgmt_gen_cleanup_fn ossl_hybrid_kmgmt_gen_cleanup;
OSSL_FUNC_keymgmt_gen_get_params_fn ossl_hybrid_kmgmt_gen_get_params;
OSSL_FUNC_keymgmt_gen_set_params_fn ossl_hybrid_kmgmt_gen_set_params;
OSSL_FUNC_keymgmt_load_fn ossl_hybrid_kmgmt_load;
OSSL_FUNC_keymgmt_get_params_fn ossl_hybrid_kmgmt_get_params;
OSSL_FUNC_keymgmt_set_params_fn ossl_hybrid_kmgmt_set_params;
OSSL_FUNC_keymgmt_has_fn ossl_hybrid_kmgmt_has;
OSSL_FUNC_keymgmt_match_fn ossl_hybrid_kmgmt_match;
OSSL_FUNC_keymgmt_validate_fn ossl_hybrid_kmgmt_validate;
OSSL_FUNC_keymgmt_import_fn ossl_hybrid_kmgmt_import;
OSSL_FUNC_keymgmt_export_fn ossl_hybrid_kmgmt_export;
OSSL_FUNC_keymgmt_dup_fn ossl_hybrid_kmgmt_dup;
