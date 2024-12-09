/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef PREFIX
# define PREFIX kmgmt
#endif

#ifndef NUM_ALGS
# define NUM_ALGS    2
#endif

#include <openssl/core_dispatch.h>
#include "prov/hybrid_pkey_defines.h"
#include "hybrid_kmgmt_local.h"
#include "prov/implementations.h"

static OSSL_FUNC_keymgmt_new_fn NAME(new);
static OSSL_FUNC_keymgmt_gen_init_fn NAME(gen_init);
static OSSL_FUNC_keymgmt_gettable_params_fn NAME(gettable_params);
static OSSL_FUNC_keymgmt_settable_params_fn NAME(settable_params);
static OSSL_FUNC_keymgmt_gen_gettable_params_fn NAME(ctx_gettable_params);
static OSSL_FUNC_keymgmt_gen_settable_params_fn NAME(ctx_settable_params);
static OSSL_FUNC_keymgmt_import_types_fn NAME(import_types);
static OSSL_FUNC_keymgmt_export_types_fn NAME(export_types);

extern const OSSL_PARAM OSSL_NAME(gettable_params)[];
extern const OSSL_PARAM OSSL_NAME(settable_params)[];
extern const OSSL_PARAM OSSL_NAME(ctx_gettable_params)[];
extern const OSSL_PARAM OSSL_NAME(ctx_settable_params)[];
extern const OSSL_PARAM OSSL_NAME(import_types)[];
extern const OSSL_PARAM OSSL_NAME(export_types)[];

static void *NAME(new)(void *provctx)
{
    return ossl_hybrid_kmgmt_new(provctx, &COMMON_NAME(info));
}

static void *NAME(gen_init)(void *provctx, int selection,
                            const OSSL_PARAM params[])
{
    return ossl_hybrid_kmgmt_gen_init(provctx, selection, params,
                                      &COMMON_NAME(info));
}

static const OSSL_PARAM *NAME(gettable_params)(void *vkey) {
    return ossl_hybrid_gettable_common(OSSL_NAME(gettable_params));
}

static const OSSL_PARAM *NAME(settable_params)(void *vkey) {
    return ossl_hybrid_settable_common(OSSL_NAME(settable_params));
}

static const OSSL_PARAM *NAME(ctx_gettable_params)(void *vctx, void *provctx) {
    return ossl_hybrid_gettable_common(OSSL_NAME(ctx_gettable_params));
}

static const OSSL_PARAM *NAME(ctx_settable_params)(void *vctx, void *provctx) {
    return ossl_hybrid_settable_common(OSSL_NAME(ctx_settable_params));
}

static const OSSL_PARAM *NAME(import_types)(int selection) {
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
        return ossl_hybrid_settable_common(OSSL_NAME(import_types));
    return NULL;
}

static const OSSL_PARAM *NAME(export_types)(int selection) {
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
        return ossl_hybrid_gettable_common(OSSL_NAME(export_types));
    return NULL;
}

const OSSL_DISPATCH OSSL_NAME(functions)[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))NAME(new) },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ossl_hybrid_pkey_free },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,
      (void (*) (void))ossl_hybrid_kmgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*) (void))NAME(gettable_params) },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,
      (void (*) (void))ossl_hybrid_kmgmt_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
      (void (*) (void))NAME(settable_params) },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ossl_hybrid_kmgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ossl_hybrid_kmgmt_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))ossl_hybrid_kmgmt_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ossl_hybrid_kmgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
      (void (*)(void))NAME(import_types) },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ossl_hybrid_kmgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
      (void (*)(void))NAME(export_types) },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))NAME(gen_init) },
    { OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS,
      (void (*)(void))ossl_hybrid_kmgmt_gen_get_params },
    { OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS,
      (void (*)(void))NAME(ctx_gettable_params) },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
      (void (*)(void))ossl_hybrid_kmgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))NAME(ctx_settable_params) },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ossl_hybrid_kmgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))ossl_hybrid_kmgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ossl_hybrid_kmgmt_load },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))ossl_hybrid_kmgmt_dup },
    OSSL_DISPATCH_END
};
