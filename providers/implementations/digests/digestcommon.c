/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/proverr.h>
#include "prov/digestcommon.h"
#include "crypto/param_trie.h"
#define ALLOW_RUN_ONCE_IN_FIPS
#include "internal/thread_once.h"

/* This enums *must* be in the same order at the param array */
enum {
    DIGEST_GETTABLE_BLOCK_SIZE,
    DIGEST_GETTABLE_SIZE,
    DIGEST_GETTABLE_XOF,
    DIGEST_GETTABLE_ALGID_ABSENT
};
static const OSSL_PARAM digest_default_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
    OSSL_PARAM_END
};

static OSSL_PTRIE *generic_digest_get_ptrie;

#if 0
static void digest_free_trie_memory(void)
{
    ossl_ptrie_free(generic_digest_get_ptrie);
}
#endif

static CRYPTO_ONCE digest_common_init = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_digest_common_init)
{
    /*
     * If this fails, it's not a problem because the code will
     * fallback to a slower but equivalent path
     */
#if 0
    if (OPENSSL_atexit(&digest_free_trie_memory))
#endif
        generic_digest_get_ptrie =
                ossl_ptrie_new(digest_default_known_gettable_params);
    return 1;
}

int ossl_digest_default_get_params(OSSL_PARAM params[], size_t blksz,
                                   size_t paramsz, unsigned long flags)
{
    OSSL_PARAM *p = NULL;
    OSSL_PTRIE_PARAM_IDX indicies[OSSL_NELEM(digest_default_known_gettable_params) - 1];

    if (!RUN_ONCE(&digest_common_init, do_digest_common_init))
        return 0;

    if (!ossl_ptrie_scan(generic_digest_get_ptrie, params,
                         OSSL_NELEM(indicies), indicies))
        return 0;

    p = ossl_ptrie_locate(DIGEST_GETTABLE_BLOCK_SIZE, params, indicies,
                          OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blksz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = ossl_ptrie_locate(DIGEST_GETTABLE_SIZE, params, indicies,
                          OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, paramsz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = ossl_ptrie_locate(DIGEST_GETTABLE_XOF, params, indicies,
                          OSSL_DIGEST_PARAM_XOF);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_DIGEST_FLAG_XOF) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = ossl_ptrie_locate(DIGEST_GETTABLE_ALGID_ABSENT, params, indicies,
                          OSSL_DIGEST_PARAM_ALGID_ABSENT);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_DIGEST_FLAG_ALGID_ABSENT) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

const OSSL_PARAM *ossl_digest_default_gettable_params(void *provctx)
{
    return digest_default_known_gettable_params;
}
