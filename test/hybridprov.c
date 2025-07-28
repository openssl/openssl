/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/store.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include "prov/provider_ctx.h"
#include "testutil.h"

extern const OSSL_DISPATCH ossl_mlx_kem_asym_kem_functions[];
extern const OSSL_DISPATCH ossl_ml_kem_asym_kem_functions[];
extern const OSSL_DISPATCH ossl_mlx_p256_kem_kmgmt_functions[];
extern const OSSL_DISPATCH ossl_ml_kem_768_keymgmt_functions[];

/* Defined in tls-provider.c */
int hybrid_provider_init(const OSSL_CORE_HANDLE *handle,
                         const OSSL_DISPATCH *in,
                         const OSSL_DISPATCH **out,
                         void **provctx);

static const OSSL_ALGORITHM hybrid_asym_kem[] = {
#ifndef OPENSSL_NO_ML_KEM
    { "ML-KEM-768:MLKEM768:id-alg-ml-kem-768:2.16.840.1.101.3.4.4.2",
      "provider=hybrid,fips=yes", ossl_ml_kem_asym_kem_functions },
# if !defined(OPENSSL_NO_EC)
    { "SecP256r1MLKEM768", "provider=hybrid,fips=yes", ossl_mlx_kem_asym_kem_functions },
# endif
#endif
    { NULL, NULL, NULL }
};

#define PROV_NAMES_SecP256r1MLKEM768 "SecP256r1MLKEM768"
#define PROV_DESCS_SecP256r1MLKEM768 "P-256+ML-KEM-768 TLS hybrid implementation"

static const OSSL_ALGORITHM hybrid_keymgmt[] = {
#ifndef OPENSSL_NO_ML_KEM
    { "ML-KEM-768:MLKEM768:id-alg-ml-kem-768:2.16.840.1.101.3.4.4.2",
      "provider=hybrid,fips=yes",
      ossl_ml_kem_768_keymgmt_functions,
      "OpenSSL ML-KEM-768 implementation" },
# if !defined(OPENSSL_NO_EC)
    { PROV_NAMES_SecP256r1MLKEM768, "provider=hybrid,fips=yes",
      ossl_mlx_p256_kem_kmgmt_functions, PROV_DESCS_SecP256r1MLKEM768 },
# endif
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *hybrid_query(void *provctx, int operation_id,
                                          int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEM:
        return hybrid_asym_kem;
    case OSSL_OP_KEYMGMT:
        return hybrid_keymgmt;
    }
    return NULL;
}

static void hybrid_teardown(void *provctx)
{
    ossl_prov_ctx_free(provctx);
}

static const OSSL_DISPATCH hybrid_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))hybrid_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))hybrid_teardown },
    OSSL_DISPATCH_END
};

int hybrid_provider_init(const OSSL_CORE_HANDLE *handle,
                         const OSSL_DISPATCH *in,
                         const OSSL_DISPATCH **out,
                         void **provctx)
{
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }
    if (c_get_libctx == NULL)
        return 0;

    if ((*provctx = ossl_prov_ctx_new()) == NULL) {
        *provctx = NULL;
        return 0;
    }
    ossl_prov_ctx_set0_libctx(*provctx, (OSSL_LIB_CTX *)c_get_libctx(handle));
    ossl_prov_ctx_set0_handle(*provctx, handle);
    *out = hybrid_dispatch_table;
    return 1;
}
