/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdint.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include "testutil.h"

/* A bounded provider exercises reported lengths without huge allocations. */
static struct {
    size_t reported_size;
    int length_queries;
    int data_queries;
    int sets;
    unsigned char stored[6];
} state;

static void *add1_new(void *provctx)
{
    return provctx;
}

static void add1_free(void *ctx)
{
}

static int add1_has(const void *key, int selection)
{
    return 1;
}

static int add1_init(void *ctx, void *key, const OSSL_PARAM params[])
{
    return 1;
}

static int add1_derive(void *ctx, unsigned char *secret, size_t *secretlen,
    size_t outlen)
{
    return 0;
}

static int add1_get_params(void *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_INFO);

    if (p == NULL)
        return 0;
    if (p->data == NULL) {
        state.length_queries++;
        p->return_size = state.reported_size;
        return 1;
    }
    state.data_queries++;
    /* Stop the unpatched path before it can copy using a wrapped length. */
    if (state.reported_size != 3)
        return 0;
    return OSSL_PARAM_set_octet_string(p, "old", 3);
}

static int add1_set_params(void *ctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO);

    state.sets++;
    if (p == NULL || p->data_size != sizeof(state.stored))
        return 0;
    memcpy(state.stored, p->data, sizeof(state.stored));
    return 1;
}

static const OSSL_PARAM *add1_gettable_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
        OSSL_PARAM_END
    };

    return params;
}

static const OSSL_DISPATCH add1_keymgmt[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))add1_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))add1_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))add1_has },
    OSSL_DISPATCH_END
};

static const OSSL_DISPATCH add1_keyexch[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))add1_new },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))add1_free },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))add1_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))add1_derive },
    { OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))add1_get_params },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))add1_gettable_params },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))add1_set_params },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))add1_gettable_params },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM *add1_query(void *provctx, int operation,
    int *no_cache)
{
    static const OSSL_ALGORITHM keymgmts[] = {
        { "HKDF", "provider=add1-test", add1_keymgmt },
        { NULL, NULL, NULL }
    };
    static const OSSL_ALGORITHM keyexchs[] = {
        { "HKDF", "provider=add1-test", add1_keyexch },
        { NULL, NULL, NULL }
    };

    *no_cache = 0;
    if (operation == OSSL_OP_KEYMGMT)
        return keymgmts;
    if (operation == OSSL_OP_KEYEXCH)
        return keyexchs;
    return NULL;
}

static int add1_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)
{
    static const OSSL_DISPATCH dispatch[] = {
        { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))add1_query },
        OSSL_DISPATCH_END
    };

    *out = dispatch;
    *provctx = &state;
    return 1;
}

static int test_add1_info(int overflow)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *provider = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned long err;
    int ret = 0, result;

    memset(&state, 0, sizeof(state));
    state.reported_size = overflow ? SIZE_MAX - 1 : 3;
    if (!TEST_ptr(libctx = OSSL_LIB_CTX_new())
        || !TEST_true(OSSL_PROVIDER_add_builtin(libctx, "add1-test",
            add1_provider_init))
        || !TEST_ptr(provider = OSSL_PROVIDER_load(libctx, "add1-test"))
        || !TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(libctx, "HKDF",
                         "provider=add1-test"))
        || !TEST_int_gt(EVP_PKEY_derive_init(pctx), 0))
        goto end;

    ERR_clear_error();
    result = EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char *)"new", 3);
    if (!TEST_int_eq(state.length_queries, 1))
        goto end;
    if (overflow) {
        err = ERR_get_error();
        if (!TEST_int_eq(result, 0)
            || !TEST_int_eq(state.data_queries, 0)
            || !TEST_int_eq(state.sets, 0)
            || !TEST_int_eq(ERR_GET_LIB(err), ERR_LIB_EVP)
            || !TEST_int_eq(ERR_GET_REASON(err), ERR_R_INTERNAL_ERROR))
            goto end;
    } else if (!TEST_int_gt(result, 0)
        || !TEST_int_eq(state.data_queries, 1)
        || !TEST_int_eq(state.sets, 1)
        || !TEST_mem_eq(state.stored, sizeof(state.stored), "oldnew", 6)) {
        goto end;
    }
    ret = 1;
end:
    EVP_PKEY_CTX_free(pctx);
    OSSL_PROVIDER_unload(provider);
    OSSL_LIB_CTX_free(libctx);
    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_add1_info, 2);
    return 1;
}
