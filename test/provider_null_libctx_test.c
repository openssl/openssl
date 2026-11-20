/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Providers loaded through a NULL library context while a non-global context
 * is the thread default must stay bound to the context they were loaded into.
 *
 * test_null_libctx_mirror_deactivation:
 *     Context A has "default" and a child-owning provider "probe-owner".
 *     Context B gets "default" through a NULL libctx while B is the thread
 *     default, and is freed while A is the thread default.  This must not
 *     deactivate the "default" mirror in probe-owner's child library context.
 *
 * test_null_libctx_fetch_thread_default:
 *     Context A gets "default" through a NULL libctx while A is the thread
 *     default.  With B (only the "null" provider) as thread default, fetching
 *     HMAC from A explicitly must still work.
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include "testutil.h"

typedef struct {
    OSSL_LIB_CTX *child;
} PROBE_CTX;

/* Reports whether SHA2-256 can be fetched in the provider's child libctx */
static int probe_get_params(void *provctx, OSSL_PARAM params[])
{
    PROBE_CTX *p = provctx;
    OSSL_PARAM *res = OSSL_PARAM_locate(params, "probe-result");
    EVP_MD *md = EVP_MD_fetch(p->child, "SHA2-256", NULL);
    int ok = md != NULL;

    EVP_MD_free(md);
    ERR_clear_error();
    return res == NULL || OSSL_PARAM_set_int(res, ok);
}

static void probe_teardown(void *provctx)
{
    PROBE_CTX *p = provctx;

    OSSL_LIB_CTX_free(p->child);
    OPENSSL_free(p);
}

static const OSSL_DISPATCH probe_dispatch[] = {
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))probe_get_params },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))probe_teardown },
    OSSL_DISPATCH_END
};

static int probe_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out, void **provctx)
{
    PROBE_CTX *p = OPENSSL_zalloc(sizeof(*p));

    if (p == NULL || (p->child = OSSL_LIB_CTX_new_child(handle, in)) == NULL) {
        OPENSSL_free(p);
        return 0;
    }
    *provctx = p;
    *out = probe_dispatch;
    return 1;
}

static int probe(OSSL_PROVIDER *prov)
{
    int res = -1;
    OSSL_PARAM params[] = {
        OSSL_PARAM_int("probe-result", &res),
        OSSL_PARAM_END
    };

    return OSSL_PROVIDER_get_params(prov, params) ? res : -1;
}

static int test_null_libctx_mirror_deactivation(void)
{
    OSSL_LIB_CTX *a = OSSL_LIB_CTX_new(), *b = OSSL_LIB_CTX_new();
    OSSL_LIB_CTX *old = NULL;
    OSSL_PROVIDER *adef = NULL, *aprobe = NULL, *bdef = NULL;
    int ret = 0;

    if (!TEST_ptr(a) || !TEST_ptr(b)
        || !TEST_true(OSSL_PROVIDER_add_builtin(a, "probe-owner", probe_init))
        || !TEST_ptr(adef = OSSL_PROVIDER_load(a, "default"))
        || !TEST_ptr(aprobe = OSSL_PROVIDER_load(a, "probe-owner"))
        || !TEST_int_eq(probe(aprobe), 1))
        goto end;

    old = OSSL_LIB_CTX_set0_default(b);
    bdef = OSSL_PROVIDER_load(NULL, "default"); /* lands in B */
    OSSL_LIB_CTX_set0_default(a);
    if (!TEST_ptr(bdef))
        goto end;
    OSSL_PROVIDER_unload(bdef);
    OSSL_LIB_CTX_free(b); /* A, not B, is the thread default here */
    b = NULL;
    OSSL_LIB_CTX_set0_default(old);
    old = NULL;

    /* probe-owner's child must still see A's "default" provider */
    ret = TEST_int_eq(probe(aprobe), 1);
end:
    if (old != NULL)
        OSSL_LIB_CTX_set0_default(old);
    OSSL_PROVIDER_unload(aprobe);
    OSSL_PROVIDER_unload(adef);
    OSSL_LIB_CTX_free(b);
    OSSL_LIB_CTX_free(a);
    return ret;
}

static int test_null_libctx_fetch_thread_default(void)
{
    static unsigned char key[32];
    OSSL_LIB_CTX *a = OSSL_LIB_CTX_new(), *b = OSSL_LIB_CTX_new();
    OSSL_LIB_CTX *old = NULL;
    OSSL_PROVIDER *adef = NULL, *bnull = NULL;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA2-256", 0),
        OSSL_PARAM_END
    };
    int ret = 0;

    if (!TEST_ptr(a) || !TEST_ptr(b))
        goto end;
    old = OSSL_LIB_CTX_set0_default(a);
    adef = OSSL_PROVIDER_load(NULL, "default"); /* lands in A */
    OSSL_LIB_CTX_set0_default(old);
    if (!TEST_ptr(adef)
        || !TEST_ptr(bnull = OSSL_PROVIDER_load(b, "null")))
        goto end;

    old = OSSL_LIB_CTX_set0_default(b);
    ret = TEST_ptr(mac = EVP_MAC_fetch(a, "HMAC", NULL)) /* explicit A */
        && TEST_ptr(mctx = EVP_MAC_CTX_new(mac))
        && TEST_true(EVP_MAC_init(mctx, key, sizeof(key), params));
    OSSL_LIB_CTX_set0_default(old);
end:
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    OSSL_PROVIDER_unload(adef);
    OSSL_PROVIDER_unload(bnull);
    OSSL_LIB_CTX_free(b);
    OSSL_LIB_CTX_free(a);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_null_libctx_mirror_deactivation);
    ADD_TEST(test_null_libctx_fetch_thread_default);
    return 1;
}
