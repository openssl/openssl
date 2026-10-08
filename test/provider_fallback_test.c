/*
 * Copyright 2020-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <string.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include "testutil.h"

static int test_provider(OSSL_LIB_CTX *ctx)
{
    EVP_KEYMGMT *rsameth = NULL;
    const OSSL_PROVIDER *prov = NULL;
    int ok;

    ok = TEST_true(OSSL_PROVIDER_available(ctx, "default"))
        && TEST_ptr(rsameth = EVP_KEYMGMT_fetch(ctx, "RSA", NULL))
        && TEST_ptr(prov = EVP_KEYMGMT_get0_provider(rsameth))
        && TEST_str_eq(OSSL_PROVIDER_get0_name(prov), "default");

    EVP_KEYMGMT_free(rsameth);
    return ok;
}

static int test_fallback_provider(void)
{
    return test_provider(NULL);
}

static int test_explicit_provider(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov = NULL;
    int ok;

    ok = TEST_ptr(ctx = OSSL_LIB_CTX_new())
        && TEST_ptr(prov = OSSL_PROVIDER_load(ctx, "default"));

    if (ok) {
        ok = test_provider(ctx);
        if (ok)
            ok = TEST_true(OSSL_PROVIDER_unload(prov));
        else
            OSSL_PROVIDER_unload(prov);
    }

    OSSL_LIB_CTX_free(ctx);
    return ok;
}

/* Count active default providers. */
static int count_default_provider(OSSL_PROVIDER *prov, void *cbdata)
{
    int *count = cbdata;

    if (strcmp(OSSL_PROVIDER_get0_name(prov), "default") == 0)
        (*count)++;
    return 1;
}

/* Reproduce fallback duplication with child-provider synchronization. */
static int test_fallback_duplication(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *legacy = NULL, *deflt = NULL;
    EVP_MD *md = NULL;
    int default_count;
    int ok = 0;
#ifdef OPENSSL_NO_MD4
    const char *trigger_algo = "SHA256";
#else
    const char *trigger_algo = "MD4";
#endif

    if (!TEST_ptr(ctx = OSSL_LIB_CTX_new()))
        return 0;

    /* Load legacy first so the child-provider path is exercised. */
    legacy = OSSL_PROVIDER_try_load(ctx, "legacy", 1);
    if (legacy == NULL) {
        int skip = TEST_skip("Legacy provider not available");

        OSSL_LIB_CTX_free(ctx);
        return skip;
    }

    /* Load default while retaining automatic fallback activation. */
    if (!TEST_ptr(deflt = OSSL_PROVIDER_try_load(ctx, "default", 1)))
        goto err;

    /* Trigger fallback activation; MD4 also exercises legacy. */
    if (!TEST_ptr(md = EVP_MD_fetch(ctx, trigger_algo, "-fips")))
        goto err;
    EVP_MD_free(md);
    md = NULL;

    default_count = 0;
    if (!TEST_true(OSSL_PROVIDER_do_all(ctx, count_default_provider,
            &default_count))
        || !TEST_int_eq(default_count, 1))
        goto err;

    /* The fallback reference must keep default active. */
    if (!TEST_true(OSSL_PROVIDER_unload(deflt)))
        goto err;
    deflt = NULL;
    if (!TEST_true(OSSL_PROVIDER_unload(legacy)))
        goto err;
    legacy = NULL;

    if (!TEST_ptr(md = EVP_MD_fetch(ctx, "SHA256", "-fips")))
        goto err;
    EVP_MD_free(md);
    md = NULL;

    /* Repeat the issue's load/fetch/unload cycle. */
    if (!TEST_ptr(deflt = OSSL_PROVIDER_try_load(ctx, "default", 1)))
        goto err;
    if (!TEST_ptr(md = EVP_MD_fetch(ctx, "SHA256", "-fips")))
        goto err;
    EVP_MD_free(md);
    md = NULL;
    if (!TEST_true(OSSL_PROVIDER_unload(deflt)))
        goto err;
    deflt = NULL;

    ok = 1;

err:
    EVP_MD_free(md);
    OSSL_PROVIDER_unload(deflt);
    OSSL_PROVIDER_unload(legacy);
    /* This teardown previously double-freed the duplicate. */
    OSSL_LIB_CTX_free(ctx);
    return ok;
}

/* Reproduce the duplication without relying on the legacy module. */
static int test_fallback_default_only(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *deflt = NULL;
    EVP_MD *md = NULL;
    int default_count;
    int ok = 0;

    if (!TEST_ptr(ctx = OSSL_LIB_CTX_new()))
        return 0;

    if (!TEST_ptr(deflt = OSSL_PROVIDER_try_load(ctx, "default", 1)))
        goto err;

    /* Fallback activation must reuse the explicit default. */
    if (!TEST_ptr(md = EVP_MD_fetch(ctx, "SHA256", "-fips")))
        goto err;
    EVP_MD_free(md);
    md = NULL;

    default_count = 0;
    if (!TEST_true(OSSL_PROVIDER_do_all(ctx, count_default_provider,
            &default_count))
        || !TEST_int_eq(default_count, 1))
        goto err;

    /* Unloading the explicit handle must not deactivate the fallback. */
    if (!TEST_true(OSSL_PROVIDER_unload(deflt)))
        goto err;
    deflt = NULL;

    if (!TEST_ptr(md = EVP_MD_fetch(ctx, "SHA256", "-fips")))
        goto err;
    EVP_MD_free(md);
    md = NULL;

    ok = 1;

err:
    EVP_MD_free(md);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(ctx);
    return ok;
}

/* Exercise fallback reuse with an inactive in-store provider. */
static int test_fallback_reactivate_inactive(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *legacy = NULL, *deflt = NULL;
    EVP_MD *md = NULL;
    int default_count;
    int ok = 0;

    if (!TEST_ptr(ctx = OSSL_LIB_CTX_new()))
        return 0;

    /* Register child-provider callbacks before loading default. */
    legacy = OSSL_PROVIDER_try_load(ctx, "legacy", 1);
    if (legacy == NULL) {
        int skip = TEST_skip("Legacy provider not available");

        OSSL_LIB_CTX_free(ctx);
        return skip;
    }

    if (!TEST_ptr(deflt = OSSL_PROVIDER_try_load(ctx, "default", 1)))
        goto err;

    /* Leave the in-store object inactive with fallbacks enabled. */
    if (!TEST_true(OSSL_PROVIDER_unload(deflt)))
        goto err;
    deflt = NULL;

    /* Reactivate the object through fallback loading. */
    if (!TEST_ptr(md = EVP_MD_fetch(ctx, "SHA256", "-fips")))
        goto err;
    EVP_MD_free(md);
    md = NULL;

    default_count = 0;
    if (!TEST_true(OSSL_PROVIDER_do_all(ctx, count_default_provider,
            &default_count))
        || !TEST_int_eq(default_count, 1))
        goto err;

    if (!TEST_true(OSSL_PROVIDER_unload(legacy)))
        goto err;
    legacy = NULL;

    ok = 1;

err:
    EVP_MD_free(md);
    OSSL_PROVIDER_unload(deflt);
    OSSL_PROVIDER_unload(legacy);
    OSSL_LIB_CTX_free(ctx);
    return ok;
}

int setup_tests(void)
{
    ADD_TEST(test_fallback_provider);
    ADD_TEST(test_explicit_provider);
    ADD_TEST(test_fallback_duplication);
    ADD_TEST(test_fallback_default_only);
    ADD_TEST(test_fallback_reactivate_inactive);
    return 1;
}
