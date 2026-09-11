/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You may obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html.
 */

/*
 * Verify that a no-cache provider does not prevent methods from another
 * provider from being cached.  Unloading that provider before freeing each
 * method also exercises the original dangling-reference failure.
 */

#include <openssl/core_dispatch.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/store.h>
#include <openssl/provider.h>

#include "testutil.h"
#include "internal/cryptlib.h"
#include "internal/nelem.h"
#include "internal/property.h"
#include "internal/namemap.h"

#define SUB_ENCODER 0
#define SUB_DECODER 1
#define SUB_STORE_LOADER 2

static OSSL_LIB_CTX *load_with_nocache(OSSL_PROVIDER **out_deflt,
    OSSL_PROVIDER **out_test)
{
    OSSL_LIB_CTX *libctx;
    OSSL_PROVIDER *deflt, *test;

    if (!TEST_ptr(libctx = OSSL_LIB_CTX_new()))
        return NULL;

    if (!TEST_ptr(deflt = OSSL_PROVIDER_load(libctx, "default"))) {
        OSSL_LIB_CTX_free(libctx);
        return NULL;
    }

    /* Allow direct invocation where setenv() is available. */
#if defined(_BSD_SOURCE)                                        \
    || (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L) \
    || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 600)
    setenv("OSSL_TEST_PROVIDER_NO_CACHE", "yes", 1);
#endif

    if (!TEST_ptr(test = OSSL_PROVIDER_load(libctx, "p_ossltest"))) {
        OSSL_PROVIDER_unload(deflt);
        OSSL_LIB_CTX_free(libctx);
        return NULL;
    }

    *out_deflt = deflt;
    *out_test = test;
    return libctx;
}

static int method_was_cached(OSSL_LIB_CTX *libctx, int store_index,
    OSSL_PROVIDER *deflt, const char *name,
    const char *propq, void *method)
{
    OSSL_METHOD_STORE *store;
    OSSL_NAMEMAP *namemap;
    void *cached = NULL;
    int id;

    if (!TEST_ptr(store = ossl_lib_ctx_get_data(libctx, store_index)))
        return 0;

    if ((namemap = ossl_namemap_stored(libctx)) == NULL)
        return 0;
    if (!TEST_int_ne(id = ossl_namemap_name2num(namemap, name), 0))
        return 0;

    if (!TEST_true(ossl_method_store_cache_get(store, deflt, id,
            propq != NULL ? propq : "",
            &cached)))
        return 0;

    return TEST_ptr_eq(cached, method);
}

/* Do not pass vacuously if p_ossltest fails to request no_cache. */
static int nocache_precondition_holds(OSSL_PROVIDER *test)
{
    static const struct {
        int op;
        const char *name;
    } ops[] = {
        { OSSL_OP_ENCODER, "ENCODER" },
        { OSSL_OP_DECODER, "DECODER" },
        { OSSL_OP_STORE, "STORE" },
    };
    size_t i;

    for (i = 0; i < OSSL_NELEM(ops); i++) {
        const OSSL_ALGORITHM *algs;
        int no_cache = 0;

        algs = OSSL_PROVIDER_query_operation(test, ops[i].op, &no_cache);
        if (!TEST_ptr(algs)) {
            TEST_info("p_ossltest advertises no %s algorithms", ops[i].name);
            return 0;
        }
        if (!TEST_true(no_cache)) {
            TEST_info("p_ossltest did not request no_cache for %s "
                      "(OSSL_TEST_PROVIDER_NO_CACHE not in effect)",
                ops[i].name);
            OSSL_PROVIDER_unquery_operation(test, ops[i].op, algs);
            return 0;
        }
        OSSL_PROVIDER_unquery_operation(test, ops[i].op, algs);
    }
    return 1;
}

static int test_nocache_fetch(int tst)
{
    OSSL_LIB_CTX *libctx;
    OSSL_PROVIDER *deflt = NULL, *test = NULL;
    int ok = 0;

    libctx = load_with_nocache(&deflt, &test);
    if (!TEST_ptr(libctx))
        return 0;

    if (!nocache_precondition_holds(test)) {
        OSSL_PROVIDER_unload(deflt);
        OSSL_PROVIDER_unload(test);
        OSSL_LIB_CTX_free(libctx);
        return 0;
    }

    switch (tst) {
    case SUB_ENCODER: {
        const char *propq = "output=der,structure=PrivateKeyInfo";
        OSSL_ENCODER *enc = OSSL_ENCODER_fetch(libctx, "RSA", propq);
        int cache_ok;

        if (!TEST_ptr(enc))
            break;
        cache_ok = TEST_ptr_eq(OSSL_ENCODER_get0_provider(enc), deflt)
            && method_was_cached(libctx, OSSL_LIB_CTX_ENCODER_STORE_INDEX,
                deflt, "RSA", propq, enc);
        if (!TEST_int_eq(OSSL_PROVIDER_unload(deflt), 1)) {
            OSSL_ENCODER_free(enc);
            break;
        }
        deflt = NULL;
        OSSL_ENCODER_free(enc);
        ok = cache_ok;
        break;
    }
    case SUB_DECODER: {
        const char *propq = "input=der,structure=PrivateKeyInfo";
        OSSL_DECODER *dec = OSSL_DECODER_fetch(libctx, "RSA", propq);
        int cache_ok;

        if (!TEST_ptr(dec))
            break;
        cache_ok = TEST_ptr_eq(OSSL_DECODER_get0_provider(dec), deflt)
            && method_was_cached(libctx, OSSL_LIB_CTX_DECODER_STORE_INDEX,
                deflt, "RSA", propq, dec);
        if (!TEST_int_eq(OSSL_PROVIDER_unload(deflt), 1)) {
            OSSL_DECODER_free(dec);
            break;
        }
        deflt = NULL;
        OSSL_DECODER_free(dec);
        ok = cache_ok;
        break;
    }
    case SUB_STORE_LOADER: {
        OSSL_STORE_LOADER *loader = OSSL_STORE_LOADER_fetch(libctx, "file", NULL);
        int cache_ok;

        if (!TEST_ptr(loader))
            break;
        cache_ok = TEST_ptr_eq(OSSL_STORE_LOADER_get0_provider(loader), deflt)
            && method_was_cached(libctx,
                OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX,
                deflt, "file", NULL, loader);
        if (!TEST_int_eq(OSSL_PROVIDER_unload(deflt), 1)) {
            OSSL_STORE_LOADER_free(loader);
            break;
        }
        deflt = NULL;
        OSSL_STORE_LOADER_free(loader);
        ok = cache_ok;
        break;
    }
    default:
        break;
    }

    if (deflt != NULL)
        OSSL_PROVIDER_unload(deflt);
    OSSL_PROVIDER_unload(test);
    OSSL_LIB_CTX_free(libctx);
    return ok;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_nocache_fetch, 3);
    return 1;
}
