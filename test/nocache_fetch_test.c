/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You may obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html.
 */

/*
 * Regression test for the "no-cache provider poisons caching of cacheable
 * methods fetched from another provider" defect in the three fetch paths that
 * decide cacheability after ossl_method_construct() but independently of the
 * EVP path: OSSL_ENCODER, OSSL_DECODER and OSSL_STORE_LOADER.
 *
 * Mechanism
 * ---------
 * When an activated provider requests no_cache for an operation, the core
 * allocates a per-fetch temporary store for that operation and shares it across
 * every provider for the duration of the fetch (see
 * ossl_method_construct_reserve_store()).  Like the EVP path before #32077,
 * these fetch paths used
 * "a temporary store exists" (methdata->tmp_store == NULL) as a proxy for "this
 * method is non-cacheable".  Because the temporary store is shared, a cacheable
 * method fetched from a *different* provider was wrongly de-cached: it was kept
 * only by the provider-implementation table with no extra ownership reference,
 * got freed when its providing provider was unloaded, and was then touched
 * through a borrowed pointer (use-after-free).
 *
 * #32077 fixed the EVP path by looking the method up in the temporary store.
 * The fix extended here is simpler and operation-agnostic: decide cacheability
 * from each method's own no_store flag (the same flag the provider set at
 * construction time) instead of from the shared temporary store.
 *
 * Why this is deterministic
 * -------------------------
 * The observable symptom (a use-after-free in the method's *_free) is
 * allocator- and field-dependent: whether the invalid read escalates to a crash
 * depends on which field *_free touches and on what the allocator leaves in the
 * freed chunk, so a crash-based assertion is not a reliable gate.  Instead the
 * primary assertion inspects the outcome directly: a correctly handled
 * cacheable method must end up installed in the relevant libctx method-store
 * *cache* under the expected (provider, id, property) key.  On buggy code the
 * proxy de-caches it, so that cache entry is absent and the assertion fails
 * regardless of allocator or sanitizer.
 *
 * Each subtest still drives the full unload-then-free lifecycle *after*
 * recording the cache result (rather than short-circuiting on failure): on
 * buggy code the de-cached method has no ownership reference and is freed
 * during the unload, so the following *_free then touches freed memory.  That
 * use-after-free is the secondary detector and is reported by valgrind/ASan
 * builds (it is also the loud failure on allocators that escalate it to a
 * double free).  The cache check remains the deterministic one: it fails the
 * subtest even on allocators where the unload/free ordering is silent.
 *
 * Self-validation of the precondition
 * -----------------------------------
 * The whole test is meaningful only while p_ossltest actually requests
 * no_cache; if that precondition silently fails (for example on a platform
 * whose libc lacks setenv() and the env var never takes effect), no temporary
 * store is created and the buggy code would pass by taking the fixed code's
 * branch.  Each subtest therefore first queries p_ossltest directly for
 * ENCODER, DECODER and STORE and asserts both a non-NULL algorithm array and
 * no_cache == 1, so a missing precondition is a loud failure rather than a
 * vacuous pass.  This is hardening: the cache assertion below is what detects
 * the regression, this check only rules out passing for the wrong reason.
 *
 * Each subtest loads the default provider alongside p_ossltest (which requests
 * no_cache for every operation when OSSL_TEST_PROVIDER_NO_CACHE is set,
 * reproducing the relevant query-level no_cache behavior), then fetches a
 * cacheable method that only default provides, records the cache check, and
 * unloads default before freeing the method.
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

/* Subtest indices, also used as the ADD_ALL_TESTS index. */
#define SUB_ENCODER 0
#define SUB_DECODER 1
#define SUB_STORE_LOADER 2

/*
 * Load default + p_ossltest (with no_cache requested for every operation).
 * Returns the libctx on success, NULL on failure.  Provider handles are
 * returned via out-params so the caller controls unload order.
 */
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

    /*
     * p_ossltest reads OSSL_TEST_PROVIDER_NO_CACHE on every query; set it
     * explicitly so the test is robust regardless of how it is invoked.  The
     * recipe sets it too, so this is belt-and-braces.  setenv() is POSIX, so
     * guard it the same way test/conf_include_test.c does; on platforms without
     * it the recipe's environment is relied upon instead.
     */
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

/*
 * Primary, allocator-independent assertion: a cacheable method fetched from
 * |deflt| while a no_cache provider is present must have been installed in the
 * libctx method-store *cache* for |store_index| under the key
 * (deflt, name_id, propq), and that cache entry must be the very method handed
 * back to the caller.  On the buggy (tmp_store-proxy) code the method is
 * de-cached, so the lookup fails and this returns 0 -- with no reliance on any
 * memory error being observed.
 */
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

/*
 * Self-validation of the test's precondition (useful hardening, not a
 * correctness gate in its own right): prove end-to-end, through the same
 * query path the core uses during a fetch, that p_ossltest is actually
 * requesting no_cache for each of the three operations under test.  Without
 * this check, OSSL_TEST_PROVIDER_NO_CACHE failing to take effect -- for
 * example on a platform whose libc lacks setenv(), leaving only the recipe to
 * set it -- would mean no per-fetch temporary store is ever created; the
 * unfixed code would then take the same branch as the fixed code and every
 * assertion below would succeed on broken sources (a vacuous pass).  Failing
 * here turns that into a loud, named failure instead.
 */
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

    /*
     * Guard against a vacuous pass: confirm the no_cache precondition holds
     * end-to-end before asserting anything about the cache.  See
     * nocache_precondition_holds().
     */
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
        /*
         * Primary, deterministic check: the cacheable method fetched from
         * default must be installed in the libctx encoder-store cache under
         * (deflt, id, propq).  "RSA" is default-only, never p_ossltest.
         * Record the outcome but keep going: the unload-then-free below is
         * the secondary detector that reaches the use-after-free on buggy
         * code (reported by valgrind/ASan).
         */
        cache_ok = TEST_ptr_eq(OSSL_ENCODER_get0_provider(enc), deflt)
            && method_was_cached(libctx, OSSL_LIB_CTX_ENCODER_STORE_INDEX,
                deflt, "RSA", propq, enc);
        /*
         * Unload default, then free: on buggy code the de-cached method is
         * freed during the unload and this *_free then reads freed memory.
         * The unload return is checked so a failed unload cannot masquerade
         * as a pass.
         */
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
        /* NULL properties normalize to "" on both fetch and cache. */
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
