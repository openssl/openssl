/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include "internal/hashtable.h"
#include "internal/property.h"
#include "internal/refcount.h"

#define TEST_NID 1024

/*
 * TEST_NID maps to shard zero with the property cache's current power-of-two
 * shard count, so this partial view is enough to reach the cache table.
 */
typedef struct {
    void *algs;
    HT *cache;
} TEST_STORED_ALGORITHMS;

struct ossl_method_store_st {
    OSSL_LIB_CTX *ctx;
    TEST_STORED_ALGORITHMS *algs;
    CRYPTO_RWLOCK *biglock;
};

typedef struct {
    HT_KEY key_header;
} QUERY_KEY;

/*
 * We make our OSSL_PROVIDER for testing purposes.  The property cache only
 * uses the provider pointer as a key, except when tracing asks for its name.
 */
struct ossl_provider_st {
    unsigned int flag_initialized : 1;
    unsigned int flag_activated : 1;
    CRYPTO_RWLOCK *flag_lock;
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *activatecnt_lock;
    int activatecnt;
    char *name;
};

static long alloc_count;
static long fail_at;
static int fail_enabled;
static int method_refs;

static void *test_malloc(size_t num, const char *file, int line)
{
    (void)file;
    (void)line;

    if (fail_enabled && ++alloc_count == fail_at)
        return NULL;

    return malloc(num);
}

static void *test_realloc(void *ptr, size_t num, const char *file, int line)
{
    (void)file;
    (void)line;

    if (fail_enabled && ++alloc_count == fail_at)
        return NULL;

    return realloc(ptr, num);
}

static void test_free(void *ptr, const char *file, int line)
{
    (void)file;
    (void)line;

    free(ptr);
}

static int up_ref(void *p)
{
    (void)p;

    method_refs++;
    return 1;
}

static void down_ref(void *p)
{
    (void)p;

    method_refs--;
}

static int delete_providerless_cache_entry(OSSL_METHOD_STORE *store)
{
    QUERY_KEY key;
    uint8_t keybuf[sizeof(int)];
    size_t keylen = 0;
    int nid = TEST_NID;

    memcpy(&keybuf[keylen], &nid, sizeof(nid));
    keylen += sizeof(nid);
    HT_INIT_KEY_EXTERNAL(&key, keybuf, keylen);

    return ossl_ht_delete(store->algs->cache, TO_HT_KEY(&key));
}

static int property_cache_workload(int expect_success)
{
    static struct ossl_provider_st prov = {
        .flag_initialized = 1,
        .flag_activated = 1,
        .name = "property-memfail"
    };
    OSSL_METHOD_STORE *store = NULL;
    int method = 1;
    void *result = NULL;
    int ret = 0;

    method_refs = 0;

    if ((store = ossl_method_store_new(NULL)) == NULL)
        goto end;
    if (!ossl_method_store_add(store, (OSSL_PROVIDER *)&prov, TEST_NID, "",
            &method, up_ref, down_ref))
        goto end;
    /*
     * Restrict failure injection to the cache paths.  Store setup exercises
     * unrelated global initialization and platform lock allocation.
     */
    alloc_count = 0;
    fail_enabled = 1;
    if (!ossl_method_store_cache_set(store, (OSSL_PROVIDER *)&prov, TEST_NID,
            "", &method, up_ref, down_ref))
        goto end;
    if (!delete_providerless_cache_entry(store))
        goto end;
    if (!ossl_method_store_cache_get(store, NULL, TEST_NID, "", &result)
        || result != &method)
        goto end;
    ret = 1;

end:
    fail_enabled = 0;
    if (result != NULL)
        down_ref(result);
    ossl_method_store_free(store);

    if (method_refs != 0) {
        fprintf(stderr, "method reference leak: %d\n", method_refs);
        return 0;
    }

    return expect_success ? ret : 1;
}

int main(int argc, char **argv)
{
    int ret = EXIT_FAILURE;

    if (argc < 2) {
        fprintf(stderr, "usage: %s count | run <allocation-number>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (!CRYPTO_set_mem_functions(test_malloc, test_realloc, test_free)) {
        fprintf(stderr, "failed to set memory functions\n");
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "count") == 0) {
        if (property_cache_workload(1)) {
            fprintf(stderr, "skip: 0 count %ld\n", alloc_count);
            ret = EXIT_SUCCESS;
        }
    } else if (strcmp(argv[1], "run") == 0 && argc == 3) {
        fail_at = strtol(argv[2], NULL, 10);
        if (fail_at > 0 && property_cache_workload(0))
            ret = EXIT_SUCCESS;
    } else {
        fprintf(stderr, "usage: %s count | run <allocation-number>\n", argv[0]);
    }

    OPENSSL_cleanup();
    return ret;
}
