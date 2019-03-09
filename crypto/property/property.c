/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <openssl/crypto.h>
#include "internal/property.h"
#include "internal/ctype.h"
#include <openssl/lhash.h>
#include <openssl/rand.h>
#include "internal/thread_once.h"
#include "internal/lhash.h"
#include "internal/sparse_array.h"
#include "property_lcl.h"

/* The number of elements in the query cache before we initiate a flush */
#define IMPL_CACHE_FLUSH_THRESHOLD  500

typedef struct {
    OSSL_PROPERTY_LIST *properties;
    void *method;
    void (*method_destruct)(void *);
} IMPLEMENTATION;

DEFINE_STACK_OF(IMPLEMENTATION)

typedef struct {
    const char *query;
    void *method;
    char body[1];
} QUERY;

DEFINE_LHASH_OF(QUERY);

typedef struct {
    int nid;
    STACK_OF(IMPLEMENTATION) *impls;
    LHASH_OF(QUERY) *cache;
} ALGORITHM;

struct ossl_method_store_st {
    size_t nelem;
    SPARSE_ARRAY_OF(ALGORITHM) *algs;
    OSSL_PROPERTY_LIST *global_properties;
    int need_flush;
    unsigned int nbits;
    unsigned char rand_bits[(IMPL_CACHE_FLUSH_THRESHOLD + 7) / 8];
    CRYPTO_RWLOCK *lock;
};

typedef struct {
    OSSL_METHOD_STORE *store;
    LHASH_OF(QUERY) *cache;
    size_t nelem;
} IMPL_CACHE_FLUSH;

DEFINE_SPARSE_ARRAY_OF(ALGORITHM);

static void ossl_method_cache_flush(OSSL_METHOD_STORE *store, int nid);
static void ossl_method_cache_flush_all(OSSL_METHOD_STORE *c);

int ossl_property_read_lock(OSSL_METHOD_STORE *p)
{
    return p != NULL ? CRYPTO_THREAD_read_lock(p->lock) : 0;
}

int ossl_property_write_lock(OSSL_METHOD_STORE *p)
{
    return p != NULL ? CRYPTO_THREAD_write_lock(p->lock) : 0;
}

int ossl_property_unlock(OSSL_METHOD_STORE *p)
{
    return p != 0 ? CRYPTO_THREAD_unlock(p->lock) : 0;
}

int ossl_method_store_init(void)
{
    if (ossl_property_string_init()
            && ossl_prop_defn_init()
            && ossl_property_parse_init())
        return 1;

    ossl_method_store_cleanup();
    return 0;
}

void ossl_method_store_cleanup(void)
{
    ossl_property_string_cleanup();
    ossl_prop_defn_cleanup();
}

static CRYPTO_ONCE method_store_init_flag = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_method_store_init)
{
    return OPENSSL_init_crypto(0, NULL)
        && ossl_method_store_init()
        && OPENSSL_atexit(&ossl_method_store_cleanup);
}

static unsigned long query_hash(const QUERY *a)
{
    return OPENSSL_LH_strhash(a->query);
}

static int query_cmp(const QUERY *a, const QUERY *b)
{
    return strcmp(a->query, b->query);
}

static void impl_free(IMPLEMENTATION *impl)
{
    if (impl != NULL) {
        if (impl->method_destruct)
            impl->method_destruct(impl->method);
        OPENSSL_free(impl);
    }
}

static void impl_cache_free(QUERY *elem)
{
    OPENSSL_free(elem);
}

static void alg_cleanup(ossl_uintmax_t idx, ALGORITHM *a)
{
    if (a != NULL) {
        sk_IMPLEMENTATION_pop_free(a->impls, &impl_free);
        lh_QUERY_doall(a->cache, &impl_cache_free);
        lh_QUERY_free(a->cache);
        OPENSSL_free(a);
    }
}

OSSL_METHOD_STORE *ossl_method_store_new(void)
{
    OSSL_METHOD_STORE *res;

    if (!RUN_ONCE(&method_store_init_flag, do_method_store_init))
        return 0;

    res = OPENSSL_zalloc(sizeof(*res));
    if (res != NULL) {
        if ((res->algs = ossl_sa_ALGORITHM_new()) == NULL) {
            OPENSSL_free(res);
            return NULL;
        }
        if ((res->lock = CRYPTO_THREAD_lock_new()) == NULL) {
            OPENSSL_free(res->algs);
            OPENSSL_free(res);
            return NULL;
        }
    }
    return res;
}

void ossl_method_store_free(OSSL_METHOD_STORE *store)
{
    if (store != NULL) {
        ossl_sa_ALGORITHM_doall(store->algs, &alg_cleanup);
        ossl_sa_ALGORITHM_free(store->algs);
        ossl_property_free(store->global_properties);
        CRYPTO_THREAD_lock_free(store->lock);
        OPENSSL_free(store);
    }
}

static ALGORITHM *ossl_method_store_retrieve(OSSL_METHOD_STORE *store, int nid)
{
    return ossl_sa_ALGORITHM_get(store->algs, nid);
}

static int ossl_method_store_insert(OSSL_METHOD_STORE *store, ALGORITHM *alg)
{
        return ossl_sa_ALGORITHM_set(store->algs, alg->nid, alg);
}

int ossl_method_store_add(OSSL_METHOD_STORE *store,
                          int nid, const char *properties,
                          void *method, void (*method_destruct)(void *))
{
    ALGORITHM *alg = NULL;
    IMPLEMENTATION *impl;
    int ret = 0;

    if (nid <= 0 || method == NULL || store == NULL)
        return 0;
    if (properties == NULL)
        properties = "";

    /* Create new entry */
    impl = OPENSSL_malloc(sizeof(*impl));
    if (impl == NULL)
        return 0;
    impl->method = method;
    impl->method_destruct = method_destruct;

    /*
     * Insert into the hash table if required.
     *
     * A write lock is used unconditionally because we wend our way down to the
     * property string code which isn't locking friendly.
     */
    ossl_property_write_lock(store);
    ossl_method_cache_flush(store, nid);
    if ((impl->properties = ossl_prop_defn_get(properties)) == NULL) {
        if ((impl->properties = ossl_parse_property(properties)) == NULL)
            goto err;
        ossl_prop_defn_set(properties, impl->properties);
    }

    alg = ossl_method_store_retrieve(store, nid);
    if (alg == NULL) {
        if ((alg = OPENSSL_zalloc(sizeof(*alg))) == NULL
                || (alg->impls = sk_IMPLEMENTATION_new_null()) == NULL
                || (alg->cache = lh_QUERY_new(&query_hash, &query_cmp)) == NULL)
            goto err;
        alg->nid = nid;
        if (!ossl_method_store_insert(store, alg))
            goto err;
    }

    /* Push onto stack */
    if (sk_IMPLEMENTATION_push(alg->impls, impl))
        ret = 1;
    ossl_property_unlock(store);
    if (ret == 0)
        impl_free(impl);
    return ret;

err:
    ossl_property_unlock(store);
    alg_cleanup(0, alg);
    impl_free(impl);
    return 0;
}

int ossl_method_store_remove(OSSL_METHOD_STORE *store, int nid,
                             const void *method)
{
    ALGORITHM *alg = NULL;
    int i;

    if (nid <= 0 || method == NULL || store == NULL)
        return 0;

    ossl_property_write_lock(store);
    ossl_method_cache_flush(store, nid);
    alg = ossl_method_store_retrieve(store, nid);
    if (alg == NULL) {
        ossl_property_unlock(store);
        return 0;
    }

    /*
     * A sorting find then a delete could be faster but these stacks should be
     * relatively small, so we avoid the overhead.  Sorting could also surprise
     * users when result orderings change (even though they are not guaranteed).
     */
    for (i = 0; i < sk_IMPLEMENTATION_num(alg->impls); i++) {
        IMPLEMENTATION *impl = sk_IMPLEMENTATION_value(alg->impls, i);

        if (impl->method == method) {
            sk_IMPLEMENTATION_delete(alg->impls, i);
            ossl_property_unlock(store);
            impl_free(impl);
            return 1;
        }
    }
    ossl_property_unlock(store);
    return 0;
}

int ossl_method_store_fetch(OSSL_METHOD_STORE *store, int nid,
                            const char *prop_query, void **method)
{
    ALGORITHM *alg;
    IMPLEMENTATION *impl;
    OSSL_PROPERTY_LIST *pq = NULL, *p2;
    int ret = 0;
    int j;

    if (nid <= 0 || method == NULL || store == NULL)
        return 0;

    /*
     * This only needs to be a read lock, because queries never create property
     * names or value and thus don't modify any of the property string layer.
     */
    ossl_property_read_lock(store);
    alg = ossl_method_store_retrieve(store, nid);
    if (alg == NULL) {
        ossl_property_unlock(store);
        return 0;
    }

    if (prop_query == NULL) {
        if ((impl = sk_IMPLEMENTATION_value(alg->impls, 0)) != NULL) {
            *method = impl->method;
            ret = 1;
        }
        goto fin;
    }
    pq = ossl_parse_query(prop_query);
    if (pq == NULL)
        goto fin;
    if (store->global_properties != NULL) {
        p2 = ossl_property_merge(pq, store->global_properties);
        if (p2 == NULL)
            goto fin;
        ossl_property_free(pq);
        pq = p2;
    }
    for (j = 0; j < sk_IMPLEMENTATION_num(alg->impls); j++) {
        impl = sk_IMPLEMENTATION_value(alg->impls, j);

        if (ossl_property_match(pq, impl->properties)) {
            *method = impl->method;
            ret = 1;
            goto fin;
        }
    }
fin:
    ossl_property_unlock(store);
    ossl_property_free(pq);
    return ret;
}

int ossl_method_store_set_global_properties(OSSL_METHOD_STORE *store,
                                            const char *prop_query) {
    int ret = 0;

    if (store == NULL)
        return 1;

    ossl_property_write_lock(store);
    ossl_method_cache_flush_all(store);
    if (prop_query == NULL) {
        ossl_property_free(store->global_properties);
        store->global_properties = NULL;
        ossl_property_unlock(store);
        return 1;
    }
    store->global_properties = ossl_parse_query(prop_query);
    ret = store->global_properties != NULL;
    ossl_property_unlock(store);
    return ret;
}

static void impl_cache_flush_alg(ossl_uintmax_t idx, ALGORITHM *alg)
{
    lh_QUERY_doall(alg->cache, &impl_cache_free);
    lh_QUERY_flush(alg->cache);
}

static void ossl_method_cache_flush(OSSL_METHOD_STORE *store, int nid)
{
    ALGORITHM *alg = ossl_method_store_retrieve(store, nid);

    if (alg != NULL) {
        store->nelem -= lh_QUERY_num_items(alg->cache);
        impl_cache_flush_alg(0, alg);
    }
}

static void ossl_method_cache_flush_all(OSSL_METHOD_STORE *store)
{
    ossl_sa_ALGORITHM_doall(store->algs, &impl_cache_flush_alg);
    store->nelem = 0;
}

IMPLEMENT_LHASH_DOALL_ARG(QUERY, IMPL_CACHE_FLUSH);

/*
 * Flush an element from the query cache (perhaps).
 *
 * In order to avoid taking a write lock to keep accurate LRU information or
 * using atomic operations to approximate similar, the procedure used here
 * is to stochastically flush approximately half the cache.  Since generating
 * random numbers is relatively expensive, we produce them in blocks and
 * consume them as we go, saving generated bits between generations of flushes.
 *
 * This procedure isn't ideal, LRU would be better.  However, in normal
 * operation, reaching a full cache would be quite unexpected.  It means
 * that no steady state of algorithm queries has been reached.  I.e. it is most
 * likely an attack of some form.  A suboptimal clearance strategy that doesn't
 * degrade performance of the normal case is preferable to a more refined
 * approach that imposes a performance impact.
 */
static void impl_cache_flush_cache(QUERY *c, IMPL_CACHE_FLUSH *state)
{
    OSSL_METHOD_STORE *store = state->store;
    unsigned int n;

    if (store->nbits == 0) {
        if (!RAND_bytes(store->rand_bits, sizeof(store->rand_bits)))
            return;
        store->nbits = sizeof(store->rand_bits) * 8;
    }
    n = --store->nbits;
    if ((store->rand_bits[n >> 3] & (1 << (n & 7))) != 0)
        OPENSSL_free(lh_QUERY_delete(state->cache, c));
    else
        state->nelem++;
}

static void impl_cache_flush_one_alg(ossl_uintmax_t idx, ALGORITHM *alg,
                                     void *v)
{
    IMPL_CACHE_FLUSH *state = (IMPL_CACHE_FLUSH *)v;

    state->cache = alg->cache;
    lh_QUERY_doall_IMPL_CACHE_FLUSH(state->cache, &impl_cache_flush_cache,
                                    state);
}

static void ossl_method_cache_flush_some(OSSL_METHOD_STORE *store)
{
    IMPL_CACHE_FLUSH state;

    state.nelem = 0;
    state.store = store;
    ossl_sa_ALGORITHM_doall_arg(store->algs, &impl_cache_flush_one_alg, &state);
    store->need_flush = 0;
    store->nelem = state.nelem;
}

int ossl_method_store_cache_get(OSSL_METHOD_STORE *store, int nid,
                                const char *prop_query, void **method)
{
    ALGORITHM *alg;
    QUERY elem, *r;

    if (nid <= 0 || store == NULL)
        return 0;

    ossl_property_read_lock(store);
    alg = ossl_method_store_retrieve(store, nid);
    if (alg == NULL) {
        ossl_property_unlock(store);
        return 0;
    }

    elem.query = prop_query;
    r = lh_QUERY_retrieve(alg->cache, &elem);
    if (r == NULL) {
        ossl_property_unlock(store);
        return 0;
    }
    *method = r->method;
    ossl_property_unlock(store);
    return 1;
}

int ossl_method_store_cache_set(OSSL_METHOD_STORE *store, int nid,
                                const char *prop_query, void *method)
{
    QUERY elem, *old, *p = NULL;
    ALGORITHM *alg;
    size_t len;

    if (nid <= 0 || store == NULL)
        return 0;
    if (prop_query == NULL)
        return 1;

    ossl_property_write_lock(store);
    if (store->need_flush)
        ossl_method_cache_flush_some(store);
    alg = ossl_method_store_retrieve(store, nid);
    if (alg == NULL) {
        ossl_property_unlock(store);
        return 0;
    }

    if (method == NULL) {
        elem.query = prop_query;
        lh_QUERY_delete(alg->cache, &elem);
        ossl_property_unlock(store);
        return 1;
    }
    p = OPENSSL_malloc(sizeof(*p) + (len = strlen(prop_query)));
    if (p != NULL) {
        p->query = p->body;
        p->method = method;
        memcpy((char *)p->query, prop_query, len + 1);
        if ((old = lh_QUERY_insert(alg->cache, p)) != NULL)
            OPENSSL_free(old);
        if (old != NULL || !lh_QUERY_error(alg->cache)) {
            store->nelem++;
            if (store->nelem >= IMPL_CACHE_FLUSH_THRESHOLD)
                store->need_flush = 1;
            ossl_property_unlock(store);
            return 1;
        }
    }
    ossl_property_unlock(store);
    OPENSSL_free(p);
    return 0;
}
