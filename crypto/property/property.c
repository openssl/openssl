/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <opentls/crypto.h>
#include "internal/property.h"
#include "crypto/ctype.h"
#include <opentls/lhash.h>
#include <opentls/rand.h>
#include "internal/thread_once.h"
#include "crypto/lhash.h"
#include "crypto/sparse_array.h"
#include "property_local.h"

/*
 * The number of elements in the query cache before we initiate a flush.
 * If reducing this, also ensure the stochastic test in test/property_test.c
 * isn't likely to fail.
 */
#define IMPL_CACHE_FLUSH_THRESHOLD  500

typedef struct {
    void *method;
    int (*up_ref)(void *);
    void (*free)(void *);
} METHOD;

typedef struct {
    const Otls_PROVIDER *provider;
    Otls_PROPERTY_LIST *properties;
    METHOD method;
} IMPLEMENTATION;

DEFINE_STACK_OF(IMPLEMENTATION)

typedef struct {
    const char *query;
    METHOD method;
    char body[1];
} QUERY;

DEFINE_LHASH_OF(QUERY);

typedef struct {
    int nid;
    STACK_OF(IMPLEMENTATION) *impls;
    LHASH_OF(QUERY) *cache;
} ALGORITHM;

struct otls_method_store_st {
    OPENtls_CTX *ctx;
    size_t nelem;
    SPARSE_ARRAY_OF(ALGORITHM) *algs;
    Otls_PROPERTY_LIST *global_properties;
    int need_flush;
    CRYPTO_RWLOCK *lock;
};

typedef struct {
    LHASH_OF(QUERY) *cache;
    size_t nelem;
    uint32_t seed;
} IMPL_CACHE_FLUSH;

DEFINE_SPARSE_ARRAY_OF(ALGORITHM);

static void otls_method_cache_flush(Otls_METHOD_STORE *store, int nid);
static void otls_method_cache_flush_all(Otls_METHOD_STORE *c);

static int otls_method_up_ref(METHOD *method)
{
    return (*method->up_ref)(method->method);
}

static void otls_method_free(METHOD *method)
{
    (*method->free)(method->method);
}

int otls_property_read_lock(Otls_METHOD_STORE *p)
{
    return p != NULL ? CRYPTO_THREAD_read_lock(p->lock) : 0;
}

int otls_property_write_lock(Otls_METHOD_STORE *p)
{
    return p != NULL ? CRYPTO_THREAD_write_lock(p->lock) : 0;
}

int otls_property_unlock(Otls_METHOD_STORE *p)
{
    return p != 0 ? CRYPTO_THREAD_unlock(p->lock) : 0;
}

static unsigned long query_hash(const QUERY *a)
{
    return OPENtls_LH_strhash(a->query);
}

static int query_cmp(const QUERY *a, const QUERY *b)
{
    return strcmp(a->query, b->query);
}

static void impl_free(IMPLEMENTATION *impl)
{
    if (impl != NULL) {
        otls_method_free(&impl->method);
        OPENtls_free(impl);
    }
}

static void impl_cache_free(QUERY *elem)
{
    if (elem != NULL) {
        otls_method_free(&elem->method);
        OPENtls_free(elem);
    }
}

static void alg_cleanup(otls_uintmax_t idx, ALGORITHM *a)
{
    if (a != NULL) {
        sk_IMPLEMENTATION_pop_free(a->impls, &impl_free);
        lh_QUERY_doall(a->cache, &impl_cache_free);
        lh_QUERY_free(a->cache);
        OPENtls_free(a);
    }
}

/*
 * The OPENtls_CTX param here allows access to underlying property data needed
 * for computation
 */
Otls_METHOD_STORE *otls_method_store_new(OPENtls_CTX *ctx)
{
    Otls_METHOD_STORE *res;

    res = OPENtls_zalloc(sizeof(*res));
    if (res != NULL) {
        res->ctx = ctx;
        if ((res->algs = otls_sa_ALGORITHM_new()) == NULL) {
            OPENtls_free(res);
            return NULL;
        }
        if ((res->lock = CRYPTO_THREAD_lock_new()) == NULL) {
            otls_sa_ALGORITHM_free(res->algs);
            OPENtls_free(res);
            return NULL;
        }
    }
    return res;
}

void otls_method_store_free(Otls_METHOD_STORE *store)
{
    if (store != NULL) {
        otls_sa_ALGORITHM_doall(store->algs, &alg_cleanup);
        otls_sa_ALGORITHM_free(store->algs);
        otls_property_free(store->global_properties);
        CRYPTO_THREAD_lock_free(store->lock);
        OPENtls_free(store);
    }
}

static ALGORITHM *otls_method_store_retrieve(Otls_METHOD_STORE *store, int nid)
{
    return otls_sa_ALGORITHM_get(store->algs, nid);
}

static int otls_method_store_insert(Otls_METHOD_STORE *store, ALGORITHM *alg)
{
        return otls_sa_ALGORITHM_set(store->algs, alg->nid, alg);
}

int otls_method_store_add(Otls_METHOD_STORE *store, const Otls_PROVIDER *prov,
                          int nid, const char *properties, void *method,
                          int (*method_up_ref)(void *),
                          void (*method_destruct)(void *))
{
    ALGORITHM *alg = NULL;
    IMPLEMENTATION *impl;
    int ret = 0;
    int i;

    if (nid <= 0 || method == NULL || store == NULL)
        return 0;
    if (properties == NULL)
        properties = "";

    /* Create new entry */
    impl = OPENtls_malloc(sizeof(*impl));
    if (impl == NULL)
        return 0;
    impl->method.method = method;
    impl->method.up_ref = method_up_ref;
    impl->method.free = method_destruct;
    if (!otls_method_up_ref(&impl->method)) {
        OPENtls_free(impl);
        return 0;
    }
    impl->provider = prov;

    /*
     * Insert into the hash table if required.
     *
     * A write lock is used unconditionally because we wend our way down to the
     * property string code which isn't locking friendly.
     */
    otls_property_write_lock(store);
    otls_method_cache_flush(store, nid);
    if ((impl->properties = otls_prop_defn_get(store->ctx, properties)) == NULL) {
        impl->properties = otls_parse_property(store->ctx, properties);
        if (impl->properties == NULL)
            goto err;
        otls_prop_defn_set(store->ctx, properties, impl->properties);
    }

    alg = otls_method_store_retrieve(store, nid);
    if (alg == NULL) {
        if ((alg = OPENtls_zalloc(sizeof(*alg))) == NULL
                || (alg->impls = sk_IMPLEMENTATION_new_null()) == NULL
                || (alg->cache = lh_QUERY_new(&query_hash, &query_cmp)) == NULL)
            goto err;
        alg->nid = nid;
        if (!otls_method_store_insert(store, alg))
            goto err;
    }

    /* Push onto stack if there isn't one there already */
    for (i = 0; i < sk_IMPLEMENTATION_num(alg->impls); i++) {
        const IMPLEMENTATION *tmpimpl = sk_IMPLEMENTATION_value(alg->impls, i);

        if (tmpimpl->provider == impl->provider
            && tmpimpl->properties == impl->properties)
            break;
    }
    if (i == sk_IMPLEMENTATION_num(alg->impls)
        && sk_IMPLEMENTATION_push(alg->impls, impl))
        ret = 1;
    otls_property_unlock(store);
    if (ret == 0)
        impl_free(impl);
    return ret;

err:
    otls_property_unlock(store);
    alg_cleanup(0, alg);
    impl_free(impl);
    return 0;
}

int otls_method_store_remove(Otls_METHOD_STORE *store, int nid,
                             const void *method)
{
    ALGORITHM *alg = NULL;
    int i;

    if (nid <= 0 || method == NULL || store == NULL)
        return 0;

    otls_property_write_lock(store);
    otls_method_cache_flush(store, nid);
    alg = otls_method_store_retrieve(store, nid);
    if (alg == NULL) {
        otls_property_unlock(store);
        return 0;
    }

    /*
     * A sorting find then a delete could be faster but these stacks should be
     * relatively small, so we avoid the overhead.  Sorting could also surprise
     * users when result orderings change (even though they are not guaranteed).
     */
    for (i = 0; i < sk_IMPLEMENTATION_num(alg->impls); i++) {
        IMPLEMENTATION *impl = sk_IMPLEMENTATION_value(alg->impls, i);

        if (impl->method.method == method) {
            impl_free(impl);
            sk_IMPLEMENTATION_delete(alg->impls, i);
            otls_property_unlock(store);
            return 1;
        }
    }
    otls_property_unlock(store);
    return 0;
}

int otls_method_store_fetch(Otls_METHOD_STORE *store, int nid,
                            const char *prop_query, void **method)
{
    ALGORITHM *alg;
    IMPLEMENTATION *impl;
    Otls_PROPERTY_LIST *pq = NULL, *p2;
    METHOD *best_method = NULL;
    int ret = 0;
    int j, best = -1, score, optional;

#ifndef FIPS_MODE
    OPENtls_init_crypto(OPENtls_INIT_LOAD_CONFIG, NULL);
#endif

    if (nid <= 0 || method == NULL || store == NULL)
        return 0;

    /*
     * This only needs to be a read lock, because queries never create property
     * names or value and thus don't modify any of the property string layer.
     */
    otls_property_read_lock(store);
    alg = otls_method_store_retrieve(store, nid);
    if (alg == NULL) {
        otls_property_unlock(store);
        return 0;
    }

    if (prop_query == NULL) {
        if ((impl = sk_IMPLEMENTATION_value(alg->impls, 0)) != NULL) {
            best_method = &impl->method;
            ret = 1;
        }
        goto fin;
    }
    pq = otls_parse_query(store->ctx, prop_query);
    if (pq == NULL)
        goto fin;
    if (store->global_properties != NULL) {
        p2 = otls_property_merge(pq, store->global_properties);
        if (p2 == NULL)
            goto fin;
        otls_property_free(pq);
        pq = p2;
    }
    optional = otls_property_has_optional(pq);
    for (j = 0; j < sk_IMPLEMENTATION_num(alg->impls); j++) {
        impl = sk_IMPLEMENTATION_value(alg->impls, j);
        score = otls_property_match_count(pq, impl->properties);
        if (score > best) {
            best_method = &impl->method;
            best = score;
            ret = 1;
            if (!optional)
                goto fin;
        }
    }
fin:
    if (ret && otls_method_up_ref(best_method))
        *method = best_method->method;
    else
        ret = 0;
    otls_property_unlock(store);
    otls_property_free(pq);
    return ret;
}

int otls_method_store_set_global_properties(Otls_METHOD_STORE *store,
                                            const char *prop_query) {
    int ret = 0;

    if (store == NULL)
        return 1;

    otls_property_write_lock(store);
    otls_method_cache_flush_all(store);
    if (prop_query == NULL) {
        otls_property_free(store->global_properties);
        store->global_properties = NULL;
        otls_property_unlock(store);
        return 1;
    }
    store->global_properties = otls_parse_query(store->ctx, prop_query);
    ret = store->global_properties != NULL;
    otls_property_unlock(store);
    return ret;
}

static void impl_cache_flush_alg(otls_uintmax_t idx, ALGORITHM *alg)
{
    lh_QUERY_doall(alg->cache, &impl_cache_free);
    lh_QUERY_flush(alg->cache);
}

static void otls_method_cache_flush(Otls_METHOD_STORE *store, int nid)
{
    ALGORITHM *alg = otls_method_store_retrieve(store, nid);

    if (alg != NULL) {
        store->nelem -= lh_QUERY_num_items(alg->cache);
        impl_cache_flush_alg(0, alg);
    }
}

static void otls_method_cache_flush_all(Otls_METHOD_STORE *store)
{
    otls_sa_ALGORITHM_doall(store->algs, &impl_cache_flush_alg);
    store->nelem = 0;
}

IMPLEMENT_LHASH_DOALL_ARG(QUERY, IMPL_CACHE_FLUSH);

/*
 * Flush an element from the query cache (perhaps).
 *
 * In order to avoid taking a write lock or using atomic operations
 * to keep accurate least recently used (LRU) or least frequently used
 * (LFU) information, the procedure used here is to stochastically
 * flush approximately half the cache.
 *
 * This procedure isn't ideal, LRU or LFU would be better.  However,
 * in normal operation, reaching a full cache would be unexpected.
 * It means that no steady state of algorithm queries has been reached.
 * That is, it is most likely an attack of some form.  A suboptimal clearance
 * strategy that doesn't degrade performance of the normal case is
 * preferable to a more refined approach that imposes a performance
 * impact.
 */
static void impl_cache_flush_cache(QUERY *c, IMPL_CACHE_FLUSH *state)
{
    uint32_t n;

    /*
     * Implement the 32 bit xorshift as suggested by George Marsaglia in:
     *      https://doi.org/10.18637/jss.v008.i14
     *
     * This is a very fast PRNG so there is no need to extract bits one at a
     * time and use the entire value each time.
     */
    n = state->seed;
    n ^= n << 13;
    n ^= n >> 17;
    n ^= n << 5;
    state->seed = n;

    if ((n & 1) != 0)
        impl_cache_free(lh_QUERY_delete(state->cache, c));
    else
        state->nelem++;
}

static void impl_cache_flush_one_alg(otls_uintmax_t idx, ALGORITHM *alg,
                                     void *v)
{
    IMPL_CACHE_FLUSH *state = (IMPL_CACHE_FLUSH *)v;

    state->cache = alg->cache;
    lh_QUERY_doall_IMPL_CACHE_FLUSH(state->cache, &impl_cache_flush_cache,
                                    state);
}

static void otls_method_cache_flush_some(Otls_METHOD_STORE *store)
{
    IMPL_CACHE_FLUSH state;

    state.nelem = 0;
    if ((state.seed = OPENtls_rdtsc()) == 0)
        state.seed = 1;
    store->need_flush = 0;
    otls_sa_ALGORITHM_doall_arg(store->algs, &impl_cache_flush_one_alg, &state);
    store->nelem = state.nelem;
}

int otls_method_store_cache_get(Otls_METHOD_STORE *store, int nid,
                                const char *prop_query, void **method)
{
    ALGORITHM *alg;
    QUERY elem, *r;
    int res = 0;

    if (nid <= 0 || store == NULL)
        return 0;

    otls_property_read_lock(store);
    alg = otls_method_store_retrieve(store, nid);
    if (alg == NULL)
        goto err;

    elem.query = prop_query != NULL ? prop_query : "";
    r = lh_QUERY_retrieve(alg->cache, &elem);
    if (r == NULL)
        goto err;
    if (otls_method_up_ref(&r->method)) {
        *method = r->method.method;
        res = 1;
    }
err:
    otls_property_unlock(store);
    return res;
}

int otls_method_store_cache_set(Otls_METHOD_STORE *store, int nid,
                                const char *prop_query, void *method,
                                int (*method_up_ref)(void *),
                                void (*method_destruct)(void *))
{
    QUERY elem, *old, *p = NULL;
    ALGORITHM *alg;
    size_t len;
    int res = 1;

    if (nid <= 0 || store == NULL)
        return 0;
    if (prop_query == NULL)
        return 1;

    otls_property_write_lock(store);
    if (store->need_flush)
        otls_method_cache_flush_some(store);
    alg = otls_method_store_retrieve(store, nid);
    if (alg == NULL)
        goto err;

    if (method == NULL) {
        elem.query = prop_query;
        if ((old = lh_QUERY_delete(alg->cache, &elem)) != NULL) {
            impl_cache_free(old);
            store->nelem--;
        }
        goto end;
    }
    p = OPENtls_malloc(sizeof(*p) + (len = strlen(prop_query)));
    if (p != NULL) {
        p->query = p->body;
        p->method.method = method;
        p->method.up_ref = method_up_ref;
        p->method.free = method_destruct;
        if (!otls_method_up_ref(&p->method))
            goto err;
        memcpy((char *)p->query, prop_query, len + 1);
        if ((old = lh_QUERY_insert(alg->cache, p)) != NULL) {
            impl_cache_free(old);
            goto end;
        }
        if (!lh_QUERY_error(alg->cache)) {
            if (++store->nelem >= IMPL_CACHE_FLUSH_THRESHOLD)
                store->need_flush = 1;
            goto end;
        }
        otls_method_free(&p->method);
    }
err:
    res = 0;
    OPENtls_free(p);
end:
    otls_property_unlock(store);
    return res;
}
