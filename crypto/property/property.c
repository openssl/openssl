/*
 * Copyright 2019-2025 The OpenSSL Project Authors. All Rights Reserved.
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
#include <openssl/provider.h>
#include "internal/property.h"
#include "internal/provider.h"
#include "internal/hashtable.h"
#include "internal/tsan_assist.h"
#include "internal/list.h"
#include "internal/hashfunc.h"
#include "internal/time.h"
#include <openssl/lhash.h>
#include <openssl/rand.h>
#include <openssl/trace.h>
#include "crypto/sparse_array.h"
#include "property_local.h"
#include "crypto/context.h"

/*
 * The shard count was determined through performance testing with the evp_fetch
 * tool on an Intel Xeon Gold 6248R CPU @ 3.00GHz. Testing showed that 4 shards
 * combined with CACHE_SIZE delivered the best performance for 16 or
 * more threads, and close to best performance at below 16 threads.
 */
#ifndef NUM_SHARDS
#define NUM_SHARDS 4
#endif

#ifndef CACHE_SIZE
#define CACHE_SIZE 512
#endif

/*
 * To keep random cull distributions from being unbiased, we should keep both
 * CACHE_SIZE and NUM_SHARDS as powers of 2
 */
#if (CACHE_SIZE != 0 && (CACHE_SIZE & (CACHE_SIZE - 1)))
#error "CACHE_SIZE must be a power of 2"
#endif

#if (NUM_SHARDS != 0 && (NUM_SHARDS & (NUM_SHARDS - 1)))
#error "NUM_SHARDS must be a power of 2"
#endif
/*
 * The number of elements in the query cache before we initiate a flush.
 * If reducing this, also ensure the stochastic test in test/property_test.c
 * isn't likely to fail.
 */
#define IMPL_CACHE_FLUSH_THRESHOLD (CACHE_SIZE / NUM_SHARDS)

#if defined(__GNUC__) || defined(__clang__)
/*
 * ALLOW_VLA enables the use of dynamically sized arrays
 * in ossl_method_store_cache_[get|set].  This is done for
 * performance reasons, as moving the stack pointer is
 * way faster than getting memory from heap.  This introduces
 * the potential for stack overflows, but we check for that
 * by capping the size of the buffer to a large value
 * MAX_PROP_QUERY as there shouldn't be any property queries that long.
 */
#define ALLOW_VLA
#endif

/*
 * Max allowed length of our property query
 */
#define MAX_PROP_QUERY 4096

typedef struct {
    void *method;
    int (*up_ref)(void *);
    void (*free)(void *);
} METHOD;

typedef struct {
    const OSSL_PROVIDER *provider;
    OSSL_PROPERTY_LIST *properties;
    METHOD method;
} IMPLEMENTATION;

DEFINE_STACK_OF(IMPLEMENTATION)

typedef struct query_st {
    OSSL_LIST_MEMBER(lru_entry, struct query_st); /* member of our linked list */
    void *saptr; /* pointer to our owning STORED_ALGORITHM */
    int nid; /* nid of this query */
    uint64_t specific_hash; /* hash of [nid,prop_query,prov] tuple */
    uint64_t generic_hash; /* hash of [nid,prop_query] tuple */
    METHOD method; /* METHOD for this query */
    TSAN_QUALIFIER uint32_t used; /* flag to indicate used since last cull */
} QUERY;

/*
 * This is our key to lookup queries
 * It has no key data as we allocate and marshall
 * it dynamically in ossl_method_store_cache_[set|get]
 */
typedef struct query_key {
    HT_KEY key_header;
} QUERY_KEY;

IMPLEMENT_HT_VALUE_TYPE_FNS(QUERY, cache, static)

DEFINE_LIST_OF(lru_entry, QUERY);

typedef OSSL_LIST(lru_entry) QUERY_LRU_LIST;

typedef struct {
    int nid;
    STACK_OF(IMPLEMENTATION) *impls;
} ALGORITHM;

typedef struct {
    SPARSE_ARRAY_OF(ALGORITHM) * algs;

    HT *cache;
    /*
     * This is a list of every element in our query
     * cache.  NOTE: Its named lru list, but to avoid
     * having to remove/insert to the list a bunch, it
     * actually just uses a heuristic with the QUERY used
     * flag to identify recently used QUERY elements
     */
    QUERY_LRU_LIST lru_list;
    /*
     * Lock to protect each shard of |algs| from concurrent writing,
     * when individual implementations or queries are inserted.  This is used
     * by the appropriate functions here.
     */
    CRYPTO_RWLOCK *lock;

    /* query cache specific values */

} STORED_ALGORITHMS;

struct ossl_method_store_st {
    OSSL_LIB_CTX *ctx;
    STORED_ALGORITHMS *algs;
    /*
     * Lock to reserve the whole store.  This is used when fetching a set
     * of algorithms, via these functions, found in crypto/core_fetch.c:
     * ossl_method_construct_reserve_store()
     * ossl_method_construct_unreserve_store()
     */
    CRYPTO_RWLOCK *biglock;
};

DEFINE_SPARSE_ARRAY_OF(ALGORITHM);

DEFINE_STACK_OF(ALGORITHM)

typedef struct ossl_global_properties_st {
    OSSL_PROPERTY_LIST *list;
#ifndef FIPS_MODULE
    unsigned int no_mirrored : 1;
#endif
} OSSL_GLOBAL_PROPERTIES;

#define stored_algs_shard(store, nid) (&(store)->algs[(nid) & (NUM_SHARDS - 1)])

static void ossl_method_cache_flush_alg(STORED_ALGORITHMS *sa,
    ALGORITHM *alg);
static void ossl_method_cache_flush(STORED_ALGORITHMS *sa, int nid);

/* Global properties are stored per library context */
void ossl_ctx_global_properties_free(void *vglobp)
{
    OSSL_GLOBAL_PROPERTIES *globp = vglobp;

    if (globp != NULL) {
        ossl_property_free(globp->list);
        OPENSSL_free(globp);
    }
}

void *ossl_ctx_global_properties_new(OSSL_LIB_CTX *ctx)
{
    return OPENSSL_zalloc(sizeof(OSSL_GLOBAL_PROPERTIES));
}

OSSL_PROPERTY_LIST **ossl_ctx_global_properties(OSSL_LIB_CTX *libctx,
    ossl_unused int loadconfig)
{
    OSSL_GLOBAL_PROPERTIES *globp;

#if !defined(FIPS_MODULE) && !defined(OPENSSL_NO_AUTOLOAD_CONFIG)
    if (loadconfig && !OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL))
        return NULL;
#endif
    globp = ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_GLOBAL_PROPERTIES);

    return globp != NULL ? &globp->list : NULL;
}

#ifndef FIPS_MODULE
int ossl_global_properties_no_mirrored(OSSL_LIB_CTX *libctx)
{
    OSSL_GLOBAL_PROPERTIES *globp
        = ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_GLOBAL_PROPERTIES);

    return globp != NULL && globp->no_mirrored ? 1 : 0;
}

void ossl_global_properties_stop_mirroring(OSSL_LIB_CTX *libctx)
{
    OSSL_GLOBAL_PROPERTIES *globp
        = ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_GLOBAL_PROPERTIES);

    if (globp != NULL)
        globp->no_mirrored = 1;
}
#endif

static int ossl_method_up_ref(METHOD *method)
{
    return (*method->up_ref)(method->method);
}

static void ossl_method_free(METHOD *method)
{
    (*method->free)(method->method);
}

static __owur int ossl_property_read_lock(STORED_ALGORITHMS *p)
{
    return p != NULL ? CRYPTO_THREAD_read_lock(p->lock) : 0;
}

static __owur int ossl_property_write_lock(STORED_ALGORITHMS *p)
{
    return p != NULL ? CRYPTO_THREAD_write_lock(p->lock) : 0;
}

static int ossl_property_unlock(STORED_ALGORITHMS *p)
{
    return p != 0 ? CRYPTO_THREAD_unlock(p->lock) : 0;
}

static void impl_free(IMPLEMENTATION *impl)
{
    if (impl != NULL) {
        ossl_method_free(&impl->method);
        OPENSSL_free(impl);
    }
}

static ossl_inline void impl_cache_free(QUERY *elem)
{
    if (elem != NULL) {
        STORED_ALGORITHMS *sa = elem->saptr;

#ifndef NDEBUG
        if (elem->ossl_list_lru_entry.list != NULL)
            ossl_list_lru_entry_remove(&sa->lru_list, elem);
#else
        ossl_list_lru_entry_remove(&sa->lru_list, elem);
#endif
        ossl_method_free(&elem->method);
        OPENSSL_free(elem);
    }
}

/*
 * This is the registered free function for all of our
 * allocated QUERY hashtables
 */
static void query_free(HT_VALUE *v)
{
    QUERY *elem = ossl_ht_cache_QUERY_from_value(v);
    impl_cache_free(elem);
}

static void impl_cache_flush_alg(ALGORITHM *alg, STORED_ALGORITHMS *sa)
{
    QUERY *q, *qn;
    uint64_t hash;
    QUERY_KEY key;

    /*
     * Instead of iterating over the hashtable with the
     * ossl_ht_foreach_until function, we just traverse the
     * linked list, as it much faster this way, as we avoid having
     * to visit lots of potentially empty nodes
     */
    OSSL_LIST_FOREACH_DELSAFE(q, qn, lru_entry, &sa->lru_list)
    {
        /*
         * Check for a match by nid, as we're only deleting QUERY elements
         * that are for the nid specified in alg
         */
        if (q->nid == alg->nid) {
            /*
             * We can accelerate hash table operations here, by creating a key
             * with a cached hash value, to avoid having to compute it again
             * NOTE: Each QUERY contains 2 possible hash values, that we use in
             * a priority order.  Every QUERY has a generic_hash, which is the computed
             * hash of the [nid, prop_query] tuple, and may have a specific_hash,
             * which is the computed has of the [nid, prop_query, provider] tuple.
             * We use the specific hash if its available, otherwise use the
             * generic_hash
             */
            hash = (q->specific_hash != 0) ? q->specific_hash : q->generic_hash;
            HT_INIT_KEY_CACHED(&key, hash);
            ossl_ht_delete(sa->cache, TO_HT_KEY(&key));
        }
    }
}

static void alg_cleanup(ossl_uintmax_t idx, ALGORITHM *a, void *arg)
{
    STORED_ALGORITHMS *sa = arg;

    if (a != NULL) {
        sk_IMPLEMENTATION_pop_free(a->impls, &impl_free);
        OPENSSL_free(a);
    }
    if (sa != NULL)
        ossl_sa_ALGORITHM_set(sa->algs, idx, NULL);
}

static void stored_algs_free(STORED_ALGORITHMS *sa)
{
    if (sa == NULL)
        return;

    for (int i = 0; i < NUM_SHARDS; ++i) {
        ossl_sa_ALGORITHM_doall_arg(sa[i].algs, &alg_cleanup, &sa[i]);
        ossl_sa_ALGORITHM_free(sa[i].algs);
        CRYPTO_THREAD_lock_free(sa[i].lock);
        ossl_ht_free(sa[i].cache);
    }

    OPENSSL_free(sa);
}

static STORED_ALGORITHMS *stored_algs_new(OSSL_LIB_CTX *ctx)
{
    STORED_ALGORITHMS *ret;
    HT_CONFIG ht_conf = {
        .ctx = ctx,
        .ht_free_fn = query_free,
        .ht_hash_fn = NULL,
        .init_neighborhoods = 1,
        .collision_check = 1,
        .lockless_reads = 0,
        .no_rcu = 1
    };

    ret = OPENSSL_calloc(NUM_SHARDS, sizeof(STORED_ALGORITHMS));
    if (ret == NULL)
        return NULL;

    for (int i = 0; i < NUM_SHARDS; ++i) {
        ret[i].algs = ossl_sa_ALGORITHM_new();
        if (ret[i].algs == NULL)
            goto err;

        ret[i].lock = CRYPTO_THREAD_lock_new();
        if (ret[i].lock == NULL)
            goto err;
        ret[i].cache = ossl_ht_new(&ht_conf);
        if (ret[i].cache == NULL)
            goto err;
    }

    return ret;

err:
    stored_algs_free(ret);

    return NULL;
}

/*
 * The OSSL_LIB_CTX param here allows access to underlying property data needed
 * for computation
 */
OSSL_METHOD_STORE *ossl_method_store_new(OSSL_LIB_CTX *ctx)
{
    OSSL_METHOD_STORE *res;

    res = OPENSSL_zalloc(sizeof(*res));
    if (res != NULL) {
        res->ctx = ctx;
        if ((res->algs = stored_algs_new(ctx)) == NULL
            || (res->biglock = CRYPTO_THREAD_lock_new()) == NULL) {
            ossl_method_store_free(res);
            return NULL;
        }
    }
    return res;
}

void ossl_method_store_free(OSSL_METHOD_STORE *store)
{
    if (store == NULL)
        return;

    stored_algs_free(store->algs);
    CRYPTO_THREAD_lock_free(store->biglock);
    OPENSSL_free(store);
}

int ossl_method_lock_store(OSSL_METHOD_STORE *store)
{
    return store != NULL ? CRYPTO_THREAD_write_lock(store->biglock) : 0;
}

int ossl_method_unlock_store(OSSL_METHOD_STORE *store)
{
    return store != NULL ? CRYPTO_THREAD_unlock(store->biglock) : 0;
}

static ALGORITHM *ossl_method_store_retrieve(STORED_ALGORITHMS *sa, int nid)
{
    return ossl_sa_ALGORITHM_get(sa->algs, nid);
}

static int ossl_method_store_insert(STORED_ALGORITHMS *sa, ALGORITHM *alg)
{
    return ossl_sa_ALGORITHM_set(sa->algs, alg->nid, alg);
}

/**
 * @brief Adds a method to the specified method store.
 *
 * This function adds a new method to the provided method store, associating it
 * with a specified id, properties, and provider. The method is stored with
 * reference count and destruction callbacks.
 *
 * @param store Pointer to the OSSL_METHOD_STORE where the method will be added.
 *              Must be non-null.
 * @param prov Pointer to the OSSL_PROVIDER for the provider of the method.
 *             Must be non-null.
 * @param nid (identifier) associated with the method, must be > 0
 * @param properties String containing properties of the method.
 * @param method Pointer to the method to be added.
 * @param method_up_ref Function pointer for incrementing the method ref count.
 * @param method_destruct Function pointer for destroying the method.
 *
 * @return 1 if the method is successfully added, 0 on failure.
 *
 * If tracing is enabled, a message is printed indicating that the method is
 * being added to the method store.
 *
 * NOTE: The nid parameter here is _not_ a nid in the sense of the NID_* macros.
 * It is an internal unique identifier.
 */
int ossl_method_store_add(OSSL_METHOD_STORE *store, const OSSL_PROVIDER *prov,
    int nid, const char *properties, void *method,
    int (*method_up_ref)(void *),
    void (*method_destruct)(void *))
{
    STORED_ALGORITHMS *sa;
    ALGORITHM *alg = NULL;
    IMPLEMENTATION *impl;
    int ret = 0;
    int i;

    if (nid <= 0 || method == NULL || store == NULL)
        return 0;

    if (properties == NULL)
        properties = "";

    if (!ossl_assert(prov != NULL))
        return 0;

    /* Create new entry */
    impl = OPENSSL_malloc(sizeof(*impl));
    if (impl == NULL)
        return 0;
    impl->method.method = method;
    impl->method.up_ref = method_up_ref;
    impl->method.free = method_destruct;
    if (!ossl_method_up_ref(&impl->method)) {
        OPENSSL_free(impl);
        return 0;
    }
    impl->provider = prov;

    sa = stored_algs_shard(store, nid);

    /* Insert into the hash table if required */
    if (!ossl_property_write_lock(sa)) {
        impl_free(impl);
        return 0;
    }

    /*
     * Flush the alg cache of any implementation that already exists
     * for this id.
     * This is done to ensure that on the next lookup we go through the
     * provider comparison in ossl_method_store_fetch.  If we don't do this
     * then this new method won't be given a chance to get selected.
     * NOTE: This doesn't actually remove the method from the backing store
     * It just ensures that we query the backing store when (re)-adding a
     * method to the algorithm cache, in case the one selected by the next
     * query selects a different implementation
     */
    ossl_method_cache_flush(sa, nid);

    /*
     * Parse the properties associated with this method, and convert it to a
     * property list stored against the implementation for later comparison
     * during fetch operations
     */
    if ((impl->properties = ossl_prop_defn_get(store->ctx, properties)) == NULL) {
        impl->properties = ossl_parse_property(store->ctx, properties);
        if (impl->properties == NULL)
            goto err;
        if (!ossl_prop_defn_set(store->ctx, properties, &impl->properties)) {
            ossl_property_free(impl->properties);
            impl->properties = NULL;
            goto err;
        }
    }

    /*
     * Check if we have an algorithm cache already for this nid.  If so use
     * it, otherwise, create it, and insert it into the store
     */
    alg = ossl_method_store_retrieve(sa, nid);
    if (alg == NULL) {
        if ((alg = OPENSSL_zalloc(sizeof(*alg))) == NULL
            || (alg->impls = sk_IMPLEMENTATION_new_null()) == NULL)
            goto err;
        alg->nid = nid;
        if (!ossl_method_store_insert(sa, alg))
            goto err;
        OSSL_TRACE2(QUERY, "Inserted an alg with nid %d into the stored algorithms %p\n",
            nid, (void *)sa);
    }

    /* Push onto stack if there isn't one there already */
    for (i = 0; i < sk_IMPLEMENTATION_num(alg->impls); i++) {
        const IMPLEMENTATION *tmpimpl = sk_IMPLEMENTATION_value(alg->impls, i);

        if (tmpimpl->provider == impl->provider
            && tmpimpl->properties == impl->properties)
            break;
    }

    if (i == sk_IMPLEMENTATION_num(alg->impls)
        && sk_IMPLEMENTATION_push(alg->impls, impl)) {
        ret = 1;
#ifndef FIPS_MODULE
        OSSL_TRACE_BEGIN(QUERY)
        {
            BIO_printf(trc_out, "Adding to method store "
                                "nid: %d\nproperties: %s\nprovider: %s\n",
                nid, properties,
                ossl_provider_name(prov) == NULL ? "none" : ossl_provider_name(prov));
        }
        OSSL_TRACE_END(QUERY);
#endif
    }
    ossl_property_unlock(sa);
    if (ret == 0)
        impl_free(impl);
    return ret;

err:
    ossl_property_unlock(sa);
    alg_cleanup(0, alg, NULL);
    impl_free(impl);
    return 0;
}

int ossl_method_store_remove(OSSL_METHOD_STORE *store, int nid,
    const void *method)
{
    ALGORITHM *alg = NULL;
    STORED_ALGORITHMS *sa;
    int i;

    if (nid <= 0 || method == NULL || store == NULL)
        return 0;

    sa = stored_algs_shard(store, nid);
    if (!ossl_property_write_lock(sa))
        return 0;
    ossl_method_cache_flush(sa, nid);
    alg = ossl_method_store_retrieve(sa, nid);
    if (alg == NULL) {
        ossl_property_unlock(sa);
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
            (void)sk_IMPLEMENTATION_delete(alg->impls, i);
            ossl_property_unlock(sa);
            return 1;
        }
    }
    ossl_property_unlock(sa);
    return 0;
}

struct alg_cleanup_by_provider_data_st {
    STORED_ALGORITHMS *sa;
    const OSSL_PROVIDER *prov;
};

/**
 * @brief Cleans up implementations of an algorithm associated with a provider.
 *
 * This function removes all implementations of a specified algorithm that are
 * associated with a given provider. The function walks through the stack of
 * implementations backwards to handle deletions without affecting indexing.
 *
 * @param idx Index of the algorithm (unused in this function).
 * @param alg Pointer to the ALGORITHM structure containing the implementations.
 * @param arg Pointer to the data containing the provider information.
 *
 * If tracing is enabled, messages are printed indicating the removal of each
 * implementation and its properties. If any implementation is removed, the
 * associated cache is flushed.
 */
static void
alg_cleanup_by_provider(ossl_uintmax_t idx, ALGORITHM *alg, void *arg)
{
    struct alg_cleanup_by_provider_data_st *data = arg;
    int i, count;

    /*
     * We walk the stack backwards, to avoid having to deal with stack shifts
     * caused by deletion
     */
    for (count = 0, i = sk_IMPLEMENTATION_num(alg->impls); i-- > 0;) {
        IMPLEMENTATION *impl = sk_IMPLEMENTATION_value(alg->impls, i);

        if (impl->provider == data->prov) {
#ifndef FIPS_MODULE
            OSSL_TRACE_BEGIN(QUERY)
            {
                char buf[512];
                size_t size;

                size = ossl_property_list_to_string(NULL, impl->properties, buf,
                    sizeof(buf));
                BIO_printf(trc_out, "Removing implementation from "
                                    "query cache\nproperties %s\nprovider %s\n",
                    size == 0 ? "none" : buf,
                    ossl_provider_name(impl->provider) == NULL ? "none" : ossl_provider_name(impl->provider));
            }
            OSSL_TRACE_END(QUERY);
#endif

            (void)sk_IMPLEMENTATION_delete(alg->impls, i);
            count++;
            impl_free(impl);
        }
    }

    /*
     * If we removed any implementation, we also clear the whole associated
     * cache, 'cause that's the sensible thing to do.
     * There's no point flushing the cache entries where we didn't remove
     * any implementation, though.
     */
    if (count > 0)
        ossl_method_cache_flush_alg(data->sa, alg);
}

int ossl_method_store_remove_all_provided(OSSL_METHOD_STORE *store,
    const OSSL_PROVIDER *prov)
{
    struct alg_cleanup_by_provider_data_st data;

    for (int k = 0; k < NUM_SHARDS; ++k) {
        STORED_ALGORITHMS *sa = &store->algs[k];

        if (!ossl_property_write_lock(sa))
            return 0;
        data.prov = prov;
        data.sa = sa;
        ossl_sa_ALGORITHM_doall_arg(sa->algs, &alg_cleanup_by_provider, &data);
        ossl_property_unlock(sa);
    }
    return 1;
}

static void alg_do_one(ALGORITHM *alg, IMPLEMENTATION *impl,
    void (*fn)(int id, void *method, void *fnarg),
    void *fnarg)
{
    fn(alg->nid, impl->method.method, fnarg);
}

static void alg_copy(ossl_uintmax_t idx, ALGORITHM *alg, void *arg)
{
    STACK_OF(ALGORITHM) *newalg = arg;

    alg = OPENSSL_memdup(alg, sizeof(ALGORITHM));
    if (alg == NULL)
        return;

    alg->impls = sk_IMPLEMENTATION_dup(alg->impls);

    (void)sk_ALGORITHM_push(newalg, alg);
}

static void del_tmpalg(ALGORITHM *alg)
{
    sk_IMPLEMENTATION_free(alg->impls);
    OPENSSL_free(alg);
}

void ossl_method_store_do_all(OSSL_METHOD_STORE *store,
    void (*fn)(int id, void *method, void *fnarg),
    void *fnarg)
{
    int i, j;
    int numalgs, numimps;
    STACK_OF(ALGORITHM) *tmpalgs;
    ALGORITHM *alg;

    if (store == NULL)
        return;

    for (int k = 0; k < NUM_SHARDS; ++k) {
        STORED_ALGORITHMS *sa = &store->algs[k];

        if (!ossl_property_read_lock(sa))
            return;

        tmpalgs = sk_ALGORITHM_new_reserve(NULL,
            (int)ossl_sa_ALGORITHM_num(sa->algs));
        if (tmpalgs == NULL) {
            ossl_property_unlock(sa);
            return;
        }

        ossl_sa_ALGORITHM_doall_arg(sa->algs, alg_copy, tmpalgs);
        ossl_property_unlock(sa);
        numalgs = sk_ALGORITHM_num(tmpalgs);
        for (i = 0; i < numalgs; i++) {
            alg = sk_ALGORITHM_value(tmpalgs, i);
            numimps = sk_IMPLEMENTATION_num(alg->impls);
            for (j = 0; j < numimps; j++)
                alg_do_one(alg, sk_IMPLEMENTATION_value(alg->impls, j), fn, fnarg);
        }
        sk_ALGORITHM_pop_free(tmpalgs, del_tmpalg);
    }
}

/**
 * @brief Fetches a method from the method store matching the given properties.
 *
 * This function searches the method store for an implementation of a specified
 * method, identified by its id (nid), and matching the given property query. If
 * successful, it returns the method and its associated provider.
 *
 * @param store Pointer to the OSSL_METHOD_STORE from which to fetch the method.
 *              Must be non-null.
 * @param nid (identifier) of the method to be fetched. Must be > 0
 * @param prop_query String containing the property query to match against.
 * @param prov_rw Pointer to the OSSL_PROVIDER to restrict the search to, or
 *                to receive the matched provider.
 * @param method Pointer to receive the fetched method. Must be non-null.
 *
 * @return 1 if the method is successfully fetched, 0 on failure.
 *
 * If tracing is enabled, a message is printed indicating the property query and
 * the resolved provider.
 *
 * NOTE: The nid parameter here is _not_ a NID in the sense of the NID_* macros.
 * It is a unique internal identifier value.
 */
int ossl_method_store_fetch(OSSL_METHOD_STORE *store,
    int nid, const char *prop_query,
    const OSSL_PROVIDER **prov_rw, void **method)
{
    OSSL_PROPERTY_LIST **plp;
    ALGORITHM *alg;
    IMPLEMENTATION *impl, *best_impl = NULL;
    OSSL_PROPERTY_LIST *pq = NULL, *p2 = NULL;
    const OSSL_PROVIDER *prov = prov_rw != NULL ? *prov_rw : NULL;
    int ret = 0;
    int j, best = -1, score, optional;
    STORED_ALGORITHMS *sa;

    if (nid <= 0 || method == NULL || store == NULL)
        return 0;

#if !defined(FIPS_MODULE) && !defined(OPENSSL_NO_AUTOLOAD_CONFIG)
    if (ossl_lib_ctx_is_default(store->ctx)
        && !OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL))
        return 0;
#endif

    sa = stored_algs_shard(store, nid);

    /* This only needs to be a read lock, because the query won't create anything */
    if (!ossl_property_read_lock(sa))
        return 0;

    OSSL_TRACE2(QUERY, "Retrieving by nid %d from stored algorithms %p\n",
        nid, (void *)sa);
    alg = ossl_method_store_retrieve(sa, nid);
    if (alg == NULL) {
        ossl_property_unlock(sa);
        OSSL_TRACE2(QUERY, "Failed to retrieve by nid %d from stored algorithms %p\n",
            nid, (void *)sa);
        return 0;
    }
    OSSL_TRACE2(QUERY, "Retrieved by nid %d from stored algorithms %p\n",
        nid, (void *)sa);

    /*
     * If a property query string is provided, convert it to an
     * OSSL_PROPERTY_LIST structure
     */
    if (prop_query != NULL)
        p2 = pq = ossl_parse_query(store->ctx, prop_query, 0);

    /*
     * If the library context has default properties specified
     * then merge those with the properties passed to this function
     */
    plp = ossl_ctx_global_properties(store->ctx, 0);
    if (plp != NULL && *plp != NULL) {
        if (pq == NULL) {
            pq = *plp;
        } else {
            p2 = ossl_property_merge(pq, *plp);
            ossl_property_free(pq);
            if (p2 == NULL)
                goto fin;
            pq = p2;
        }
    }

    /*
     * Search for a provider that provides this implementation.
     * If the requested provider is NULL, then any provider will do,
     * otherwise we should try to find the one that matches the requested
     * provider.  Note that providers are given implicit preference via the
     * ordering of the implementation stack
     */
    if (pq == NULL) {
        for (j = 0; j < sk_IMPLEMENTATION_num(alg->impls); j++) {
            impl = sk_IMPLEMENTATION_value(alg->impls, j);
            if (impl != NULL
                && (prov == NULL || impl->provider == prov)) {
                best_impl = impl;
                ret = 1;
                break;
            }
        }
        goto fin;
    }

    /*
     * If there are optional properties specified
     * then run the search again, and select the provider that matches the
     * most options
     */
    optional = ossl_property_has_optional(pq);
    for (j = 0; j < sk_IMPLEMENTATION_num(alg->impls); j++) {
        impl = sk_IMPLEMENTATION_value(alg->impls, j);
        if (impl != NULL
            && (prov == NULL || impl->provider == prov)) {
            score = ossl_property_match_count(pq, impl->properties);
            if (score > best) {
                best_impl = impl;
                best = score;
                ret = 1;
                if (!optional)
                    goto fin;
            }
        }
    }
fin:
    if (ret && ossl_method_up_ref(&best_impl->method)) {
        *method = best_impl->method.method;
        if (prov_rw != NULL)
            *prov_rw = best_impl->provider;
    } else {
        ret = 0;
    }

#ifndef FIPS_MODULE
    OSSL_TRACE_BEGIN(QUERY)
    {
        char buf[512];
        size_t size;

        size = ossl_property_list_to_string(NULL, pq, buf, 512);
        BIO_printf(trc_out, "method store query with properties %s "
                            "resolves to provider %s\n",
            size == 0 ? "none" : buf,
            best_impl == NULL ? "none" : ossl_provider_name(best_impl->provider));
    }
    OSSL_TRACE_END(QUERY);
#endif

    ossl_property_unlock(sa);
    ossl_property_free(p2);
    return ret;
}

static void ossl_method_cache_flush_alg(STORED_ALGORITHMS *sa,
    ALGORITHM *alg)
{
    impl_cache_flush_alg(alg, sa);
}

static void ossl_method_cache_flush(STORED_ALGORITHMS *sa, int nid)
{
    ALGORITHM *alg = ossl_method_store_retrieve(sa, nid);

    if (alg != NULL)
        ossl_method_cache_flush_alg(sa, alg);
}

int ossl_method_store_cache_flush_all(OSSL_METHOD_STORE *store)
{
    for (int i = 0; i < NUM_SHARDS; ++i) {
        STORED_ALGORITHMS *sa = &store->algs[i];

        if (!ossl_property_write_lock(sa))
            return 0;
        ossl_ht_flush(sa->cache);
        ossl_property_unlock(sa);
    }

    return 1;
}

/*
 * Generate some randomness in our hash table when we need it, since
 * The use of this particular code occurs before our algorithms are
 * registered, preventing the use of the RAND_bytes apis.
 * Based off of:
 * https://doi.org/10.18637/jss.v008.i14
 */
static ossl_inline void generate_random_seed(uint32_t *seed)
{
    OSSL_TIME ts;

    if (*seed == 0) {
        *seed = OPENSSL_rdtsc();
        if (*seed == 0) {
            ts = ossl_time_now();
            *seed = (uint32_t)ts.t;
        }
    }

    *seed ^= *seed << 13;
    *seed ^= *seed >> 17;
    *seed ^= *seed << 5;
}

/*
 * Cull items from the QUERY cache.
 *
 * We don't want to let our QUERY cache grow too large, so if we grow beyond
 * its threshold, randomly discard some entries.
 *
 * We do this with an lru-like heuristic, and some randomness.
 *
 * the process is:
 * 1) Iterate over each element in the QUERY hashtable, for each element:
 * 2) If its used flag is set, its been recently used, so skip it.
 * 3) Otherwise, consult the sa->seed value.  Check the low order bit of sa->seed,
 *    which at cache creation is randomly generated.  If the bit is set, select the QUERY
 *    precomputed hash value, and delete it form the table.
 * 4) Shift the seed value right one bit.
 * 5) Repeat steps 1-4 until the number of requested entries have been removed
 * 6) Update our sa->seed by xoring the current sa->seed with the last hash that was eliminated.
 */
static void QUERY_cache_select_cull(ALGORITHM *alg, STORED_ALGORITHMS *sa,
    size_t cullcount, uint32_t seed)
{
    size_t culled = 0;
    uint64_t hash = 0;
    uint32_t used = 0;
    QUERY *q, *qn;
    QUERY_KEY key;

cull_again:
    OSSL_LIST_FOREACH_DELSAFE(q, qn, lru_entry, &sa->lru_list)
    {
        /*
         * Skip QUERY elements that have been recently used
         * reset this flag so all elements have to continuously
         * demonstrate use.
         */
        used = tsan_load(&q->used);
        tsan_store(&q->used, 0);
        if (used)
            continue;
        /*
         * If the low order bit in the seed is set, we can delete this entry
         */
        if (seed & 0x1) {
            /*
             * Select the hash value to delete in priority order, specific if its
             * given, generic otherwise
             */
            hash = (q->specific_hash != 0) ? q->specific_hash : q->generic_hash;
            HT_INIT_KEY_CACHED(&key, hash);
            if (ossl_ht_delete(sa->cache, TO_HT_KEY(&key))) {
                culled++;
                if (culled == cullcount)
                    break;
            }
            generate_random_seed(&seed);
        } else {
            seed = seed >> 1;
        }
    }
    /*
     * If we didn't cull our requested number of entries
     * try again.  Note that the used flag is cleared on
     * all entries now, so every entry is fair game
     */
    if (culled < cullcount)
        goto cull_again;
}

static ossl_inline int ossl_method_store_cache_get_locked(OSSL_METHOD_STORE *store, OSSL_PROVIDER *prov,
    int nid, const char *prop_query, size_t keylen, STORED_ALGORITHMS *sa, QUERY **post_insert,
    void **method)
{
    ALGORITHM *alg;
    QUERY *r = NULL;
    int res = 0;
    QUERY_KEY key;
    HT_VALUE *v = NULL;
    uint64_t generic_hash;
#ifdef ALLOW_VLA
    uint8_t keybuf[keylen];
#else
    uint8_t *keybuf;
#endif

    *post_insert = NULL;

#ifndef ALLOW_VLA
    keybuf = OPENSSL_malloc(keylen);
    if (keybuf == NULL)
        goto err;
#endif

    alg = ossl_method_store_retrieve(sa, nid);
    if (alg == NULL)
        goto err;

    /*
     * Marshall our lookup key.
     * the key is always [nid,prop_query] and may include
     * the address of the provider on the end if given
     */
    keylen = 0;
    memcpy(&keybuf[keylen], &nid, sizeof(int));
    keylen += sizeof(int);
    memcpy(&keybuf[keylen], prop_query, strlen(prop_query));
    keylen += strlen(prop_query);
    if (prov != NULL) {
        memcpy(&keybuf[keylen], &prov, sizeof(OSSL_PROVIDER *));
        keylen += sizeof(OSSL_PROVIDER *);
    }

    HT_INIT_KEY_EXTERNAL(&key, keybuf, keylen);

    r = ossl_ht_cache_QUERY_get(sa->cache, TO_HT_KEY(&key), &v);
    if (r == NULL) {
        if (prov != NULL)
            goto err;
        /*
         * We don't have a providerless entry for this lookup
         * (it likely got culled), so we need to rebuild one
         * we can used the cached hash value from the above lookup
         * to scan the lru list for a good match
         */
        generic_hash = HT_KEY_GET_HASH(&key);
        OSSL_LIST_FOREACH(r, lru_entry, &sa->lru_list)
        {
            if (r->generic_hash == generic_hash) {
                /*
                 * We found an entry for which the generic_hash
                 * (that is the hash of the [nid,propquery] tuple
                 * matches what we tried, and failed to look up
                 * above, so duplicate this as our new generic lookup
                 */
                r = OPENSSL_memdup(r, sizeof(*r));
                if (r == NULL)
                    goto err;
                r->generic_hash = generic_hash;
                r->specific_hash = 0;
                r->used = 0;
                ossl_list_lru_entry_init_elem(r);
                HT_INIT_KEY_CACHED(&key, generic_hash);
                /*
                 * We need to take a reference here to represent the hash table
                 * ownership.  We will take a second reference below as the caller
                 * owns it as well
                 */
                if (!ossl_method_up_ref(&r->method)) {
                    impl_cache_free(r);
                    r = NULL;
                }
                /*
                 * Inform the caller that we need to insert this newly created
                 * QUERY into the hash table.  We do this because we only
                 * hold the read lock here, so after the caller drops it, we
                 * can then take the write lock to do the insert
                 */
                *post_insert = r;
                break;
            }
        }
        if (r == NULL)
            goto err;
    }
    tsan_store(&r->used, 1);
    if (ossl_method_up_ref(&r->method)) {
        *method = r->method.method;
        res = 1;
    }
err:
#ifndef ALLOW_VLA
    OPENSSL_free(keybuf);
#endif
    return res;
}

int ossl_method_store_cache_get(OSSL_METHOD_STORE *store, OSSL_PROVIDER *prov,
    int nid, const char *prop_query, void **method)
{
    size_t keylen = sizeof(int) + ((prop_query == NULL) ? 1 : strlen(prop_query))
        + sizeof(OSSL_PROVIDER *);
    int ret;
    STORED_ALGORITHMS *sa;
    QUERY *post_insert = NULL;
    QUERY_KEY key;

    if (nid <= 0 || store == NULL || prop_query == NULL)
        return 0;

    if (keylen > MAX_PROP_QUERY)
        return 0;

    sa = stored_algs_shard(store, nid);
    if (!ossl_property_read_lock(sa))
        return 0;

    /*
     * Note: We've bifurcated this function into a locked and unlocked variant
     * Not because of any specific need to do the locked work from some other location,
     * but rather because in the interests of performance, we allocate a buffer on the
     * stack which can be an arbitrary size.  In order to allow for clamping of that
     * value, we check the keylen above for size limit, and then use this call to create
     * a new stack frame in which we can safely do that stack allocation.
     */
    ret = ossl_method_store_cache_get_locked(store, prov, nid, prop_query, keylen, sa,
        &post_insert, method);

    ossl_property_unlock(sa);

    if (ret == 1 && post_insert != NULL) {
        if (!ossl_property_write_lock(sa)) {
            impl_cache_free(post_insert);
            *method = NULL;
            ret = 0;
        } else {
            HT_INIT_KEY_CACHED(&key, post_insert->generic_hash);

            if (!ossl_ht_cache_QUERY_insert(sa->cache, TO_HT_KEY(&key), post_insert, NULL)) {
                /*
                 * We raced with another thread that added the same QUERY, pitch this one
                 */
                impl_cache_free(post_insert);
                *method = NULL;
                ret = 0;
            } else {
                ossl_list_lru_entry_insert_tail(&sa->lru_list, post_insert);
            }
            ossl_property_unlock(sa);
        }
    }
    return ret;
}

static ossl_inline int ossl_method_store_cache_set_locked(OSSL_METHOD_STORE *store, OSSL_PROVIDER *prov,
    int nid, const char *prop_query, size_t keylen, STORED_ALGORITHMS *sa, void *method,
    int (*method_up_ref)(void *),
    void (*method_destruct)(void *))
{
    QUERY *old = NULL, *p = NULL;
    ALGORITHM *alg;
    QUERY_KEY key;
    int res = 1;
    size_t cullcount;
#ifdef ALLOW_VLA
    uint8_t keybuf[keylen];
#else
    uint8_t *keybuf;
#endif

#ifndef ALLOW_VLA
    keybuf = OPENSSL_malloc(keylen);
    if (keybuf == NULL)
        goto err;
#endif

    alg = ossl_method_store_retrieve(sa, nid);
    if (alg == NULL)
        goto err;
    if (ossl_ht_count(sa->cache) > IMPL_CACHE_FLUSH_THRESHOLD) {
        uint32_t seed = 0;

        generate_random_seed(&seed);
        /*
         * Cull between 1 and 25% of this cache
         */
        cullcount = ossl_ht_count(sa->cache);
        /*
         * If this cache has less than 25% of the total entries
         * in the STORED_ALGORITHMS shard, don't bother culling
         * Just wait until we try to add to a larger cache
         */
        if (cullcount >= 4) {
            cullcount = seed % (cullcount >> 2);
            cullcount = (cullcount < 1) ? 1 : cullcount;
            QUERY_cache_select_cull(alg, sa, cullcount, seed);
        }
    }

    /*
     * Marshall our lookup key
     * NOTE: Provider cant be NULL here so we always add it
     */
    keylen = 0;
    memcpy(&keybuf[keylen], &nid, sizeof(int));
    keylen += sizeof(int);
    memcpy(&keybuf[keylen], prop_query, strlen(prop_query));
    keylen += strlen(prop_query);
    memcpy(&keybuf[keylen], &prov, sizeof(OSSL_PROVIDER *));
    keylen += sizeof(OSSL_PROVIDER *);

    HT_INIT_KEY_EXTERNAL(&key, keybuf, keylen);

    if (method == NULL) {
        ossl_ht_delete(sa->cache, TO_HT_KEY(&key));
        goto end;
    }
    p = OPENSSL_malloc(sizeof(*p));
    if (p != NULL) {
        p->saptr = sa;
        p->nid = nid;
        p->used = 0;
        ossl_list_lru_entry_init_elem(p);
        p->method.method = method;
        p->method.up_ref = method_up_ref;
        p->method.free = method_destruct;
        if (!ossl_method_up_ref(&p->method))
            goto err;

        if (!ossl_ht_cache_QUERY_insert(sa->cache, TO_HT_KEY(&key), p, &old)) {
            impl_cache_free(p);
            goto err;
        }
        p->specific_hash = HT_KEY_GET_HASH(&key);
        p->generic_hash = 0;
        if (old != NULL)
            impl_cache_free(old);
        ossl_list_lru_entry_insert_head(&sa->lru_list, p);
        /*
         * We also want to add this method into the cache against a key computed _only_
         * from nid and property query.  This lets us match in the event someone does a lookup
         * against a NULL provider (i.e. the "any provided alg will do" match
         */
        keylen -= sizeof(OSSL_PROVIDER *);
        HT_INIT_KEY_EXTERNAL(&key, keybuf, keylen);
        old = p;
        p = OPENSSL_memdup(p, sizeof(*p));
        if (p == NULL)
            goto err;

        ossl_list_lru_entry_init_elem(p);
        if (!ossl_method_up_ref(&p->method))
            goto err;
        if (ossl_ht_cache_QUERY_insert(sa->cache, TO_HT_KEY(&key), p, NULL)) {
            p->specific_hash = 0;
            p->generic_hash = old->generic_hash = HT_KEY_GET_HASH(&key);
            ossl_list_lru_entry_insert_tail(&sa->lru_list, p);
        } else {
            impl_cache_free(p);
            p = NULL;
            goto err;
        }

        goto end;
    }
err:
    res = 0;
    OPENSSL_free(p);
end:
#ifndef ALLOW_VLA
    OPENSSL_free(keybuf);
#endif
    return res;
}

int ossl_method_store_cache_set(OSSL_METHOD_STORE *store, OSSL_PROVIDER *prov,
    int nid, const char *prop_query, void *method,
    int (*method_up_ref)(void *),
    void (*method_destruct)(void *))
{
    STORED_ALGORITHMS *sa;
    int res = 1;
    size_t keylen = sizeof(int) + ((prop_query == NULL) ? 1 : strlen(prop_query))
        + sizeof(OSSL_PROVIDER *);

    if (nid <= 0 || store == NULL || prop_query == NULL)
        return 0;

    if (!ossl_assert(prov != NULL))
        return 0;

    if (keylen > MAX_PROP_QUERY)
        return 0;

    sa = stored_algs_shard(store, nid);
    if (!ossl_property_write_lock(sa))
        return 0;

    /*
     * As with cache_get_locked, we do this to allow ourselves the opportunity to make sure
     * keylen isn't so large that the stack allocation of keylen bytes will case a stack
     * overflow
     */
    res = ossl_method_store_cache_set_locked(store, prov, nid, prop_query, keylen, sa, method,
        method_up_ref, method_destruct);
    ossl_property_unlock(sa);
    return res;
}
