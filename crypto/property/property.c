/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
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
#include "internal/core.h"
#include "internal/property.h"
#include "internal/provider.h"
#include "internal/tsan_assist.h"
#include "crypto/ctype.h"
#include <openssl/lhash.h>
#include <openssl/rand.h>
#include "internal/thread_once.h"
#include "internal/rcu.h"
#include "crypto/lhash.h"
#include "crypto/sparse_array.h"
#include "property_local.h"
#include "crypto/context.h"

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
    const OSSL_PROVIDER *provider;
    OSSL_PROPERTY_LIST *properties;
    METHOD method;
} IMPLEMENTATION;

DEFINE_STACK_OF(IMPLEMENTATION)

typedef struct {
    const OSSL_PROVIDER *provider;
    const char *query;
    METHOD method;
    size_t size;
    char body[1];
} QUERY;

DEFINE_LHASH_OF_EX(QUERY);

typedef struct {
    int nid;
    STACK_OF(IMPLEMENTATION) *impls;
    LHASH_OF(QUERY) *cache;
} ALGORITHM;

typedef struct {
    SPARSE_ARRAY_OF(ALGORITHM) *algs;

    /* query cache specific values */

    /* Count of the query cache entries for all algs */
    size_t cache_nelem;

    /* Flag: 1 if query cache entries for all algs need flushing */
    int cache_need_flush;
} STORED_ALGORITHMS;

struct ossl_method_store_st {
    OSSL_LIB_CTX *ctx;

    STORED_ALGORITHMS *algs;

    /*
     * Lock to protect the cached algorithms |algs| from concurrent writing,
     * when individual implementations or queries are inserted.  This is used
     * by the appropriate functions here.
     */
    CRYPTO_RCU_LOCK *lock;
    /*
     * Lock to reserve the whole store.  This is used when fetching a set
     * of algorithms, via these functions, found in crypto/core_fetch.c:
     * ossl_method_construct_reserve_store()
     * ossl_method_construct_unreserve_store()
     */
    CRYPTO_RWLOCK *biglock;
};

typedef struct {
    LHASH_OF(QUERY) *cache;
    size_t nelem;
    uint32_t seed;
    unsigned char using_global_seed;
} IMPL_CACHE_FLUSH;

DEFINE_SPARSE_ARRAY_OF(ALGORITHM);
DEFINE_STACK_OF(ALGORITHM)

typedef struct ossl_global_properties_st {
    OSSL_PROPERTY_LIST *list;
#ifndef FIPS_MODULE
    unsigned int no_mirrored : 1;
#endif
} OSSL_GLOBAL_PROPERTIES;

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

static unsigned long query_hash(const QUERY *a)
{
    return OPENSSL_LH_strhash(a->query);
}

static int query_cmp(const QUERY *a, const QUERY *b)
{
    int res = strcmp(a->query, b->query);

    if (res == 0 && a->provider != NULL && b->provider != NULL)
        res = b->provider > a->provider ? 1
            : b->provider < a->provider ? -1
            : 0;
    return res;
}

static void impl_free(IMPLEMENTATION *impl)
{
    if (impl != NULL) {
        ossl_method_free(&impl->method);
        OPENSSL_free(impl);
    }
}

static STORED_ALGORITHMS *stored_algs_new(void)
{
    STORED_ALGORITHMS *ret;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL)
        return NULL;

    ret->algs = ossl_sa_ALGORITHM_new();
    if (ret->algs == NULL) {
        OPENSSL_free(ret);
        return NULL;
    }

    return ret;
}

/* Does not free the actual ALGORITHM structures */
static void stored_algs_free(STORED_ALGORITHMS *algs)
{
    if (algs == NULL)
        return;

    ossl_sa_ALGORITHM_free(algs->algs);
    OPENSSL_free(algs);
}

struct data_shallow_dup {
    int err;
    SPARSE_ARRAY_OF(ALGORITHM) *saalg;
};

/* Shallow dup of an ALGORITHM */
static void alg_shallow_dup(uintmax_t idx, ALGORITHM *alg, void *arg)
{
    struct data_shallow_dup *data = arg;

    if (data->err)
        return;

    if (!ossl_sa_ALGORITHM_set(data->saalg, idx, alg))
        data->err = 1;

    return;
}

static STORED_ALGORITHMS *
stored_algs_shallow_dup(STORED_ALGORITHMS *src)
{
    STORED_ALGORITHMS *dest;
    struct data_shallow_dup data;

    dest = stored_algs_new();
    if (dest == NULL)
        return NULL;
    dest->cache_need_flush = src->cache_need_flush;
    dest->cache_nelem = src->cache_nelem;

    data.err = 0;
    data.saalg = dest->algs;
    ossl_sa_ALGORITHM_doall_arg(src->algs, alg_shallow_dup, &data);
    if (data.err) {
        stored_algs_free(dest);
        return NULL;
    }

    return dest;
}

static void impl_cache_free(QUERY *elem)
{
    if (elem != NULL) {
        ossl_method_free(&elem->method);
        OPENSSL_free(elem);
    }
}

static void impl_cache_flush_alg(ossl_uintmax_t idx, ALGORITHM *alg)
{
    lh_QUERY_doall(alg->cache, &impl_cache_free);
    lh_QUERY_flush(alg->cache);
}

static void alg_free(ALGORITHM *alg)
{
    if (alg != NULL)
        lh_QUERY_free(alg->cache);
    OPENSSL_free(alg);
}

static void alg_and_cache_free(ALGORITHM *alg)
{
    if (alg != NULL)
        impl_cache_flush_alg(0, alg);
    alg_free(alg);
}

/*
 * Flush the cache, free the impl statck and free the alg. Does not free the
 * actual implementations themselves
 */
static void alg_free_all(ALGORITHM *alg)
{
    if (alg != NULL)
        sk_IMPLEMENTATION_free(alg->impls);
    alg_and_cache_free(alg);
}

static void alg_cleanup(ossl_uintmax_t idx, ALGORITHM *a, void *arg)
{
    OSSL_METHOD_STORE *store = arg;

    if (a != NULL) {
        sk_IMPLEMENTATION_pop_free(a->impls, &impl_free);
        alg_and_cache_free(a);
    }
    if (store != NULL)
        ossl_sa_ALGORITHM_set(store->algs->algs, idx, NULL);
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
        if ((res->algs = stored_algs_new()) == NULL
            || (res->lock = ossl_rcu_lock_new(1, ctx)) == NULL
            || (res->biglock = CRYPTO_THREAD_lock_new()) == NULL) {
            ossl_method_store_free(res);
            return NULL;
        }
    }
    return res;
}

void ossl_method_store_free(OSSL_METHOD_STORE *store)
{
    if (store != NULL) {
        if (store->algs != NULL)
            ossl_sa_ALGORITHM_doall_arg(store->algs->algs, &alg_cleanup, store);
        stored_algs_free(store->algs);
        ossl_rcu_lock_free(store->lock);
        CRYPTO_THREAD_lock_free(store->biglock);
        OPENSSL_free(store);
    }
}

int ossl_method_lock_store(OSSL_METHOD_STORE *store)
{
    return store != NULL ? CRYPTO_THREAD_write_lock(store->biglock) : 0;
}

int ossl_method_unlock_store(OSSL_METHOD_STORE *store)
{
    return store != NULL ? CRYPTO_THREAD_unlock(store->biglock) : 0;
}

static ALGORITHM *stored_algs_retrieve(STORED_ALGORITHMS *algs, int nid)
{

    return ossl_sa_ALGORITHM_get(algs->algs, nid);
}

int ossl_method_store_add(OSSL_METHOD_STORE *store, const OSSL_PROVIDER *prov,
                          int nid, const char *properties, void *method,
                          int (*method_up_ref)(void *),
                          void (*method_destruct)(void *))
{
    ALGORITHM *algold = NULL, *algnew = NULL;
    IMPLEMENTATION *impl;
    STORED_ALGORITHMS *algsnew = NULL, *algsold = NULL;
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

    if ((impl->properties = ossl_prop_defn_get(store->ctx, properties)) == NULL) {
        impl->properties = ossl_parse_property(store->ctx, properties);
        if (impl->properties == NULL) {
            OPENSSL_free(impl);
            return 0;
        }
        if (!ossl_prop_defn_set(store->ctx, properties, &impl->properties)) {
            ossl_property_free(impl->properties);
            OPENSSL_free(impl);
            return 0;
        }
    }

    /* Insert the new implementation if required */
    ossl_rcu_write_lock(store->lock);

    algsold = ossl_rcu_deref(&store->algs);
    algsnew = stored_algs_shallow_dup(algsold);

    if (algsnew == NULL)
        goto err;

    algold = stored_algs_retrieve(algsold, nid);

    if ((algnew = OPENSSL_zalloc(sizeof(*algnew))) == NULL
            || (algnew->cache = lh_QUERY_new(&query_hash, &query_cmp)) == NULL)
        goto err;
    algnew->nid = nid;

    if (algold != NULL)
        /* Copy any pre-existing implementations onto the new stack */
        algnew->impls = sk_IMPLEMENTATION_dup(algold->impls);
    else
        algnew->impls = sk_IMPLEMENTATION_new_null();

    if (algnew->impls == NULL)
        goto err;

    /* Push onto stack if there isn't one there already */
    for (i = 0; i < sk_IMPLEMENTATION_num(algnew->impls); i++) {
        const IMPLEMENTATION *tmpimpl = sk_IMPLEMENTATION_value(algnew->impls, i);

        if (tmpimpl->provider == impl->provider
            && tmpimpl->properties == impl->properties)
            break;
    }
    if (i == sk_IMPLEMENTATION_num(algnew->impls)
        && ossl_sa_ALGORITHM_set(algsnew->algs, nid, algnew)
        && sk_IMPLEMENTATION_push(algnew->impls, impl)) {
        if (algold != NULL)
            algsnew->cache_nelem -= lh_QUERY_num_items(algold->cache);
        ossl_rcu_assign_ptr(&store->algs, &algsnew);
        ret = 1;
    }

 err:
    ossl_rcu_write_unlock(store->lock);

    if (ret) {
        ossl_synchronize_rcu(store->lock);
        stored_algs_free(algsold);
        alg_free_all(algold);
    } else {
        stored_algs_free(algsnew);
        alg_free_all(algnew);
        impl_free(impl);
    }

    return ret;
}

struct doall_alg_data_st {
    OSSL_METHOD_STORE *store;
    const OSSL_PROVIDER *prov;
    STORED_ALGORITHMS *algs;
    STACK_OF(ALGORITHM) *newalgs;
    STACK_OF(ALGORITHM) *oldalgs;
    STACK_OF(IMPLEMENTATION) *oldimpls;
    int err;
};

static void
alg_cleanup_by_provider(ossl_uintmax_t idx, ALGORITHM *algold, void *arg)
{
    struct doall_alg_data_st *data = arg;
    int i;
    int numimpl = sk_IMPLEMENTATION_num(algold->impls);
    ALGORITHM *algnew = NULL;

    /* If we already encountered an error then don't do anything more */
    if (data->err)
        return;

    /* First check if we have any implementations that need to be removed */
    for (i = 0; i < numimpl; i++) {
        IMPLEMENTATION *impl = sk_IMPLEMENTATION_value(algold->impls, i);

        if (impl->provider == data->prov)
            break;
    }
    if (i == numimpl)
        /* Nothing to be done */
        return;

    algnew = OPENSSL_malloc(sizeof(*algnew));
    if (algnew == NULL)
        goto err;

    algnew->nid = algold->nid;
    algnew->impls = sk_IMPLEMENTATION_dup(algold->impls);
    /*
     * If we remove any implementation, we also clear the whole associated
     * cache.
     */
    algnew->cache = lh_QUERY_new(&query_hash, &query_cmp);
    if (algnew->impls == NULL || algnew->cache == NULL)
        goto err;

    /*
    * We walk the stack backwards, to avoid having to deal with stack shifts
    * caused by deletion
    */
    for (i = numimpl; i-- > 0;) {
        IMPLEMENTATION *impl = sk_IMPLEMENTATION_value(algnew->impls, i);

        if (impl->provider == data->prov) {
            (void)sk_IMPLEMENTATION_delete(algnew->impls, i);
            /* Schedule the impl for later freeing */
            if (sk_IMPLEMENTATION_push(data->oldimpls, impl) == 0)
                goto err;
        }
    }

    /* Schedule the old alg for later freeing */
    if (sk_ALGORITHM_push(data->oldalgs, algold) == 0)
        goto err;

    /*
     * We also remember the new alg we created in case we encounter a later
     * error and have to rollback
     */
    if (sk_ALGORITHM_push(data->newalgs, algnew) == 0)
        goto err;

    if (ossl_sa_ALGORITHM_set(data->algs->algs, idx, algnew) == 0) {
        /* algnew is already scheduled for rollback in data->newalgs */
        algnew = NULL;
        goto err;
    }

    data->algs->cache_nelem -= lh_QUERY_num_items(algold->cache);
    return;

 err:
    alg_free_all(algnew);
    data->err = 1;
}

int ossl_method_store_remove_all_provided(OSSL_METHOD_STORE *store,
                                          const OSSL_PROVIDER *prov)
{
    struct doall_alg_data_st data;
    STORED_ALGORITHMS *algsold, *algsnew;

    data.newalgs = NULL;
    data.oldalgs = NULL;
    data.oldimpls = NULL;

    ossl_rcu_write_lock(store->lock);
    algsold = ossl_rcu_deref(&store->algs);
    algsnew = stored_algs_shallow_dup(algsold);
    if (algsnew == NULL)
        goto err;
    data.prov = prov;
    data.store = store;
    data.algs = algsnew;
    data.newalgs = sk_ALGORITHM_new_null();
    data.oldalgs = sk_ALGORITHM_new_null();
    data.oldimpls = sk_IMPLEMENTATION_new_null();
    data.err = 0;
    if (data.newalgs == NULL || data.oldalgs == NULL || data.oldimpls == NULL)
        goto err;
    ossl_sa_ALGORITHM_doall_arg(algsnew->algs, &alg_cleanup_by_provider, &data);
    if (data.err)
        goto err;
    ossl_rcu_assign_ptr(&store->algs, &algsnew);
    ossl_rcu_write_unlock(store->lock);
    ossl_synchronize_rcu(store->lock);

    /* Free any old algorithms and implementations we are no longer using */
    sk_ALGORITHM_free(data.newalgs);
    sk_ALGORITHM_pop_free(data.oldalgs, alg_free_all);
    sk_IMPLEMENTATION_pop_free(data.oldimpls, impl_free);
    stored_algs_free(algsold);
    return 1;
 err:
    ossl_rcu_write_unlock(store->lock);
    /* Rollback */
    sk_ALGORITHM_pop_free(data.newalgs, alg_free_all);
    sk_ALGORITHM_free(data.oldalgs);
    sk_IMPLEMENTATION_free(data.oldimpls);
    stored_algs_free(algsnew);
    return 0;
}

typedef struct method_data_st {
    METHOD method;
    int nid;
} METHOD_DATA;

DEFINE_STACK_OF(METHOD_DATA)

static void alg_do_each(ossl_uintmax_t idx, ALGORITHM *alg, void *arg)
{
    STACK_OF(METHOD_DATA) *data = arg;
    int i, end = sk_IMPLEMENTATION_num(alg->impls);

    for (i = 0; i < end; i++) {
        IMPLEMENTATION *impl = sk_IMPLEMENTATION_value(alg->impls, i);
        METHOD_DATA *methdata = OPENSSL_malloc(sizeof(*methdata));

        methdata->nid = alg->nid;
        methdata->method = impl->method;

        if (ossl_method_up_ref(&methdata->method)) {
            if (sk_METHOD_DATA_push(data, methdata) == 0) {
                ossl_method_free(&methdata->method);
                OPENSSL_free(methdata);
            }
        } else {
            OPENSSL_free(methdata);
        }
    }
}

void ossl_method_store_do_all(OSSL_METHOD_STORE *store,
                              void (*fn)(int id, void *method, void *fnarg),
                              void *fnarg)
{
    STACK_OF(METHOD_DATA) *data;
    int i;
    STORED_ALGORITHMS *algs;

    if (store == NULL)
        return;

    data = sk_METHOD_DATA_new_null();
    if (data == NULL)
        return;

    /*
     * We cannot call the user supplied function under a read lock in case that
     * function itself attempts to obtain a recursive lock on the store. Instead
     * we gather a list of all the methods under a read lock, and then
     * subsequently call the user function not under lock. The methods are
     * up-ref'd to ensure that they remain valid even while not under the lock.
     */
    ossl_rcu_read_lock(store->lock);
    algs = ossl_rcu_deref(&store->algs);
    ossl_sa_ALGORITHM_doall_arg(algs->algs, alg_do_each, data);
    ossl_rcu_read_unlock(store->lock);

    for (i = 0; i < sk_METHOD_DATA_num(data); i++) {
        METHOD_DATA *methdata = sk_METHOD_DATA_value(data, i);

        fn(methdata->nid, methdata->method.method, fnarg);
        ossl_method_free(&methdata->method);
        OPENSSL_free(methdata);
    }
    sk_METHOD_DATA_free(data);
}

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

    if (nid <= 0 || method == NULL || store == NULL)
        return 0;

#if !defined(FIPS_MODULE) && !defined(OPENSSL_NO_AUTOLOAD_CONFIG)
    if (ossl_lib_ctx_is_default(store->ctx)
            && !OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL))
        return 0;
#endif

    /*
     * This only needs to be a read lock, because the query won't create
     * anything
     */
    ossl_rcu_read_lock(store->lock);

    alg = stored_algs_retrieve(ossl_rcu_deref(&store->algs), nid);
    if (alg == NULL) {
        ossl_rcu_read_unlock(store->lock);
        return 0;
    }

    if (prop_query != NULL)
        p2 = pq = ossl_parse_query(store->ctx, prop_query, 0);
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

    if (pq == NULL) {
        for (j = 0; j < sk_IMPLEMENTATION_num(alg->impls); j++) {
            if ((impl = sk_IMPLEMENTATION_value(alg->impls, j)) != NULL
                && (prov == NULL || impl->provider == prov)) {
                best_impl = impl;
                ret = 1;
                break;
            }
        }
        goto fin;
    }
    optional = ossl_property_has_optional(pq);
    for (j = 0; j < sk_IMPLEMENTATION_num(alg->impls); j++) {
        if ((impl = sk_IMPLEMENTATION_value(alg->impls, j)) != NULL
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
    ossl_rcu_read_unlock(store->lock);
    ossl_property_free(p2);
    return ret;
}

static void do_cache_flush_all(ossl_uintmax_t idx, ALGORITHM *algold,
                               void *arg)
{
    ALGORITHM *algnew = NULL;
    struct doall_alg_data_st *data = arg;

    if (data->err)
        return;

    if (lh_QUERY_num_items(algold->cache) == 0)
        return;

    algnew = OPENSSL_malloc(sizeof(*algnew));
    if (algnew == NULL)
        goto err;

    *algnew = *algold;
    /* We retain the impls stack but clear the cache */
    algnew->cache = lh_QUERY_new(&query_hash, &query_cmp);
    if (algnew->cache == NULL)
        goto err;

    if (sk_ALGORITHM_push(data->oldalgs, algold) == 0)
        goto err;

    if (sk_ALGORITHM_push(data->newalgs, algnew) == 0)
        goto err;

    if (ossl_sa_ALGORITHM_set(data->algs->algs, idx, algnew) == 0) {
        /* Already in the newalgs stack so don't free algnew in the error block */
        algnew = NULL;
        goto err;
    }

    return;

 err:
    alg_and_cache_free(algnew);
    data->err = 1;
}

int ossl_method_store_cache_flush_all(OSSL_METHOD_STORE *store)
{
    struct doall_alg_data_st data;
    STORED_ALGORITHMS *algsold, *algsnew;

    data.newalgs = NULL;
    data.oldalgs = NULL;

    ossl_rcu_write_lock(store->lock);
    algsold = ossl_rcu_deref(&store->algs);
    algsnew = stored_algs_shallow_dup(algsold);
    if (algsnew == NULL)
        goto err;
    data.algs = algsnew;
    data.newalgs = sk_ALGORITHM_new_null();
    data.oldalgs = sk_ALGORITHM_new_null();
    data.err = 0;
    if (data.newalgs == NULL || data.oldalgs == NULL)
        goto err;

    ossl_sa_ALGORITHM_doall_arg(algsold->algs, &do_cache_flush_all, &data);
    if (data.err)
        goto err;

    algsnew->cache_nelem = 0;
    ossl_rcu_assign_ptr(&store->algs, &algsnew);
    ossl_rcu_write_unlock(store->lock);
    ossl_synchronize_rcu(store->lock);

    /* Free any old algorithms we are no longer using */
    sk_ALGORITHM_free(data.newalgs);
    sk_ALGORITHM_pop_free(data.oldalgs, alg_and_cache_free);
    stored_algs_free(algsold);
    return 1;

 err:
    ossl_rcu_write_unlock(store->lock);
    /* Rollback */
    sk_ALGORITHM_pop_free(data.newalgs, alg_and_cache_free);
    sk_ALGORITHM_free(data.oldalgs);
    stored_algs_free(algsnew);
    return 0;
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

static void impl_cache_flush_one_alg(ossl_uintmax_t idx, ALGORITHM *alg,
                                     void *v)
{
    IMPL_CACHE_FLUSH *state = (IMPL_CACHE_FLUSH *)v;

    state->cache = alg->cache;
    lh_QUERY_doall_IMPL_CACHE_FLUSH(state->cache, &impl_cache_flush_cache,
                                    state);
}

static void ossl_method_cache_flush_some(STORED_ALGORITHMS *algs)
{
    IMPL_CACHE_FLUSH state;
    static TSAN_QUALIFIER uint32_t global_seed = 1;

    state.nelem = 0;
    state.using_global_seed = 0;
    if ((state.seed = OPENSSL_rdtsc()) == 0) {
        /* If there is no timer available, seed another way */
        state.using_global_seed = 1;
        state.seed = tsan_load(&global_seed);
    }
    algs->cache_need_flush = 0;
    ossl_sa_ALGORITHM_doall_arg(algs->algs, &impl_cache_flush_one_alg, &state);
    algs->cache_nelem = state.nelem;
    /* Without a timer, update the global seed */
    if (state.using_global_seed)
        tsan_add(&global_seed, state.seed);
}

int ossl_method_store_cache_get(OSSL_METHOD_STORE *store, OSSL_PROVIDER *prov,
                                int nid, const char *prop_query, void **method)
{
    ALGORITHM *alg;
    QUERY elem, *r;
    int res = 0;

    if (nid <= 0 || store == NULL || prop_query == NULL)
        return 0;

    ossl_rcu_read_lock(store->lock);

    alg = stored_algs_retrieve(ossl_rcu_deref(&store->algs), nid);
    if (alg == NULL)
        goto err;

    elem.query = prop_query;
    elem.provider = prov;
    r = lh_QUERY_retrieve(alg->cache, &elem);
    if (r == NULL)
        goto err;
    if (ossl_method_up_ref(&r->method)) {
        *method = r->method.method;
        res = 1;
    }
err:
    ossl_rcu_read_unlock(store->lock);
    return res;
}

struct doall_cache_data_st {
    int err;
    LHASH_OF(QUERY) *cache;
};

static void dup_cache_entry(QUERY *src, void *arg)
{
    struct doall_cache_data_st *data = arg;
    QUERY *dest;

    if (data->err == 1)
        return;

    dest = OPENSSL_malloc(src->size);
    if (dest == NULL)
        goto err;

    memcpy(dest, src, src->size);
    dest->query = dest->body;
    if (!ossl_method_up_ref(&dest->method))
        goto err;

    (void)lh_QUERY_insert(data->cache, dest);
    if (lh_QUERY_error(data->cache)) {
        ossl_method_free(&dest->method);
        goto err;
    }
    return;
 err:
    data->err = 1;
    OPENSSL_free(dest);
}

int ossl_method_store_cache_set(OSSL_METHOD_STORE *store, OSSL_PROVIDER *prov,
                                int nid, const char *prop_query, void *method,
                                int (*method_up_ref)(void *),
                                void (*method_destruct)(void *))
{
    struct doall_cache_data_st data;
    STORED_ALGORITHMS *algsold, *algsnew;
    QUERY elem, *old = NULL, *p = NULL;
    ALGORITHM *algold = NULL, *algnew = NULL;
    size_t len;
    int res = 1;

    if (nid <= 0 || store == NULL || prop_query == NULL)
        return 0;

    if (!ossl_assert(prov != NULL))
        return 0;

    ossl_rcu_write_lock(store->lock);
    algsold = ossl_rcu_deref(&store->algs);
    algsnew = stored_algs_shallow_dup(algsold);
    if (algsnew == NULL)
        goto err;

    if (algsnew->cache_need_flush)
        ossl_method_cache_flush_some(algsnew);

    algold = stored_algs_retrieve(algsold, nid);
    if (algold == NULL)
        goto err;

    algnew = OPENSSL_malloc(sizeof(*algnew));
    if (algnew == NULL)
        goto err;
    *algnew = *algold;
    /* We retain the impls stack but clear the cache */
    algnew->cache = lh_QUERY_new(&query_hash, &query_cmp);
    if (algnew->cache == NULL)
        goto err;
    data.err = 0;
    data.cache = algnew->cache;
    lh_QUERY_doall_arg(algold->cache, dup_cache_entry, &data);
    if (data.err)
        goto err;

    if (method == NULL) {
        elem.query = prop_query;
        elem.provider = prov;
        if ((old = lh_QUERY_delete(algnew->cache, &elem)) != NULL)
            algsnew->cache_nelem--;
        goto end;
    }
    p = OPENSSL_malloc(sizeof(*p) + (len = strlen(prop_query)));
    if (p != NULL) {
        p->query = p->body;
        p->provider = prov;
        p->method.method = method;
        p->method.up_ref = method_up_ref;
        p->method.free = method_destruct;
        p->size = sizeof(*p) + len;
        if (!ossl_method_up_ref(&p->method))
            goto err;
        memcpy((char *)p->query, prop_query, len + 1);
        if ((old = lh_QUERY_insert(algnew->cache, p)) != NULL)
            goto end;
        if (!lh_QUERY_error(algnew->cache)) {
            if (++algsnew->cache_nelem >= IMPL_CACHE_FLUSH_THRESHOLD)
                algsnew->cache_need_flush = 1;
            goto end;
        }
        ossl_method_free(&p->method);
    }
err:
    res = 0;
    OPENSSL_free(p);
end:
    if (res) {
        if (ossl_sa_ALGORITHM_set(algsnew->algs, nid, algnew) != 0) {
            ossl_rcu_assign_ptr(&store->algs, &algsnew);
        } else {
            res = 0;
            OPENSSL_free(p);
        }
    }
    ossl_rcu_write_unlock(store->lock);

    if (res) {
        ossl_synchronize_rcu(store->lock);
        stored_algs_free(algsold);
        alg_and_cache_free(algold);
    } else {
        stored_algs_free(algsnew);
        alg_and_cache_free(algnew);
    }

    impl_cache_free(old);
    return res;
}
