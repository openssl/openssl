/*
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
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
#include "internal/namemap.h"
#include "internal/property.h"
#include "internal/provider.h"
#include "internal/thread.h"
#include "internal/thread_arch.h"
#include "internal/tsan_assist.h"
#include "crypto/ctype.h"
#include "crypto/evp.h"
#include <openssl/lhash.h>
#include <openssl/rand.h>
#include <openssl/thread.h>
#include "internal/thread_once.h"
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
    char body[1];
} QUERY;

DEFINE_LHASH_OF_EX(QUERY);

typedef struct {
    int nid;
    STACK_OF(IMPLEMENTATION) *impls;
    LHASH_OF(QUERY) *cache;
} ALGORITHM;

struct ossl_method_store_st {
    OSSL_LIB_CTX *ctx;
    SPARSE_ARRAY_OF(ALGORITHM) *algs;
    /*
     * Lock to protect the |algs| array from concurrent writing, when
     * individual implementations or queries are inserted.  This is used
     * by the appropriate functions here.
     */
    CRYPTO_RWLOCK *lock;
    /*
     * Lock to reserve the whole store.  This is used when fetching a set
     * of algorithms, via these functions, found in crypto/core_fetch.c:
     * ossl_method_construct_reserve_store()
     * ossl_method_construct_unreserve_store()
     */
    CRYPTO_RWLOCK *biglock;

    /* query cache specific values */

    /* Count of the query cache entries for all algs */
    size_t cache_nelem;

    /* Flag: 1 if query cache entries for all algs need flushing */
    int cache_need_flush;
};

typedef struct {
    LHASH_OF(QUERY) *cache;
    size_t nelem;
    uint32_t seed;
    unsigned char using_global_seed;
} IMPL_CACHE_FLUSH;

DEFINE_SPARSE_ARRAY_OF(ALGORITHM);

typedef struct ossl_global_properties_st {
    OSSL_PROPERTY_LIST *list;
#ifndef FIPS_MODULE
    unsigned int no_mirrored : 1;
#endif
} OSSL_GLOBAL_PROPERTIES;

typedef struct lb_global_st {
    const OSSL_CORE_HANDLE *handle;
    /* Lock to protect the strategy_status from concurrent writing. */
    CRYPTO_RWLOCK *lock;
    /* load-balanceing parameters */
    int strategy;
    void *strategy_status;
} LB_GLOBAL;

typedef struct {
    /* index of the method selected last time, init to -1 */
    int last_index;
} LBS_ROUND_ROBIN_STATUS;

static void *lb_sched_round_robin_new_status(void)
{
    LBS_ROUND_ROBIN_STATUS *rr_status;

    rr_status = OPENSSL_malloc(sizeof(*rr_status));
    if (rr_status == NULL)
        return 0;

    rr_status->last_index = -1;
    return (void *)rr_status;
}

/* a structure to record the best implementation for a <nid> */
typedef struct {
    int nid;
    IMPLEMENTATION *best_impl;
    int fetch_count;
    CRYPTO_RWLOCK *cnt_lock;
    int threshold;
} LBS_NID_BEST_IMPL;
#define FETCH_COUNT_TRIGGER_THRESHOLD (1024)

/*
 * define SA type for LBS_NID_BEST_IMPL, to be used by
 * LBS_FREE_BANDWIDTH_STATUS
 */
DEFINE_SPARSE_ARRAY_OF(LBS_NID_BEST_IMPL);

typedef struct {
    /* to record the best implementation for each <nid> */
    SPARSE_ARRAY_OF(LBS_NID_BEST_IMPL) *best_impls;
    /*
     * this lock is to protect the access to best_impls,
     * because
     *  1) a provider undload, and a impl can be removed
     *     during the lbs bandwidth update;
     *  2) lb_sched_free_bandwidth() reads best_impls;
     *  3) lb_sched_free_bandwidth() writes best_impls when
     *     a new nid comes in, and when updating writes
     *     nid_best_impl->fetch_count;
     *  4) thread lb_sched_update_free_bandwidth_fn() writes best_impls;
     */
    CRYPTO_RWLOCK *rwlock;
#if !defined(OPENSSL_NO_DEFAULT_THREAD_POOL)
    OSSL_LIB_CTX *libctx;
    /*
     * following items are related to thread
     * lb_sched_update_free_bandwidth_fn()
     */
    CRYPTO_MUTEX *lock;
    CRYPTO_CONDVAR *condvar;
    /* thread handle */
    void *handle;
    /* flag to finalize */
    unsigned int isfinalizing:1;
#endif
} LBS_FREE_BANDWIDTH_STATUS;

/* forward declaration */
#if !defined(OPENSSL_NO_DEFAULT_THREAD_POOL)
static CRYPTO_THREAD_RETVAL lb_sched_update_free_bandwidth_fn(void *data);
#endif

#define DEFAULT_MINIMUM_FREE_BANDWIDTH  (5)
#define COUNT_MAX_THREADS               (1) /* default max threads in the load-balance libctx */
static void *lb_sched_free_bandwidth_new_status(OSSL_LIB_CTX *libctx)
{
    LBS_FREE_BANDWIDTH_STATUS *fbw_status;

    fbw_status = OPENSSL_zalloc(sizeof(*fbw_status));
    if (fbw_status == NULL)
        return NULL;

    if ((fbw_status->best_impls = ossl_sa_LBS_NID_BEST_IMPL_new()) == NULL)
        goto err;
    if ((fbw_status->rwlock = CRYPTO_THREAD_lock_new()) == NULL)
        goto err;

#if !defined(OPENSSL_NO_DEFAULT_THREAD_POOL)
    fbw_status->isfinalizing = 0;
    /* thread-related initialization */
    if (((fbw_status->lock = ossl_crypto_mutex_new()) == NULL)
            || ((fbw_status->condvar = ossl_crypto_condvar_new()) == NULL)
            || ((OSSL_set_max_threads(libctx, COUNT_MAX_THREADS) == 0)))
        goto err;
    fbw_status->libctx = libctx;
    fbw_status->handle = ossl_crypto_thread_start(libctx,
                            lb_sched_update_free_bandwidth_fn, fbw_status);
    if (fbw_status->handle == NULL)
        goto err;
#endif

    return (void *)fbw_status;
err:
#if !defined(OPENSSL_NO_DEFAULT_THREAD_POOL)
    ossl_crypto_condvar_free(&fbw_status->condvar);
    ossl_crypto_mutex_free(&fbw_status->lock);
#endif
    ossl_sa_LBS_NID_BEST_IMPL_free(fbw_status->best_impls);
    CRYPTO_THREAD_lock_free(fbw_status->rwlock);
    OPENSSL_free(fbw_status);
    return NULL;
}

/* forward decalration */
static void ossl_method_free(METHOD *method);
static int ossl_method_up_ref(METHOD *method);

static void lb_sched_free_bandwidth_status_leaf_flush(ossl_uintmax_t idx,
                                                      LBS_NID_BEST_IMPL *leaf)
{
    if (leaf->best_impl != NULL) {
        ossl_method_free(&leaf->best_impl->method);
        leaf->best_impl = NULL;
    }
    CRYPTO_THREAD_lock_free(leaf->cnt_lock);
    return;
}

static void lb_sched_free_bandwidth_status_free(void * status)
{
    LBS_FREE_BANDWIDTH_STATUS *fbw_status;
    CRYPTO_THREAD_RETVAL retval;

    fbw_status = (LBS_FREE_BANDWIDTH_STATUS *)status;
#if !defined(OPENSSL_NO_DEFAULT_THREAD_POOL)
    fbw_status->isfinalizing = 1;
    ossl_crypto_condvar_broadcast(fbw_status->condvar);
    ossl_crypto_thread_join(fbw_status->handle, &retval);
    ossl_crypto_thread_clean(fbw_status->handle);

    ossl_crypto_condvar_free(&fbw_status->condvar);
    ossl_crypto_mutex_free(&fbw_status->lock);
#endif

    /* free best_impls, sparse arrary */
    if (!CRYPTO_THREAD_write_lock(fbw_status->rwlock)) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_OPERATION_FAIL);
        return;
    }
    ossl_sa_LBS_NID_BEST_IMPL_doall(fbw_status->best_impls,
                                    lb_sched_free_bandwidth_status_leaf_flush);
    ossl_sa_LBS_NID_BEST_IMPL_free_leaves(fbw_status->best_impls);
    CRYPTO_THREAD_unlock(fbw_status->rwlock);
    /* free rwlock */
    CRYPTO_THREAD_lock_free(fbw_status->rwlock);

    return;
}

/*
 * flush the impl <nid> 'cached' by free_bandwidth strategy status
 */
static void lb_sched_free_bandwidth_best_impl_flush(void *status, int nid)
{
    LBS_FREE_BANDWIDTH_STATUS *fbw_status = status;
    LBS_NID_BEST_IMPL *nid_best_impl;

#if !defined(OPENSSL_NO_DEFAULT_THREAD_POOL)
    if (!CRYPTO_THREAD_write_lock(fbw_status->rwlock))
        return;
    nid_best_impl = ossl_sa_LBS_NID_BEST_IMPL_get(fbw_status->best_impls, nid);
    if (nid_best_impl != NULL && nid_best_impl->best_impl != NULL) {
        ossl_method_free(&nid_best_impl->best_impl->method);
        nid_best_impl->best_impl = NULL;
    }
    CRYPTO_THREAD_unlock(fbw_status->rwlock);
#endif
    return;
}

/*
 * This function flushes the impl 'cached' by load_balancing strategy. It's called
 * when an impl being added or removed from the method_store.
 */
static void lb_sched_strategy_status_flush(OSSL_METHOD_STORE *store, int nid)
{
    LB_GLOBAL *lgbl;

    lgbl = ossl_lib_ctx_get_data(store->ctx, OSSL_LIB_CTX_LB_STRATEGY_INDEX);
    if (lgbl == NULL)
        return;

    switch (lgbl->strategy) {
    case LB_STRATEGY_FREE_BANDWIDTH:
        lb_sched_free_bandwidth_best_impl_flush(lgbl->strategy_status, nid);
        break;
    case LB_STRATEGY_ROUND_ROBIN:
    case LB_STRATEGY_PRIORITY:
    case LB_STRATEGY_PACKET_SIZE:
    default:
        break;
    }
    return;
}

#if !defined(OPENSSL_NO_DEFAULT_THREAD_POOL)
/*
 * forward declaration
 * functions are defined later in this file
 */
static __owur int ossl_property_read_lock(OSSL_METHOD_STORE *p);
static ALGORITHM *ossl_method_store_retrieve(OSSL_METHOD_STORE *store, int nid);
static int ossl_property_unlock(OSSL_METHOD_STORE *p);

/*
 * callback on each element of fbw_status->best_impls, indexed by
 * nid_best_impl->nid
 */
static void impls_free_bandwidth_cb(ossl_uintmax_t idx,
                                    LBS_NID_BEST_IMPL *nid_best_impl,
                                    void *arg)
{
    LBS_FREE_BANDWIDTH_STATUS *fbw_status = arg;
    OSSL_METHOD_STORE *store;
    ALGORITHM *alg = NULL;
    OSSL_NAMEMAP *namemap;
    IMPLEMENTATION *impl, *curr_best_impl = NULL;
    FREE_BANDWIDTH_QUERY fbw_query;
    int num, ref, curr_best_fbw = -1;

    if (CRYPTO_atomic_add(&nid_best_impl->fetch_count, 0, &ref,
                          nid_best_impl->cnt_lock) <= 0)
        return;
    /* only update fbw when fetch_count falling into range */
    if (ref <= FETCH_COUNT_TRIGGER_THRESHOLD)
        return;
    /* reset fetch_count */
    if (CRYPTO_atomic_add(&nid_best_impl->fetch_count,
                          -(FETCH_COUNT_TRIGGER_THRESHOLD),
                          &ref, nid_best_impl->cnt_lock) <= 0)
        return;

    namemap = ossl_lib_ctx_get_data(fbw_status->libctx, OSSL_LIB_CTX_NAMEMAP_INDEX);
    store = ossl_lib_ctx_get_data(fbw_status->libctx, OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX);
    if ((namemap == NULL) || (store == NULL)
            || (!ossl_property_read_lock(store)))   /* require read lock for alg */
        return;
    alg = ossl_method_store_retrieve(store, nid_best_impl->nid);
    if (alg == NULL)
        goto fin;

    /* from name_id to name string */
    fbw_query.name = ossl_namemap_num2name(namemap,
                            evp_method_id_to_name_id(nid_best_impl->nid),
                            0);

    num = sk_IMPLEMENTATION_num(alg->impls);

    for (int i = 0; i < num; i++) {     /* check every impl */
        impl = sk_IMPLEMENTATION_value(alg->impls, i);
        fbw_query.free_bandwidth = 0;   /* reset before querying */
        /*
         * "f" is the key word for querying free_bandwidth
         */
        ossl_provider_get_capabilities(impl->provider, "f", NULL, &fbw_query);
        /* update this impl's free_bandwidth */
        /* update the so-far best_impl */
        if (fbw_query.free_bandwidth > curr_best_fbw) {
            curr_best_fbw = fbw_query.free_bandwidth;
            curr_best_impl = impl;
        }
    }

    if ((curr_best_impl == nid_best_impl->best_impl)
        || (curr_best_impl == NULL))
        goto fin;

    /* free the old one */
    if (nid_best_impl->best_impl != NULL)
        ossl_method_free(&nid_best_impl->best_impl->method);

    /* update nid_best_impl */
    nid_best_impl->best_impl = curr_best_impl;
    ossl_method_up_ref(&curr_best_impl->method);

fin:
    ossl_property_unlock(store);
    return;
}

/* BUG: TODO:
 *    The update_fbw thread is triggered by a specific <nid>, however
 *    it updates all <nid>'s best_impls.
 *  Expected behavior: only update the best_impl of the triggering <nid>'s
 */
/*
 * main entry of the free bandwidth update thread
 */
static CRYPTO_THREAD_RETVAL lb_sched_update_free_bandwidth_fn(void *data)
{
    LBS_FREE_BANDWIDTH_STATUS *fbw_status;

    fbw_status = (LBS_FREE_BANDWIDTH_STATUS *)data;
    /* take the lock */
    ossl_crypto_mutex_lock(fbw_status->lock);

    while (1) {
        /* wait on trigger */
        ossl_crypto_condvar_wait(fbw_status->condvar, fbw_status->lock);

        /* check isfinal flag */
        if (fbw_status->isfinalizing == 1)
            break;

        /* take rwlock since we are updating the fbw_status's best_impls */
        if (CRYPTO_THREAD_write_lock(fbw_status->rwlock) != 1)
            continue;
        /*
         * check each pair of <nid> + <impl>
         * update its free_bw
         */
        ossl_sa_LBS_NID_BEST_IMPL_doall_arg(fbw_status->best_impls,
                                            impls_free_bandwidth_cb,
                                            fbw_status);
        /* unlock */
        CRYPTO_THREAD_unlock(fbw_status->rwlock);
    }

    /* release the lock */
    ossl_crypto_mutex_unlock(fbw_status->lock);
    return 1;
}
#endif

void *ossl_lb_strategy_ctx_new(OSSL_LIB_CTX *libctx)
{
    LB_GLOBAL *lgbl = OPENSSL_zalloc(sizeof(*lgbl));

    if (lgbl == NULL)
        return NULL;

    lgbl->lock = CRYPTO_THREAD_lock_new();
    if (lgbl->lock == NULL) {
        OPENSSL_free(lgbl);
        return NULL;
    }

    return lgbl;
}

void ossl_lb_strategy_ctx_free(void *lgbl)
{
    LB_GLOBAL *gbl = lgbl;

    if (gbl == NULL)
        return;

    switch (gbl->strategy) {
    case LB_STRATEGY_ROUND_ROBIN:
        break;
    case LB_STRATEGY_FREE_BANDWIDTH:
        lb_sched_free_bandwidth_status_free(gbl->strategy_status);
        break;
    case LB_STRATEGY_PRIORITY:
    case LB_STRATEGY_PACKET_SIZE:
    default:
        break;
    }

    CRYPTO_THREAD_lock_free(gbl->lock);
    OPENSSL_free(gbl->strategy_status);
    OPENSSL_free(gbl);
    return;
}

static void ossl_method_cache_flush_alg(OSSL_METHOD_STORE *store,
                                        ALGORITHM *alg);
static void ossl_method_cache_flush(OSSL_METHOD_STORE *store, int nid);

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
                                                int loadconfig)
{
    OSSL_GLOBAL_PROPERTIES *globp;

#ifndef FIPS_MODULE
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

static __owur int ossl_property_read_lock(OSSL_METHOD_STORE *p)
{
    return p != NULL ? CRYPTO_THREAD_read_lock(p->lock) : 0;
}

static __owur int ossl_property_write_lock(OSSL_METHOD_STORE *p)
{
    return p != NULL ? CRYPTO_THREAD_write_lock(p->lock) : 0;
}

static int ossl_property_unlock(OSSL_METHOD_STORE *p)
{
    return p != 0 ? CRYPTO_THREAD_unlock(p->lock) : 0;
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

static void alg_cleanup(ossl_uintmax_t idx, ALGORITHM *a, void *arg)
{
    OSSL_METHOD_STORE *store = arg;

    if (a != NULL) {
        lb_sched_strategy_status_flush(store, a->nid);

        sk_IMPLEMENTATION_pop_free(a->impls, &impl_free);
        lh_QUERY_doall(a->cache, &impl_cache_free);
        lh_QUERY_free(a->cache);
        OPENSSL_free(a);
    }
    if (store != NULL)
        ossl_sa_ALGORITHM_set(store->algs, idx, NULL);
}

/* load-balancing scheduler function prototype */
typedef IMPLEMENTATION *(lb_sched_fn)(STACK_OF(IMPLEMENTATION) *impls,
                                      void *status, int nid);
/* forward declarations of available load balancing schedulers */
static lb_sched_fn lb_sched_round_robin;
static lb_sched_fn lb_sched_free_bandwidth;

static IMPLEMENTATION *lb_sched_round_robin(STACK_OF(IMPLEMENTATION) *impls,
                                            void *status, int nid)
{
    LBS_ROUND_ROBIN_STATUS *rr_status = (LBS_ROUND_ROBIN_STATUS *)status;
    IMPLEMENTATION *impl;
    int this_index;
    int num;

    if (rr_status == NULL)
        return NULL;

    if ((num = sk_IMPLEMENTATION_num(impls)) <= 0)    /* empty or NULL */
        return NULL;

    rr_status->last_index ++;
    this_index = (rr_status->last_index >= num) ? 0 : rr_status->last_index;
    rr_status->last_index = this_index;

    impl = sk_IMPLEMENTATION_value(impls, this_index);
    return impl;
}

/*
 * Free_bandwidth scheduler strategy:
 */
static IMPLEMENTATION *lb_sched_free_bandwidth(STACK_OF(IMPLEMENTATION) *impls,
                                               void *status, int nid)
{
    LBS_FREE_BANDWIDTH_STATUS *fbw_status = (LBS_FREE_BANDWIDTH_STATUS *)status;
    int num;

    if ((fbw_status == NULL)
            || (num = sk_IMPLEMENTATION_num(impls)) <= 0)    /* empty or NULL */
        return NULL;

#if !defined(OPENSSL_NO_DEFAULT_THREAD_POOL)
    LBS_NID_BEST_IMPL *nid_best_impl;
    int ref;

    if (!CRYPTO_THREAD_read_lock(fbw_status->rwlock))
            return NULL;
    nid_best_impl = ossl_sa_LBS_NID_BEST_IMPL_get(fbw_status->best_impls, nid);
    CRYPTO_THREAD_unlock(fbw_status->rwlock);

    if(nid_best_impl == NULL) {
        /* the first time to fetch this nid, alloc it */
        if ((nid_best_impl = OPENSSL_zalloc(sizeof(*nid_best_impl))) == NULL)
            return NULL;
        if ((nid_best_impl->cnt_lock = CRYPTO_THREAD_lock_new()) == NULL)
            goto err;
        nid_best_impl->nid = nid;
        nid_best_impl->best_impl = sk_IMPLEMENTATION_value(impls, 0);
        nid_best_impl->threshold = DEFAULT_MINIMUM_FREE_BANDWIDTH;
        nid_best_impl->fetch_count = 1;
        /* insert */
        if (!CRYPTO_THREAD_write_lock(fbw_status->rwlock))
            goto err;
        if (ossl_sa_LBS_NID_BEST_IMPL_set(fbw_status->best_impls, nid,
                                          nid_best_impl) != 1) {
            CRYPTO_THREAD_unlock(fbw_status->rwlock);
            goto err;
        }
        /* do up_ref() when it has been put into the SA successfully */
        ossl_method_up_ref(&nid_best_impl->best_impl->method);
        CRYPTO_THREAD_unlock(fbw_status->rwlock);
        /* trigger an update in lb_sched_update_free_bandwidth_fn() */
        ossl_crypto_condvar_broadcast(fbw_status->condvar);
        /* here we return immediately */
        return nid_best_impl->best_impl;
    }

    if (CRYPTO_atomic_add(&nid_best_impl->fetch_count, 1, &ref,
                          nid_best_impl->cnt_lock) <= 0)
        return NULL;

    /* to check wether or not to trigger an fbw_update */
    if ((ref > FETCH_COUNT_TRIGGER_THRESHOLD)
        || (nid_best_impl->best_impl == NULL))              /* nid flushed */
        ossl_crypto_condvar_broadcast(fbw_status->condvar);

    return (nid_best_impl->best_impl == NULL) ?
           sk_IMPLEMENTATION_value(impls, 0) : nid_best_impl->best_impl;
err:
    CRYPTO_THREAD_lock_free(nid_best_impl->cnt_lock);
    OPENSSL_free(nid_best_impl);
    return NULL;
#else
    /*
     * This is a slow path. When there is no thread pool, we will have to query
     * free_bandwidth from each implemenatation one by one.
     *
     * Query each impl->provider's free_bandwidth, and return the first one whose
     * free_bandwidth is bigger than the 'threshold'.
     * If none qualifies, the final impl which is queried is returned.

     * NOTE: always start the capability query from the last good impl.
     */
    return NULL;
#endif
}

static IMPLEMENTATION *load_balancer_fetch(OSSL_LIB_CTX *libctx,
                               STACK_OF(IMPLEMENTATION) *impls, int nid)
{
    LB_GLOBAL *lgbl;
    IMPLEMENTATION *impl = NULL;

    lgbl = ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_LB_STRATEGY_INDEX);
    if (lgbl == NULL)
        return NULL;

    /* obtain the lock */
    if (!CRYPTO_THREAD_write_lock(lgbl->lock))
       return NULL;

    switch (lgbl->strategy) {
    case LB_STRATEGY_ROUND_ROBIN:
        impl = lb_sched_round_robin(impls, lgbl->strategy_status, nid);
        goto end;
    case LB_STRATEGY_FREE_BANDWIDTH:
        impl = lb_sched_free_bandwidth(impls, lgbl->strategy_status, nid);
        goto end;

    #if 0   /* To-be-added */
    case LB_STRATEGY_PRIORITY:
        impl = lb_sched_priority(impls, lgbl->strategy_status);
        goto end;
    case LB_STRATEGY_PACKET_SIZE:
        impl = lb_sched_packet_size(impls, lgbl->strategy_status);
        goto end;
    #endif

    default:
        goto end;
    }

end:
    CRYPTO_THREAD_unlock(lgbl->lock);
    return impl;
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
        if ((res->algs = ossl_sa_ALGORITHM_new()) == NULL
            || (res->lock = CRYPTO_THREAD_lock_new()) == NULL
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
            ossl_sa_ALGORITHM_doall_arg(store->algs, &alg_cleanup, store);
        ossl_sa_ALGORITHM_free(store->algs);
        CRYPTO_THREAD_lock_free(store->lock);
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

static ALGORITHM *ossl_method_store_retrieve(OSSL_METHOD_STORE *store, int nid)
{
    return ossl_sa_ALGORITHM_get(store->algs, nid);
}

static int ossl_method_store_insert(OSSL_METHOD_STORE *store, ALGORITHM *alg)
{
    return ossl_sa_ALGORITHM_set(store->algs, alg->nid, alg);
}

int ossl_method_store_add(OSSL_METHOD_STORE *store, const OSSL_PROVIDER *prov,
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

    /* Insert into the hash table if required */
    if (!ossl_property_write_lock(store)) {
        OPENSSL_free(impl);
        return 0;
    }
    ossl_method_cache_flush(store, nid);
    lb_sched_strategy_status_flush(store, nid);

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
    ossl_property_unlock(store);
    if (ret == 0)
        impl_free(impl);
    return ret;

err:
    ossl_property_unlock(store);
    alg_cleanup(0, alg, NULL);
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

    if (!ossl_property_write_lock(store))
        return 0;
    ossl_method_cache_flush(store, nid);
    lb_sched_strategy_status_flush(store, nid);

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

        if (impl->method.method == method) {
            impl_free(impl);
            (void)sk_IMPLEMENTATION_delete(alg->impls, i);
            ossl_property_unlock(store);
            return 1;
        }
    }
    ossl_property_unlock(store);
    return 0;
}

struct alg_cleanup_by_provider_data_st {
    OSSL_METHOD_STORE *store;
    const OSSL_PROVIDER *prov;
};

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
            lb_sched_strategy_status_flush(data->store, alg->nid);

            impl_free(impl);
            (void)sk_IMPLEMENTATION_delete(alg->impls, i);
            count++;
        }
    }

    /*
     * If we removed any implementation, we also clear the whole associated
     * cache, 'cause that's the sensible thing to do.
     * There's no point flushing the cache entries where we didn't remove
     * any implementation, though.
     */
    if (count > 0)
        ossl_method_cache_flush_alg(data->store, alg);
}

int ossl_method_store_remove_all_provided(OSSL_METHOD_STORE *store,
                                          const OSSL_PROVIDER *prov)
{
    struct alg_cleanup_by_provider_data_st data;

    if (!ossl_property_write_lock(store))
        return 0;
    data.prov = prov;
    data.store = store;
    ossl_sa_ALGORITHM_doall_arg(store->algs, &alg_cleanup_by_provider, &data);
    ossl_property_unlock(store);
    return 1;
}

static void alg_do_one(ALGORITHM *alg, IMPLEMENTATION *impl,
                       void (*fn)(int id, void *method, void *fnarg),
                       void *fnarg)
{
    fn(alg->nid, impl->method.method, fnarg);
}

struct alg_do_each_data_st {
    void (*fn)(int id, void *method, void *fnarg);
    void *fnarg;
};

static void alg_do_each(ossl_uintmax_t idx, ALGORITHM *alg, void *arg)
{
    struct alg_do_each_data_st *data = arg;
    int i, end = sk_IMPLEMENTATION_num(alg->impls);

    for (i = 0; i < end; i++) {
        IMPLEMENTATION *impl = sk_IMPLEMENTATION_value(alg->impls, i);

        alg_do_one(alg, impl, data->fn, data->fnarg);
    }
}

void ossl_method_store_do_all(OSSL_METHOD_STORE *store,
                              void (*fn)(int id, void *method, void *fnarg),
                              void *fnarg)
{
    struct alg_do_each_data_st data;

    data.fn = fn;
    data.fnarg = fnarg;
    if (store != NULL)
        ossl_sa_ALGORITHM_doall_arg(store->algs, alg_do_each, &data);
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

#ifndef FIPS_MODULE
    if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL))
        return 0;
#endif

    if (nid <= 0 || method == NULL || store == NULL)
        return 0;

    /* This only needs to be a read lock, because the query won't create anything */
    if (!ossl_property_read_lock(store))
        return 0;
    alg = ossl_method_store_retrieve(store, nid);
    if (alg == NULL) {
        ossl_property_unlock(store);
        return 0;
    }

    /* does this belong to a load_balancer libctx and fetching from it succeed? */
    if ((ossl_lib_ctx_is_load_balancer(store->ctx))
        && ((impl = load_balancer_fetch(store->ctx, alg->impls, nid)) != NULL)
        && (prov == NULL || impl->provider == prov)) {
        best_impl = impl;
        ret = 1;
        goto fin;
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
    ossl_property_unlock(store);
    ossl_property_free(p2);
    return ret;
}

static void ossl_method_cache_flush_alg(OSSL_METHOD_STORE *store,
                                        ALGORITHM *alg)
{
    store->cache_nelem -= lh_QUERY_num_items(alg->cache);
    impl_cache_flush_alg(0, alg);
}

static void ossl_method_cache_flush(OSSL_METHOD_STORE *store, int nid)
{
    ALGORITHM *alg = ossl_method_store_retrieve(store, nid);

    if (alg != NULL)
        ossl_method_cache_flush_alg(store, alg);
}

int ossl_method_store_cache_flush_all(OSSL_METHOD_STORE *store)
{
    if (!ossl_property_write_lock(store))
        return 0;
    ossl_sa_ALGORITHM_doall(store->algs, &impl_cache_flush_alg);
    store->cache_nelem = 0;
    ossl_property_unlock(store);
    return 1;
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

static void ossl_method_cache_flush_some(OSSL_METHOD_STORE *store)
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
    store->cache_need_flush = 0;
    ossl_sa_ALGORITHM_doall_arg(store->algs, &impl_cache_flush_one_alg, &state);
    store->cache_nelem = state.nelem;
    /* Without a timer, update the global seed */
    if (state.using_global_seed)
        tsan_add(&global_seed, state.seed);
}

/*
 * return: 1, success; 0, failure
 */
int ossl_load_balancer_init(OSSL_LIB_CTX *ctx, int strategy)
{
    LB_GLOBAL *lgbl;
    void *status = NULL;

    /* initialize strategy */
    lgbl = ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_LB_STRATEGY_INDEX);
    if (lgbl == NULL)
        return 0;

    lgbl->strategy = strategy;
    switch (lgbl->strategy) {
    case LB_STRATEGY_ROUND_ROBIN:
        status = lb_sched_round_robin_new_status();
        break;
    case LB_STRATEGY_FREE_BANDWIDTH:
        status = lb_sched_free_bandwidth_new_status(ctx);
        break;
    case LB_STRATEGY_PRIORITY:
    case LB_STRATEGY_PACKET_SIZE:
    default:
        break;
    }

    if (status == NULL)
        return 0;
    lgbl->strategy_status = status;
    return 1;
}

int ossl_method_store_cache_get(OSSL_METHOD_STORE *store, OSSL_PROVIDER *prov,
                                int nid, const char *prop_query, void **method)
{
    ALGORITHM *alg;
    QUERY elem, *r;
    IMPLEMENTATION *impl;
    int res = 0;

    if (nid <= 0 || store == NULL || prop_query == NULL)
        return 0;

    if (!ossl_property_read_lock(store))
        return 0;
    alg = ossl_method_store_retrieve(store, nid);
    if (alg == NULL)
        goto err;

    /* does this belong to a load balancer libctx and fetching from it succeed? */
    if ((ossl_lib_ctx_is_load_balancer(store->ctx))
        && ((impl = load_balancer_fetch(store->ctx, alg->impls, nid)) != NULL)
        && (prov == NULL || impl->provider == prov)
        && (ossl_method_up_ref(&impl->method))) {
        *method = impl->method.method;
        res = 1;
        ossl_property_unlock(store);
        return res;
    }

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
    ossl_property_unlock(store);
    return res;
}

int ossl_method_store_cache_set(OSSL_METHOD_STORE *store, OSSL_PROVIDER *prov,
                                int nid, const char *prop_query, void *method,
                                int (*method_up_ref)(void *),
                                void (*method_destruct)(void *))
{
    QUERY elem, *old, *p = NULL;
    ALGORITHM *alg;
    size_t len;
    int res = 1;

    if (nid <= 0 || store == NULL || prop_query == NULL)
        return 0;

    if (!ossl_assert(prov != NULL))
        return 0;

    if (!ossl_property_write_lock(store))
        return 0;
    if (store->cache_need_flush)
        ossl_method_cache_flush_some(store);
    alg = ossl_method_store_retrieve(store, nid);
    if (alg == NULL)
        goto err;

    if (method == NULL) {
        elem.query = prop_query;
        elem.provider = prov;
        if ((old = lh_QUERY_delete(alg->cache, &elem)) != NULL) {
            impl_cache_free(old);
            store->cache_nelem--;
        }
        goto end;
    }
    p = OPENSSL_malloc(sizeof(*p) + (len = strlen(prop_query)));
    if (p != NULL) {
        p->query = p->body;
        p->provider = prov;
        p->method.method = method;
        p->method.up_ref = method_up_ref;
        p->method.free = method_destruct;
        if (!ossl_method_up_ref(&p->method))
            goto err;
        memcpy((char *)p->query, prop_query, len + 1);
        if ((old = lh_QUERY_insert(alg->cache, p)) != NULL) {
            impl_cache_free(old);
            goto end;
        }
        if (!lh_QUERY_error(alg->cache)) {
            if (++store->cache_nelem >= IMPL_CACHE_FLUSH_THRESHOLD)
                store->cache_need_flush = 1;
            goto end;
        }
        ossl_method_free(&p->method);
    }
err:
    res = 0;
    OPENSSL_free(p);
end:
    ossl_property_unlock(store);
    return res;
}
