/*
 * Copyright 2016-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use the OPENSSL_fork_*() deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/crypto.h>
#include <crypto/cryptlib.h>
#include "internal/cryptlib.h"
#include "internal/rcu.h"
#include "rcu_internal.h"

#if defined(__clang__) && defined(__has_feature)
# if __has_feature(thread_sanitizer)
#  define __SANITIZE_THREAD__
# endif
#endif

#if defined(__SANITIZE_THREAD__)
# include <sanitizer/tsan_interface.h>
# define TSAN_FAKE_UNLOCK(x)   __tsan_mutex_pre_unlock((x), 0); \
__tsan_mutex_post_unlock((x), 0)

# define TSAN_FAKE_LOCK(x)  __tsan_mutex_pre_lock((x), 0); \
__tsan_mutex_post_lock((x), 0, 0)
#else
# define TSAN_FAKE_UNLOCK(x)
# define TSAN_FAKE_LOCK(x)
#endif

#if defined(__sun)
# include <atomic.h>
#endif

#if defined(__apple_build_version__) && __apple_build_version__ < 6000000
/*
 * OS/X 10.7 and 10.8 had a weird version of clang which has __ATOMIC_ACQUIRE and
 * __ATOMIC_ACQ_REL but which expects only one parameter for __atomic_is_lock_free()
 * rather than two which has signature __atomic_is_lock_free(sizeof(_Atomic(T))).
 * All of this makes impossible to use __atomic_is_lock_free here.
 *
 * See: https://github.com/llvm/llvm-project/commit/a4c2602b714e6c6edb98164550a5ae829b2de760
 */
# define BROKEN_CLANG_ATOMICS
#endif

#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG) && !defined(OPENSSL_SYS_WINDOWS)

# if defined(OPENSSL_SYS_UNIX)
#  include <sys/types.h>
#  include <unistd.h>
# endif

# include <assert.h>

/*
 * The Non-Stop KLT thread model currently seems broken in its rwlock
 * implementation
 */
# if defined(PTHREAD_RWLOCK_INITIALIZER) && !defined(_KLT_MODEL_)
#  define USE_RWLOCK
# endif

/*
 * For all GNU/clang atomic builtins, we also need fallbacks, to cover all
 * other compilers.

 * Unfortunately, we can't do that with some "generic type", because there's no
 * guarantee that the chosen generic type is large enough to cover all cases.
 * Therefore, we implement fallbacks for each applicable type, with composed
 * names that include the type they handle.
 *
 * (an anecdote: we previously tried to use |void *| as the generic type, with
 * the thought that the pointer itself is the largest type.  However, this is
 * not true on 32-bit pointer platforms, as a |uint64_t| is twice as large)
 *
 * All applicable ATOMIC_ macros take the intended type as first parameter, so
 * they can map to the correct fallback function.  In the GNU/clang case, that
 * parameter is simply ignored.
 */

/*
 * Internal types used with the ATOMIC_ macros, to make it possible to compose
 * fallback function names.
 */
typedef void *pvoid;
typedef struct rcu_cb_item *prcu_cb_item;

# if defined(__GNUC__) && defined(__ATOMIC_ACQUIRE) && !defined(BROKEN_CLANG_ATOMICS) \
    && !defined(USE_ATOMIC_FALLBACKS)
#  if defined(__APPLE__) && defined(__clang__) && defined(__aarch64__)
/*
 * For pointers, Apple M1 virtualized cpu seems to have some problem using the
 * ldapr instruction (see https://github.com/openssl/openssl/pull/23974)
 * When using the native apple clang compiler, this instruction is emitted for
 * atomic loads, which is bad.  So, if
 * 1) We are building on a target that defines __APPLE__ AND
 * 2) We are building on a target using clang (__clang__) AND
 * 3) We are building for an M1 processor (__aarch64__)
 * Then we should not use __atomic_load_n and instead implement our own
 * function to issue the ldar instruction instead, which produces the proper
 * sequencing guarantees
 */
static inline void *apple_atomic_load_n_pvoid(void **p,
                                              ossl_unused int memorder)
{
    void *ret;

    __asm volatile("ldar %0, [%1]" : "=r" (ret): "r" (p):);

    return ret;
}

/* For uint64_t, we should be fine, though */
#   define apple_atomic_load_n_uint32_t(p, o) __atomic_load_n(p, o)
#   define apple_atomic_load_n_uint64_t(p, o) __atomic_load_n(p, o)

#   define ATOMIC_LOAD_N(t, p, o) apple_atomic_load_n_##t(p, o)
#  else
#   define ATOMIC_LOAD_N(t, p, o) __atomic_load_n(p, o)
#  endif
#  define ATOMIC_STORE_N(t, p, v, o) __atomic_store_n(p, v, o)
#  define ATOMIC_STORE(t, p, v, o) __atomic_store(p, v, o)
#  define ATOMIC_EXCHANGE_N(t, p, v, o) __atomic_exchange_n(p, v, o)
#  define ATOMIC_ADD_FETCH(p, v, o) __atomic_add_fetch(p, v, o)
#  define ATOMIC_FETCH_ADD(p, v, o) __atomic_fetch_add(p, v, o)
#  define ATOMIC_SUB_FETCH(p, v, o) __atomic_sub_fetch(p, v, o)
#  define ATOMIC_AND_FETCH(p, m, o) __atomic_and_fetch(p, m, o)
#  define ATOMIC_OR_FETCH(p, m, o) __atomic_or_fetch(p, m, o)
# else
static pthread_mutex_t atomic_sim_lock = PTHREAD_MUTEX_INITIALIZER;

#  define IMPL_fallback_atomic_load_n(t)                        \
    static ossl_inline t fallback_atomic_load_n_##t(t *p)            \
    {                                                           \
        t ret;                                                  \
                                                                \
        pthread_mutex_lock(&atomic_sim_lock);                   \
        ret = *p;                                               \
        pthread_mutex_unlock(&atomic_sim_lock);                 \
        return ret;                                             \
    }
IMPL_fallback_atomic_load_n(uint32_t)
IMPL_fallback_atomic_load_n(uint64_t)
IMPL_fallback_atomic_load_n(pvoid)

#  define ATOMIC_LOAD_N(t, p, o) fallback_atomic_load_n_##t(p)

#  define IMPL_fallback_atomic_store_n(t)                       \
    static ossl_inline t fallback_atomic_store_n_##t(t *p, t v)      \
    {                                                           \
        t ret;                                                  \
                                                                \
        pthread_mutex_lock(&atomic_sim_lock);                   \
        ret = *p;                                               \
        *p = v;                                                 \
        pthread_mutex_unlock(&atomic_sim_lock);                 \
        return ret;                                             \
    }
IMPL_fallback_atomic_store_n(uint32_t)
IMPL_fallback_atomic_store_n(uint64_t)

#  define ATOMIC_STORE_N(t, p, v, o) fallback_atomic_store_n_##t(p, v)

#  define IMPL_fallback_atomic_store(t)                         \
    static ossl_inline void fallback_atomic_store_##t(t *p, t *v)    \
    {                                                           \
        pthread_mutex_lock(&atomic_sim_lock);                   \
        *p = *v;                                                \
        pthread_mutex_unlock(&atomic_sim_lock);                 \
    }
IMPL_fallback_atomic_store(uint64_t)
IMPL_fallback_atomic_store(pvoid)

#  define ATOMIC_STORE(t, p, v, o) fallback_atomic_store_##t(p, v)

#  define IMPL_fallback_atomic_exchange_n(t)                            \
    static ossl_inline t fallback_atomic_exchange_n_##t(t *p, t v)           \
    {                                                                   \
        t ret;                                                          \
                                                                        \
        pthread_mutex_lock(&atomic_sim_lock);                           \
        ret = *p;                                                       \
        *p = v;                                                         \
        pthread_mutex_unlock(&atomic_sim_lock);                         \
        return ret;                                                     \
    }
IMPL_fallback_atomic_exchange_n(uint64_t)
IMPL_fallback_atomic_exchange_n(prcu_cb_item)

#  define ATOMIC_EXCHANGE_N(t, p, v, o) fallback_atomic_exchange_n_##t(p, v)

/*
 * The fallbacks that follow don't need any per type implementation, as
 * they are designed for uint64_t only.  If there comes a time when multiple
 * types need to be covered, it's relatively easy to refactor them the same
 * way as the fallbacks above.
 */

static ossl_inline uint64_t fallback_atomic_add_fetch(uint64_t *p, uint64_t v)
{
    uint64_t ret;

    pthread_mutex_lock(&atomic_sim_lock);
    *p += v;
    ret = *p;
    pthread_mutex_unlock(&atomic_sim_lock);
    return ret;
}

#  define ATOMIC_ADD_FETCH(p, v, o) fallback_atomic_add_fetch(p, v)

static ossl_inline uint64_t fallback_atomic_fetch_add(uint64_t *p, uint64_t v)
{
    uint64_t ret;

    pthread_mutex_lock(&atomic_sim_lock);
    ret = *p;
    *p += v;
    pthread_mutex_unlock(&atomic_sim_lock);
    return ret;
}

#  define ATOMIC_FETCH_ADD(p, v, o) fallback_atomic_fetch_add(p, v)

static ossl_inline uint64_t fallback_atomic_sub_fetch(uint64_t *p, uint64_t v)
{
    uint64_t ret;

    pthread_mutex_lock(&atomic_sim_lock);
    *p -= v;
    ret = *p;
    pthread_mutex_unlock(&atomic_sim_lock);
    return ret;
}

#  define ATOMIC_SUB_FETCH(p, v, o) fallback_atomic_sub_fetch(p, v)

static ossl_inline uint64_t fallback_atomic_and_fetch(uint64_t *p, uint64_t m)
{
    uint64_t ret;

    pthread_mutex_lock(&atomic_sim_lock);
    *p &= m;
    ret = *p;
    pthread_mutex_unlock(&atomic_sim_lock);
    return ret;
}

#  define ATOMIC_AND_FETCH(p, v, o) fallback_atomic_and_fetch(p, v)

static ossl_inline uint64_t fallback_atomic_or_fetch(uint64_t *p, uint64_t m)
{
    uint64_t ret;

    pthread_mutex_lock(&atomic_sim_lock);
    *p |= m;
    ret = *p;
    pthread_mutex_unlock(&atomic_sim_lock);
    return ret;
}

#  define ATOMIC_OR_FETCH(p, v, o) fallback_atomic_or_fetch(p, v)
# endif

/*
 * users is broken up into 2 parts
 * bits 0-15 current readers
 * bit 32-63 ID
 */
# define READER_SHIFT 0
# define ID_SHIFT 32
/* TODO: READER_SIZE 32 in threads_win.c */
# define READER_SIZE 16
# define ID_SIZE 32

# define READER_MASK     (((uint64_t)1 << READER_SIZE) - 1)
# define ID_MASK         (((uint64_t)1 << ID_SIZE) - 1)
# define READER_COUNT(x) ((uint32_t)(((uint64_t)(x) >> READER_SHIFT) & \
                                     READER_MASK))
# define ID_VAL(x)       ((uint32_t)(((uint64_t)(x) >> ID_SHIFT) & ID_MASK))
# define VAL_READER      ((uint64_t)1 << READER_SHIFT)
# define VAL_ID(x)       ((uint64_t)x << ID_SHIFT)

/*
 * This is the core of an rcu lock. It tracks the readers and writers for the
 * current quiescence point for a given lock. Users is the 64 bit value that
 * stores the READERS/ID as defined above
 *
 */
struct rcu_qp {
    uint64_t users;
};

struct thread_qp {
    struct rcu_qp *qp;
    unsigned int depth;
    CRYPTO_RCU_LOCK *lock;
};

# define MAX_QPS 10
/*
 * This is the per thread tracking data
 * that is assigned to each thread participating
 * in an rcu qp
 *
 * qp points to the qp that it last acquired
 *
 */
struct rcu_thr_data {
    struct thread_qp thread_qps[MAX_QPS];
};

/*
 * This is the internal version of a CRYPTO_RCU_LOCK
 * it is cast from CRYPTO_RCU_LOCK
 */
struct rcu_lock_st {
    /* Callbacks to call for next ossl_synchronize_rcu */
    struct rcu_cb_item *cb_items;

    /* The context we are being created against */
    OSSL_LIB_CTX *ctx;

    /* rcu generation counter for in-order retirement */
    uint32_t id_ctr;

    /* TODO: can be moved before id_ctr for better alignment */
    /* Array of quiescent points for synchronization */
    struct rcu_qp *qp_group;

    /* Number of elements in qp_group array */
    uint32_t group_count;

    /* Index of the current qp in the qp_group array */
    uint32_t reader_idx;

    /* value of the next id_ctr value to be retired */
    uint32_t next_to_retire;

    /* index of the next free rcu_qp in the qp_group */
    uint32_t current_alloc_idx;

    /* number of qp's in qp_group array currently being retired */
    uint32_t writers_alloced;

    /* lock protecting write side operations */
    pthread_mutex_t write_lock;

    /* lock protecting updates to writers_alloced/current_alloc_idx */
    pthread_mutex_t alloc_lock;

    /* signal to wake threads waiting on alloc_lock */
    pthread_cond_t alloc_signal;

    /* lock to enforce in-order retirement */
    pthread_mutex_t prior_lock;

    /* signal to wake threads waiting on prior_lock */
    pthread_cond_t prior_signal;
};

/* Read side acquisition of the current qp */
static struct rcu_qp *get_hold_current_qp(struct rcu_lock_st *lock)
{
    uint32_t qp_idx;

    /* get the current qp index */
    for (;;) {
        /*
         * Notes on use of __ATOMIC_ACQUIRE
         * We need to ensure the following:
         * 1) That subsequent operations aren't optimized by hoisting them above
         * this operation.  Specifically, we don't want the below re-load of
         * qp_idx to get optimized away
         * 2) We want to ensure that any updating of reader_idx on the write side
         * of the lock is flushed from a local cpu cache so that we see any
         * updates prior to the load.  This is a non-issue on cache coherent
         * systems like x86, but is relevant on other arches
         * Note: This applies to the reload below as well
         */
        qp_idx = ATOMIC_LOAD_N(uint32_t, &lock->reader_idx, __ATOMIC_ACQUIRE);

        /*
         * Notes of use of __ATOMIC_RELEASE
         * This counter is only read by the write side of the lock, and so we
         * specify __ATOMIC_RELEASE here to ensure that the write side of the
         * lock see this during the spin loop read of users, as it waits for the
         * reader count to approach zero
         */
        ATOMIC_ADD_FETCH(&lock->qp_group[qp_idx].users, VAL_READER,
                         __ATOMIC_RELEASE);

        /* if the idx hasn't changed, we're good, else try again */
        if (qp_idx == ATOMIC_LOAD_N(uint32_t, &lock->reader_idx, __ATOMIC_ACQUIRE))
            break;

        /*
         * Notes on use of __ATOMIC_RELEASE
         * As with the add above, we want to ensure that this decrement is
         * seen by the write side of the lock as soon as it happens to prevent
         * undue spinning waiting for write side completion
         */
        ATOMIC_SUB_FETCH(&lock->qp_group[qp_idx].users, VAL_READER,
                         __ATOMIC_RELEASE);
    }

    return &lock->qp_group[qp_idx];
}

static void ossl_rcu_free_local_data(void *arg)
{
    OSSL_LIB_CTX *ctx = arg;
    CRYPTO_THREAD_LOCAL *lkey = ossl_lib_ctx_get_rcukey(ctx);
    struct rcu_thr_data *data = CRYPTO_THREAD_get_local(lkey);

    OPENSSL_free(data);
    CRYPTO_THREAD_set_local(lkey, NULL);
}

void ossl_rcu_read_lock(CRYPTO_RCU_LOCK *lock)
{
    struct rcu_thr_data *data;
    int i, available_qp = -1;
    CRYPTO_THREAD_LOCAL *lkey = ossl_lib_ctx_get_rcukey(lock->ctx);

    /*
     * we're going to access current_qp here so ask the
     * processor to fetch it
     */
    data = CRYPTO_THREAD_get_local(lkey);

    if (data == NULL) {
        data = OPENSSL_zalloc(sizeof(*data));
        OPENSSL_assert(data != NULL);
        CRYPTO_THREAD_set_local(lkey, data);
        ossl_init_thread_start(NULL, lock->ctx, ossl_rcu_free_local_data);
    }

    for (i = 0; i < MAX_QPS; i++) {
        if (data->thread_qps[i].qp == NULL && available_qp == -1)
            available_qp = i;
        /* If we have a hold on this lock already, we're good */
        if (data->thread_qps[i].lock == lock) {
            data->thread_qps[i].depth++;
            return;
        }
    }

    /*
     * if we get here, then we don't have a hold on this lock yet
     */
    assert(available_qp != -1);

    data->thread_qps[available_qp].qp = get_hold_current_qp(lock);
    data->thread_qps[available_qp].depth = 1;
    data->thread_qps[available_qp].lock = lock;
}

void ossl_rcu_read_unlock(CRYPTO_RCU_LOCK *lock)
{
    int i;
    CRYPTO_THREAD_LOCAL *lkey = ossl_lib_ctx_get_rcukey(lock->ctx);
    struct rcu_thr_data *data = CRYPTO_THREAD_get_local(lkey);
    uint64_t ret;

    assert(data != NULL);

    for (i = 0; i < MAX_QPS; i++) {
        if (data->thread_qps[i].lock == lock) {
            /*
             * As with read side acquisition, we use __ATOMIC_RELEASE here
             * to ensure that the decrement is published immediately
             * to any write side waiters
             */
            data->thread_qps[i].depth--;
            if (data->thread_qps[i].depth == 0) {
                ret = ATOMIC_SUB_FETCH(&data->thread_qps[i].qp->users, VAL_READER,
                                       __ATOMIC_RELEASE);
                OPENSSL_assert(ret != UINT64_MAX);
                data->thread_qps[i].qp = NULL;
                data->thread_qps[i].lock = NULL;
            }
            return;
        }
    }
    /*
     * If we get here, we're trying to unlock a lock that we never acquired -
     * that's fatal.
     */
    assert(0);
}

/*
 * Write side allocation routine to get the current qp
 * and replace it with a new one
 */
static struct rcu_qp *update_qp(CRYPTO_RCU_LOCK *lock)
{
    uint64_t new_id;
    uint32_t current_idx;

    pthread_mutex_lock(&lock->alloc_lock);

    /*
     * we need at least one qp to be available with one
     * left over, so that readers can start working on
     * one that isn't yet being waited on
     */
    while (lock->group_count - lock->writers_alloced < 2)
        /* we have to wait for one to be free */
        pthread_cond_wait(&lock->alloc_signal, &lock->alloc_lock);

    current_idx = lock->current_alloc_idx;

    /* Allocate the qp */
    lock->writers_alloced++;

    /* increment the allocation index */
    lock->current_alloc_idx =
        (lock->current_alloc_idx + 1) % lock->group_count;

    /* get and insert a new id */
    new_id = VAL_ID(lock->id_ctr);
    lock->id_ctr++;

    /*
     * Even though we are under a write side lock here
     * We need to use atomic instructions to ensure that the results
     * of this update are published to the read side prior to updating the
     * reader idx below
     */
    ATOMIC_AND_FETCH(&lock->qp_group[current_idx].users, ID_MASK,
                     __ATOMIC_RELEASE);
    ATOMIC_OR_FETCH(&lock->qp_group[current_idx].users, new_id,
                    __ATOMIC_RELEASE);

    /*
     * Update the reader index to be the prior qp.
     * Note the use of __ATOMIC_RELEASE here is based on the corresponding use
     * of __ATOMIC_ACQUIRE in get_hold_current_qp, as we want any publication
     * of this value to be seen on the read side immediately after it happens
     */
    ATOMIC_STORE_N(uint32_t, &lock->reader_idx, lock->current_alloc_idx,
                   __ATOMIC_RELEASE);

    /* wake up any waiters */
    pthread_cond_signal(&lock->alloc_signal);
    pthread_mutex_unlock(&lock->alloc_lock);
    return &lock->qp_group[current_idx];
}

static void retire_qp(CRYPTO_RCU_LOCK *lock, struct rcu_qp *qp)
{
    pthread_mutex_lock(&lock->alloc_lock);
    lock->writers_alloced--;
    pthread_cond_signal(&lock->alloc_signal);
    pthread_mutex_unlock(&lock->alloc_lock);
}

/* TODO: count should be unsigned, e.g uint32_t */
/* a negative value could result in unexpected behaviour */
static struct rcu_qp *allocate_new_qp_group(CRYPTO_RCU_LOCK *lock,
                                            int count)
{
    struct rcu_qp *new =
        OPENSSL_zalloc(sizeof(*new) * count);

    lock->group_count = count;
    return new;
}

void ossl_rcu_write_lock(CRYPTO_RCU_LOCK *lock)
{
    pthread_mutex_lock(&lock->write_lock);
    TSAN_FAKE_UNLOCK(&lock->write_lock);
}

void ossl_rcu_write_unlock(CRYPTO_RCU_LOCK *lock)
{
    TSAN_FAKE_LOCK(&lock->write_lock);
    pthread_mutex_unlock(&lock->write_lock);
}

void ossl_synchronize_rcu(CRYPTO_RCU_LOCK *lock)
{
    struct rcu_qp *qp;
    uint64_t count;
    struct rcu_cb_item *cb_items, *tmpcb;

    pthread_mutex_lock(&lock->write_lock);
    cb_items = lock->cb_items;
    lock->cb_items = NULL;
    pthread_mutex_unlock(&lock->write_lock);

    qp = update_qp(lock);

    /*
     * wait for the reader count to reach zero
     * Note the use of __ATOMIC_ACQUIRE here to ensure that any
     * prior __ATOMIC_RELEASE write operation in get_hold_current_qp
     * is visible prior to our read
     */
    do {
        count = ATOMIC_LOAD_N(uint64_t, &qp->users, __ATOMIC_ACQUIRE);
    } while (READER_COUNT(count) != 0);

    /* retire in order */
    pthread_mutex_lock(&lock->prior_lock);
    while (lock->next_to_retire != ID_VAL(count))
        pthread_cond_wait(&lock->prior_signal, &lock->prior_lock);
    lock->next_to_retire++;
    pthread_cond_broadcast(&lock->prior_signal);
    pthread_mutex_unlock(&lock->prior_lock);

    retire_qp(lock, qp);

    /* handle any callbacks that we have */
    while (cb_items != NULL) {
        tmpcb = cb_items;
        cb_items = cb_items->next;
        tmpcb->fn(tmpcb->data);
        OPENSSL_free(tmpcb);
    }
}

int ossl_rcu_call(CRYPTO_RCU_LOCK *lock, rcu_cb_fn cb, void *data)
{
    struct rcu_cb_item *new =
        OPENSSL_zalloc(sizeof(*new));

    if (new == NULL)
        return 0;

    new->data = data;
    new->fn = cb;
    /*
     * Use __ATOMIC_ACQ_REL here to indicate that any prior writes to this
     * list are visible to us prior to reading, and publish the new value
     * immediately
     */
    new->next = ATOMIC_EXCHANGE_N(prcu_cb_item, &lock->cb_items, new,
                                  __ATOMIC_ACQ_REL);

    return 1;
}

void *ossl_rcu_uptr_deref(void **p)
{
    return ATOMIC_LOAD_N(pvoid, p, __ATOMIC_ACQUIRE);
}

void ossl_rcu_assign_uptr(void **p, void **v)
{
    ATOMIC_STORE(pvoid, p, v, __ATOMIC_RELEASE);
}

CRYPTO_RCU_LOCK *ossl_rcu_lock_new(int num_writers, OSSL_LIB_CTX *ctx)
{
    struct rcu_lock_st *new;

    if (num_writers < 1)
        num_writers = 1;

    ctx = ossl_lib_ctx_get_concrete(ctx);
    if (ctx == NULL)
        return 0;

    new = OPENSSL_zalloc(sizeof(*new));
    if (new == NULL)
        return NULL;

    new->ctx = ctx;
    pthread_mutex_init(&new->write_lock, NULL);
    pthread_mutex_init(&new->prior_lock, NULL);
    pthread_mutex_init(&new->alloc_lock, NULL);
    pthread_cond_init(&new->prior_signal, NULL);
    pthread_cond_init(&new->alloc_signal, NULL);
    new->qp_group = allocate_new_qp_group(new, num_writers + 1);
    if (new->qp_group == NULL) {
        OPENSSL_free(new);
        new = NULL;
    }
    return new;
}

void ossl_rcu_lock_free(CRYPTO_RCU_LOCK *lock)
{
    struct rcu_lock_st *rlock = (struct rcu_lock_st *)lock;

    if (lock == NULL)
        return;

    /* make sure we're synchronized */
    ossl_synchronize_rcu(rlock);

    OPENSSL_free(rlock->qp_group);
    /* There should only be a single qp left now */
    OPENSSL_free(rlock);
}

CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void)
{
# ifdef USE_RWLOCK
    CRYPTO_RWLOCK *lock;

    if ((lock = OPENSSL_zalloc(sizeof(pthread_rwlock_t))) == NULL)
        /* Don't set error, to avoid recursion blowup. */
        return NULL;

    if (pthread_rwlock_init(lock, NULL) != 0) {
        OPENSSL_free(lock);
        return NULL;
    }
# else
    pthread_mutexattr_t attr;
    CRYPTO_RWLOCK *lock;

    if ((lock = OPENSSL_zalloc(sizeof(pthread_mutex_t))) == NULL)
        /* Don't set error, to avoid recursion blowup. */
        return NULL;

    /*
     * We don't use recursive mutexes, but try to catch errors if we do.
     */
    pthread_mutexattr_init(&attr);
#  if !defined (__TANDEM) && !defined (_SPT_MODEL_)
#   if !defined(NDEBUG) && !defined(OPENSSL_NO_MUTEX_ERRORCHECK)
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#   endif
#  else
    /* The SPT Thread Library does not define MUTEX attributes. */
#  endif

    if (pthread_mutex_init(lock, &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        OPENSSL_free(lock);
        return NULL;
    }

    pthread_mutexattr_destroy(&attr);
# endif

    return lock;
}

__owur int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock)
{
# ifdef USE_RWLOCK
    if (pthread_rwlock_rdlock(lock) != 0)
        return 0;
# else
    if (pthread_mutex_lock(lock) != 0) {
        assert(errno != EDEADLK && errno != EBUSY);
        return 0;
    }
# endif

    return 1;
}

__owur int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock)
{
# ifdef USE_RWLOCK
    if (pthread_rwlock_wrlock(lock) != 0)
        return 0;
# else
    if (pthread_mutex_lock(lock) != 0) {
        assert(errno != EDEADLK && errno != EBUSY);
        return 0;
    }
# endif

    return 1;
}

int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock)
{
# ifdef USE_RWLOCK
    if (pthread_rwlock_unlock(lock) != 0)
        return 0;
# else
    if (pthread_mutex_unlock(lock) != 0) {
        assert(errno != EPERM);
        return 0;
    }
# endif

    return 1;
}

void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock)
{
    if (lock == NULL)
        return;

# ifdef USE_RWLOCK
    pthread_rwlock_destroy(lock);
# else
    pthread_mutex_destroy(lock);
# endif
    OPENSSL_free(lock);

    return;
}

int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void))
{
    if (pthread_once(once, init) != 0)
        return 0;

    return 1;
}

int CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *))
{
    if (pthread_key_create(key, cleanup) != 0)
        return 0;

    return 1;
}

void *CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL *key)
{
    return pthread_getspecific(*key);
}

int CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL *key, void *val)
{
    if (pthread_setspecific(*key, val) != 0)
        return 0;

    return 1;
}

int CRYPTO_THREAD_cleanup_local(CRYPTO_THREAD_LOCAL *key)
{
    if (pthread_key_delete(*key) != 0)
        return 0;

    return 1;
}

CRYPTO_THREAD_ID CRYPTO_THREAD_get_current_id(void)
{
    return pthread_self();
}

int CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b)
{
    return pthread_equal(a, b);
}

int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock)
{
# if defined(__GNUC__) && defined(__ATOMIC_ACQ_REL) && !defined(BROKEN_CLANG_ATOMICS)
    if (__atomic_is_lock_free(sizeof(*val), val)) {
        *ret = __atomic_add_fetch(val, amount, __ATOMIC_ACQ_REL);
        return 1;
    }
# elif defined(__sun) && (defined(__SunOS_5_10) || defined(__SunOS_5_11))
    /* This will work for all future Solaris versions. */
    if (ret != NULL) {
        *ret = atomic_add_int_nv((volatile unsigned int *)val, amount);
        return 1;
    }
# endif
    if (lock == NULL || !CRYPTO_THREAD_write_lock(lock))
        return 0;

    *val += amount;
    *ret  = *val;

    if (!CRYPTO_THREAD_unlock(lock))
        return 0;

    return 1;
}

int CRYPTO_atomic_add64(uint64_t *val, uint64_t op, uint64_t *ret,
                        CRYPTO_RWLOCK *lock)
{
# if defined(__GNUC__) && defined(__ATOMIC_ACQ_REL) && !defined(BROKEN_CLANG_ATOMICS)
    if (__atomic_is_lock_free(sizeof(*val), val)) {
        *ret = __atomic_add_fetch(val, op, __ATOMIC_ACQ_REL);
        return 1;
    }
# elif defined(__sun) && (defined(__SunOS_5_10) || defined(__SunOS_5_11))
    /* This will work for all future Solaris versions. */
    if (ret != NULL) {
        *ret = atomic_add_64_nv(val, op);
        return 1;
    }
# endif
    if (lock == NULL || !CRYPTO_THREAD_write_lock(lock))
        return 0;
    *val += op;
    *ret  = *val;

    if (!CRYPTO_THREAD_unlock(lock))
        return 0;

    return 1;
}

int CRYPTO_atomic_and(uint64_t *val, uint64_t op, uint64_t *ret,
                      CRYPTO_RWLOCK *lock)
{
# if defined(__GNUC__) && defined(__ATOMIC_ACQ_REL) && !defined(BROKEN_CLANG_ATOMICS)
    if (__atomic_is_lock_free(sizeof(*val), val)) {
        *ret = __atomic_and_fetch(val, op, __ATOMIC_ACQ_REL);
        return 1;
    }
# elif defined(__sun) && (defined(__SunOS_5_10) || defined(__SunOS_5_11))
    /* This will work for all future Solaris versions. */
    if (ret != NULL) {
        *ret = atomic_and_64_nv(val, op);
        return 1;
    }
# endif
    if (lock == NULL || !CRYPTO_THREAD_write_lock(lock))
        return 0;
    *val &= op;
    *ret  = *val;

    if (!CRYPTO_THREAD_unlock(lock))
        return 0;

    return 1;
}

int CRYPTO_atomic_or(uint64_t *val, uint64_t op, uint64_t *ret,
                     CRYPTO_RWLOCK *lock)
{
# if defined(__GNUC__) && defined(__ATOMIC_ACQ_REL) && !defined(BROKEN_CLANG_ATOMICS)
    if (__atomic_is_lock_free(sizeof(*val), val)) {
        *ret = __atomic_or_fetch(val, op, __ATOMIC_ACQ_REL);
        return 1;
    }
# elif defined(__sun) && (defined(__SunOS_5_10) || defined(__SunOS_5_11))
    /* This will work for all future Solaris versions. */
    if (ret != NULL) {
        *ret = atomic_or_64_nv(val, op);
        return 1;
    }
# endif
    if (lock == NULL || !CRYPTO_THREAD_write_lock(lock))
        return 0;
    *val |= op;
    *ret  = *val;

    if (!CRYPTO_THREAD_unlock(lock))
        return 0;

    return 1;
}

int CRYPTO_atomic_load(uint64_t *val, uint64_t *ret, CRYPTO_RWLOCK *lock)
{
# if defined(__GNUC__) && defined(__ATOMIC_ACQUIRE) && !defined(BROKEN_CLANG_ATOMICS)
    if (__atomic_is_lock_free(sizeof(*val), val)) {
        __atomic_load(val, ret, __ATOMIC_ACQUIRE);
        return 1;
    }
# elif defined(__sun) && (defined(__SunOS_5_10) || defined(__SunOS_5_11))
    /* This will work for all future Solaris versions. */
    if (ret != NULL) {
        *ret = atomic_or_64_nv(val, 0);
        return 1;
    }
# endif
    if (lock == NULL || !CRYPTO_THREAD_read_lock(lock))
        return 0;
    *ret  = *val;
    if (!CRYPTO_THREAD_unlock(lock))
        return 0;

    return 1;
}

int CRYPTO_atomic_store(uint64_t *dst, uint64_t val, CRYPTO_RWLOCK *lock)
{
# if defined(__GNUC__) && defined(__ATOMIC_ACQUIRE) && !defined(BROKEN_CLANG_ATOMICS)
    if (__atomic_is_lock_free(sizeof(*dst), dst)) {
        __atomic_store(dst, &val, __ATOMIC_RELEASE);
        return 1;
    }
# elif defined(__sun) && (defined(__SunOS_5_10) || defined(__SunOS_5_11))
    /* This will work for all future Solaris versions. */
    if (ret != NULL) {
        atomic_swap_64(dst, val);
        return 1;
    }
# endif
    if (lock == NULL || !CRYPTO_THREAD_write_lock(lock))
        return 0;
    *dst  = val;
    if (!CRYPTO_THREAD_unlock(lock))
        return 0;

    return 1;
}

int CRYPTO_atomic_load_int(int *val, int *ret, CRYPTO_RWLOCK *lock)
{
# if defined(__GNUC__) && defined(__ATOMIC_ACQUIRE) && !defined(BROKEN_CLANG_ATOMICS)
    if (__atomic_is_lock_free(sizeof(*val), val)) {
        __atomic_load(val, ret, __ATOMIC_ACQUIRE);
        return 1;
    }
# elif defined(__sun) && (defined(__SunOS_5_10) || defined(__SunOS_5_11))
    /* This will work for all future Solaris versions. */
    if (ret != NULL) {
        *ret = (int)atomic_or_uint_nv((unsigned int *)val, 0);
        return 1;
    }
# endif
    if (lock == NULL || !CRYPTO_THREAD_read_lock(lock))
        return 0;
    *ret  = *val;
    if (!CRYPTO_THREAD_unlock(lock))
        return 0;

    return 1;
}

# ifndef FIPS_MODULE
int openssl_init_fork_handlers(void)
{
    return 1;
}
# endif /* FIPS_MODULE */

int openssl_get_fork_id(void)
{
    return getpid();
}
#endif
