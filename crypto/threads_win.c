/*
 * Copyright 2016-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if defined(_WIN32)
# include <windows.h>
# if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x600
#  define USE_RWLOCK
# endif
#endif
#include <assert.h>

/*
 * VC++ 2008 or earlier x86 compilers do not have an inline implementation
 * of InterlockedOr64 for 32bit and will fail to run on Windows XP 32bit.
 * https://docs.microsoft.com/en-us/cpp/intrinsics/interlockedor-intrinsic-functions#requirements
 * To work around this problem, we implement a manual locking mechanism for
 * only VC++ 2008 or earlier x86 compilers.
 */

#if (defined(_MSC_VER) && defined(_M_IX86) && _MSC_VER <= 1600)
# define NO_INTERLOCKEDOR64
#endif

#include <openssl/crypto.h>
#include <crypto/cryptlib.h>
#include "internal/common.h"
#include "internal/thread_arch.h"
#include "internal/rcu.h"
#include "rcu_internal.h"

#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG) && defined(OPENSSL_SYS_WINDOWS)

# ifdef USE_RWLOCK
typedef struct {
    SRWLOCK lock;
    int exclusive;
} CRYPTO_win_rwlock;
# endif

static CRYPTO_THREAD_LOCAL rcu_thr_key;

# define READER_SHIFT 0
# define ID_SHIFT 32 
# define READER_SIZE 32 
# define ID_SIZE 32 

# define READER_MASK     (((LONG64)1 << READER_SIZE)-1)
# define ID_MASK         (((LONG64)1 << ID_SIZE)-1)
# define READER_COUNT(x) (((LONG64)(x) >> READER_SHIFT) & READER_MASK)
# define ID_VAL(x)       (((LONG64)(x) >> ID_SHIFT) & ID_MASK)
# define VAL_READER      ((LONG64)1 << READER_SHIFT)
# define VAL_ID(x)       ((LONG64)x << ID_SHIFT)

/*
 * This defines a quescent point (qp)
 * This is the barrier beyond which a writer
 * must wait before freeing data that was
 * atomically updated
 */
struct rcu_qp {
    volatile LONG64 users;
};

struct thread_qp {
    struct rcu_qp *qp;
    unsigned int depth;
    CRYPTO_RCU_LOCK *lock;
};

#define MAX_QPS 10
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
    struct rcu_cb_item *cb_items;
    uint32_t id_ctr;
    struct rcu_qp *qp_group;
    size_t group_count;
    uint32_t next_to_retire;
    volatile long int reader_idx;
    uint32_t current_alloc_idx;
    uint32_t writers_alloced;
    CRYPTO_MUTEX *write_lock;
    CRYPTO_MUTEX *alloc_lock;
    CRYPTO_CONDVAR *alloc_signal;
    CRYPTO_MUTEX *prior_lock;
    CRYPTO_CONDVAR *prior_signal;
};

/*
 * Called on thread exit to free the pthread key
 * associated with this thread, if any
 */
static void free_rcu_thr_data(void *ptr)
{
    struct rcu_thr_data *data =
                        (struct rcu_thr_data *)CRYPTO_THREAD_get_local(&rcu_thr_key);

    OPENSSL_free(data);
    CRYPTO_THREAD_set_local(&rcu_thr_key, NULL);
}


static void ossl_rcu_init(void)
{
    CRYPTO_THREAD_init_local(&rcu_thr_key, NULL);
    ossl_init_thread_start(NULL, NULL, free_rcu_thr_data);
}

static struct rcu_qp *allocate_new_qp_group(struct rcu_lock_st *lock,
                                            int count)
{
    struct rcu_qp *new =
        OPENSSL_zalloc(sizeof(*new) * count);

    lock->group_count = count;
    return new;
}

static CRYPTO_ONCE rcu_init_once = CRYPTO_ONCE_STATIC_INIT;

CRYPTO_RCU_LOCK *ossl_rcu_lock_new(int num_writers)
{
    struct rcu_lock_st *new;

    if (!CRYPTO_THREAD_run_once(&rcu_init_once, ossl_rcu_init))
        return NULL;

    if (num_writers < 1)
        num_writers = 1;

    new = OPENSSL_zalloc(sizeof(*new));

    if (new == NULL)
        return NULL;

    new->write_lock = ossl_crypto_mutex_new();
    new->alloc_signal = ossl_crypto_condvar_new();
    new->prior_signal = ossl_crypto_condvar_new();
    new->alloc_lock = ossl_crypto_mutex_new();
    new->prior_lock = ossl_crypto_mutex_new();
    new->write_lock = ossl_crypto_mutex_new();
    new->qp_group = allocate_new_qp_group(new, num_writers + 1);
    if (new->qp_group == NULL
        || new->alloc_signal == NULL
        || new->prior_signal == NULL
        || new->write_lock == NULL
        || new->alloc_lock == NULL
        || new->prior_lock == NULL) {
        OPENSSL_free(new->qp_group);
        ossl_crypto_condvar_free(&new->alloc_signal);
        ossl_crypto_condvar_free(&new->prior_signal);
        ossl_crypto_mutex_free(&new->alloc_lock);
        ossl_crypto_mutex_free(&new->prior_lock);
        ossl_crypto_mutex_free(&new->write_lock);
        OPENSSL_free(new);
        new = NULL;
    }
    return new;

}

void ossl_rcu_lock_free(CRYPTO_RCU_LOCK *lock)
{
    OPENSSL_free(lock->qp_group);
    ossl_crypto_condvar_free(&lock->alloc_signal);
    ossl_crypto_condvar_free(&lock->prior_signal);
    ossl_crypto_mutex_free(&lock->alloc_lock);
    ossl_crypto_mutex_free(&lock->prior_lock);
    ossl_crypto_mutex_free(&lock->write_lock);
    OPENSSL_free(lock);
}

static inline struct rcu_qp *get_hold_current_qp(CRYPTO_RCU_LOCK *lock)
{
    uint32_t qp_idx;

    /* get the current qp index */
    for (;;) {
        qp_idx = InterlockedOr(&lock->reader_idx, 0);
        InterlockedAdd64(&lock->qp_group[qp_idx].users, VAL_READER);
        if (qp_idx == InterlockedOr(&lock->reader_idx, 0))
            break;
        InterlockedAdd64(&lock->qp_group[qp_idx].users, -VAL_READER);
    }

    return &lock->qp_group[qp_idx];
}

void ossl_rcu_read_lock(CRYPTO_RCU_LOCK *lock)
{
    struct rcu_thr_data *data;
    int i;
    int available_qp = -1;

    /*
     * we're going to access current_qp here so ask the
     * processor to fetch it
     */
    data = CRYPTO_THREAD_get_local(&rcu_thr_key);

    if (data == NULL) {
        data = OPENSSL_zalloc(sizeof(*data));
        OPENSSL_assert(data != NULL);
        CRYPTO_THREAD_set_local(&rcu_thr_key, data);
    }

    for (i = 0; i < MAX_QPS; i++) {
        if (data->thread_qps[i].qp == NULL && available_qp == -1)
            available_qp = i;
        /* If we have a hold on this lock already, we're good */
        if (data->thread_qps[i].lock == lock)
            return;
    }

    /*
     * if we get here, then we don't have a hold on this lock yet
     */
    assert(available_qp != -1);

    data->thread_qps[available_qp].qp = get_hold_current_qp(lock);
    data->thread_qps[available_qp].depth = 1;
    data->thread_qps[available_qp].lock = lock;
}

void ossl_rcu_write_lock(CRYPTO_RCU_LOCK *lock)
{
    ossl_crypto_mutex_lock(lock->write_lock);
}

void ossl_rcu_write_unlock(CRYPTO_RCU_LOCK *lock)
{
    ossl_crypto_mutex_unlock(lock->write_lock);
}

void ossl_rcu_read_unlock(CRYPTO_RCU_LOCK *lock)
{
    struct rcu_thr_data *data = CRYPTO_THREAD_get_local(&rcu_thr_key);
    int i;
    LONG64 ret;

    assert(data != NULL);

    for (i = 0; i < MAX_QPS; i++) {
        if (data->thread_qps[i].lock == lock) {
            data->thread_qps[i].depth--;
            if (data->thread_qps[i].depth == 0) {
                ret = InterlockedAdd64(&data->thread_qps[i].qp->users, -VAL_READER);
                OPENSSL_assert(ret >= 0);
                data->thread_qps[i].qp = NULL;
                data->thread_qps[i].lock = NULL;
            }
            return;
        }
    }
}

static struct rcu_qp *update_qp(CRYPTO_RCU_LOCK *lock)
{
    uint64_t new_id;
    uint32_t current_idx;
    uint32_t tmp;

    ossl_crypto_mutex_lock(lock->alloc_lock);
    /*
     * we need at least one qp to be available with one
     * left over, so that readers can start working on
     * one that isn't yet being waited on
     */
    while (lock->group_count - lock->writers_alloced < 2)
        ossl_crypto_condvar_wait(lock->alloc_signal, lock->alloc_lock);

    current_idx = lock->current_alloc_idx;
    /* Allocate the qp */
    lock->writers_alloced++;

    /* increment the allocation index */
    lock->current_alloc_idx =
        (lock->current_alloc_idx + 1) % lock->group_count;

    /* get and insert a new id */
    new_id = lock->id_ctr;
    lock->id_ctr++;

    new_id = VAL_ID(new_id);
    InterlockedAnd64(&lock->qp_group[current_idx].users, ID_MASK);
    InterlockedAdd64(&lock->qp_group[current_idx].users, new_id);

    /* update the reader index to be the prior qp */
    tmp = lock->current_alloc_idx;
    InterlockedExchange(&lock->reader_idx, tmp);

    /* wake up any waiters */
    ossl_crypto_condvar_broadcast(lock->alloc_signal);
    ossl_crypto_mutex_unlock(lock->alloc_lock);
    return &lock->qp_group[current_idx];
}

static void retire_qp(CRYPTO_RCU_LOCK *lock,
                      struct rcu_qp *qp)
{
    ossl_crypto_mutex_lock(lock->alloc_lock);
    lock->writers_alloced--;
    ossl_crypto_condvar_broadcast(lock->alloc_signal);
    ossl_crypto_mutex_unlock(lock->alloc_lock);
}


void ossl_synchronize_rcu(CRYPTO_RCU_LOCK *lock)
{
    struct rcu_qp *qp;
    uint64_t count;
    struct rcu_cb_item *cb_items, *tmpcb;

    /* before we do anything else, lets grab the cb list */
    cb_items = InterlockedExchangePointer((void * volatile *)&lock->cb_items, NULL);

    qp = update_qp(lock);

    /* wait for the reader count to reach zero */
    do {
        count = InterlockedOr64(&qp->users, 0);
    } while (READER_COUNT(count) != 0);

    /* retire in order */
    ossl_crypto_mutex_lock(lock->prior_lock);
    while (lock->next_to_retire != ID_VAL(count))
        ossl_crypto_condvar_wait(lock->prior_signal, lock->prior_lock);

    lock->next_to_retire++;
    ossl_crypto_condvar_broadcast(lock->prior_signal);
    ossl_crypto_mutex_unlock(lock->prior_lock);

    retire_qp(lock, qp);

    /* handle any callbacks that we have */
    while (cb_items != NULL) {
        tmpcb = cb_items;
        cb_items = cb_items->next;
        tmpcb->fn(tmpcb->data);
        OPENSSL_free(tmpcb);
    }

    /* and we're done */
    return;

}

int ossl_rcu_call(CRYPTO_RCU_LOCK *lock, rcu_cb_fn cb, void *data)
{
    struct rcu_cb_item *new;
    struct rcu_cb_item *prev;

    new = OPENSSL_zalloc(sizeof(struct rcu_cb_item));
    if (new == NULL)
        return 0;
    prev = new;
    new->data = data;
    new->fn = cb;

    InterlockedExchangePointer((void * volatile *)&lock->cb_items, prev);
    new->next = prev;
    return 1;
}

void *ossl_rcu_uptr_deref(void **p)
{
    return (void *)*p;
}

void ossl_rcu_assign_uptr(void **p, void **v)
{
    InterlockedExchangePointer((void * volatile *)p, (void *)*v);
}


CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void)
{
    CRYPTO_RWLOCK *lock;
# ifdef USE_RWLOCK
    CRYPTO_win_rwlock *rwlock;

    if ((lock = OPENSSL_zalloc(sizeof(CRYPTO_win_rwlock))) == NULL)
        /* Don't set error, to avoid recursion blowup. */
        return NULL;
    rwlock = lock;
    InitializeSRWLock(&rwlock->lock);
# else

    if ((lock = OPENSSL_zalloc(sizeof(CRITICAL_SECTION))) == NULL)
        /* Don't set error, to avoid recursion blowup. */
        return NULL;

#  if !defined(_WIN32_WCE)
    /* 0x400 is the spin count value suggested in the documentation */
    if (!InitializeCriticalSectionAndSpinCount(lock, 0x400)) {
        OPENSSL_free(lock);
        return NULL;
    }
#  else
    InitializeCriticalSection(lock);
#  endif
# endif

    return lock;
}

__owur int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock)
{
# ifdef USE_RWLOCK
    CRYPTO_win_rwlock *rwlock = lock;

    AcquireSRWLockShared(&rwlock->lock);
# else
    EnterCriticalSection(lock);
# endif
    return 1;
}

__owur int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock)
{
# ifdef USE_RWLOCK
    CRYPTO_win_rwlock *rwlock = lock;

    AcquireSRWLockExclusive(&rwlock->lock);
    rwlock->exclusive = 1;
# else
    EnterCriticalSection(lock);
# endif
    return 1;
}

int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock)
{
# ifdef USE_RWLOCK
    CRYPTO_win_rwlock *rwlock = lock;

    if (rwlock->exclusive) {
        rwlock->exclusive = 0;
        ReleaseSRWLockExclusive(&rwlock->lock);
    } else {
        ReleaseSRWLockShared(&rwlock->lock);
    }
# else
    LeaveCriticalSection(lock);
# endif
    return 1;
}

void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock)
{
    if (lock == NULL)
        return;

# ifndef USE_RWLOCK
    DeleteCriticalSection(lock);
# endif
    OPENSSL_free(lock);

    return;
}

# define ONCE_UNINITED     0
# define ONCE_ININIT       1
# define ONCE_DONE         2

/*
 * We don't use InitOnceExecuteOnce because that isn't available in WinXP which
 * we still have to support.
 */
int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void))
{
    LONG volatile *lock = (LONG *)once;
    LONG result;

    if (*lock == ONCE_DONE)
        return 1;

    do {
        result = InterlockedCompareExchange(lock, ONCE_ININIT, ONCE_UNINITED);
        if (result == ONCE_UNINITED) {
            init();
            *lock = ONCE_DONE;
            return 1;
        }
    } while (result == ONCE_ININIT);

    return (*lock == ONCE_DONE);
}

int CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *))
{
    *key = TlsAlloc();
    if (*key == TLS_OUT_OF_INDEXES)
        return 0;

    return 1;
}

void *CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL *key)
{
    DWORD last_error;
    void *ret;

    /*
     * TlsGetValue clears the last error even on success, so that callers may
     * distinguish it successfully returning NULL or failing. It is documented
     * to never fail if the argument is a valid index from TlsAlloc, so we do
     * not need to handle this.
     *
     * However, this error-mangling behavior interferes with the caller's use of
     * GetLastError. In particular SSL_get_error queries the error queue to
     * determine whether the caller should look at the OS's errors. To avoid
     * destroying state, save and restore the Windows error.
     *
     * https://msdn.microsoft.com/en-us/library/windows/desktop/ms686812(v=vs.85).aspx
     */
    last_error = GetLastError();
    ret = TlsGetValue(*key);
    SetLastError(last_error);
    return ret;
}

int CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL *key, void *val)
{
    if (TlsSetValue(*key, val) == 0)
        return 0;

    return 1;
}

int CRYPTO_THREAD_cleanup_local(CRYPTO_THREAD_LOCAL *key)
{
    if (TlsFree(*key) == 0)
        return 0;

    return 1;
}

CRYPTO_THREAD_ID CRYPTO_THREAD_get_current_id(void)
{
    return GetCurrentThreadId();
}

int CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b)
{
    return (a == b);
}

int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock)
{
    *ret = (int)InterlockedExchangeAdd((long volatile *)val, (long)amount) + amount;
    return 1;
}

int CRYPTO_atomic_or(uint64_t *val, uint64_t op, uint64_t *ret,
                     CRYPTO_RWLOCK *lock)
{
#if (defined(NO_INTERLOCKEDOR64))
    if (lock == NULL || !CRYPTO_THREAD_write_lock(lock))
        return 0;
    *val |= op;
    *ret = *val;

    if (!CRYPTO_THREAD_unlock(lock))
        return 0;

    return 1;
#else
    *ret = (uint64_t)InterlockedOr64((LONG64 volatile *)val, (LONG64)op) | op;
    return 1;
#endif
}

int CRYPTO_atomic_load(uint64_t *val, uint64_t *ret, CRYPTO_RWLOCK *lock)
{
#if (defined(NO_INTERLOCKEDOR64))
    if (lock == NULL || !CRYPTO_THREAD_read_lock(lock))
        return 0;
    *ret = *val;
    if (!CRYPTO_THREAD_unlock(lock))
        return 0;

    return 1;
#else
    *ret = (uint64_t)InterlockedOr64((LONG64 volatile *)val, 0);
    return 1;
#endif
}

int CRYPTO_atomic_load_int(int *val, int *ret, CRYPTO_RWLOCK *lock)
{
#if (defined(NO_INTERLOCKEDOR64))
    if (lock == NULL || !CRYPTO_THREAD_read_lock(lock))
        return 0;
    *ret = *val;
    if (!CRYPTO_THREAD_unlock(lock))
        return 0;

    return 1;
#else
    /* On Windows, LONG is always the same size as int. */
    *ret = (int)InterlockedOr((LONG volatile *)val, 0);
    return 1;
#endif
}

int openssl_init_fork_handlers(void)
{
    return 0;
}

int openssl_get_fork_id(void)
{
    return 0;
}
#endif
