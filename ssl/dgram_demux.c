/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/e_os.h"
#include "internal/dgram_demux.h"
#include "internal/thread_arch.h"
#include "internal/common.h"
#include <openssl/err.h>
#include <string.h>

#if !defined(OPENSSL_NO_QUIC) || !defined(OPENSSL_NO_DTLS)

/* URXE_DEMUX_STATE_* are defined in dgram_demux.h */

#define DEMUX_DEFAULT_MTU 1500
#define DEMUX_MIN_INITIAL_DGRAM_LEN 1200

struct dgram_demux_st {
    /*
     * The underlying transport BIO with datagram semantics. Protected by
     * recv_mutex, as are the three fields that follow it.
     */
    BIO *net_bio;

    /*
     * Our current understanding of the upper bound on an incoming datagram size
     * in bytes.
     */
    size_t mtu;

    /* The datagram_id to use for the next datagram we receive. */
    uint64_t next_datagram_id;

    /* Whether to use local address support. */
    char use_local_addr;

    /* Time retrieval callback. */
    OSSL_TIME (*now)(void *arg);
    void *now_arg;

    /* The default packet handler, if any. */
    ossl_dgram_demux_cb_fn *default_cb;
    ossl_dgram_demux_route_fn *route_cb;
    void *default_cb_arg;

    /*
     * The receive reserve: the URXEs the next network read receives into, at
     * most one batch of them. A read moves the ones it filled to the pending
     * list, or straight to the batch being dispatched, and the next read tops
     * the reserve up again from the free list. Only the receive path touches
     * it, so a URXE is returned to the free list without waiting for a read
     * in progress. Protected by recv_mutex.
     */
    DGRAM_URXE_LIST urx_rx;

    /*
     * List of URXEs which are filled with received encrypted data. These are
     * removed from this list as we invoke the callbacks for each of them. They
     * are then not on any list managed by us; we forget about them until our
     * user calls ossl_dgram_demux_release_urxe to return the URXE to us, at
     * which point we add it to the free list. Protected by recv_mutex.
     */
    DGRAM_URXE_LIST urx_pending;

    /* Whether internal locking is required */
    char require_mutex;

    /* Maximum URXEs cached on the free list; 0 means unbounded. */
    size_t max_free_urxe;

    /*
     * Used only if require_mutex is set.
     *
     * recv_mutex serialises the receive path: the network read itself, which
     * a BIO need not support from two threads at once, and the state it works
     * on. It is held across the read, a system call, and never while a
     * handler is called.
     *
     * Returning a URXE takes no lock, so it never waits for a network read,
     * whoever is making one. free_lock is only what CRYPTO_atomic_*() fall
     * back to on a platform that has no atomic operations.
     */
    CRYPTO_MUTEX *recv_mutex;
    CRYPTO_RWLOCK *free_lock;

    /*
     * The free list: URXEs which are not currently in use (i.e., not filled
     * with unconsumed data), the ones our user has returned to us. They
     * refill the receive reserve.
     *
     * It is a stack, linked through the next pointer of the URXE's list
     * member, and it has no lock. Any thread pushes, with a compare-and-swap
     * of urx_free. Only the receive path takes URXEs off it, under
     * recv_mutex, so there is one taker at a time: a URXE it has seen on the
     * stack stays there, on top of the same URXEs, until the taker removes it
     * itself. A compare-and-swap that finds the head unchanged has therefore
     * missed nothing (no ABA problem).
     *
     * num_free counts the URXEs on the stack and those about to be pushed. A
     * thread adds to it before it pushes, and does not push what would take
     * it past max_free_urxe, so the limit holds at any moment.
     */
    void *urx_free;
    int num_free;
};

static ossl_inline void demux_lock_recv(DGRAM_DEMUX *demux)
{
    if (demux->require_mutex)
        ossl_crypto_mutex_lock(demux->recv_mutex);
}

static ossl_inline void demux_unlock_recv(DGRAM_DEMUX *demux)
{
    if (demux->require_mutex)
        ossl_crypto_mutex_unlock(demux->recv_mutex);
}

/*
 * Replace the head of the free list with |head| if it is still |*expect|.
 * Returns 1 if it was replaced and 0, with the current head in |*expect|, if
 * it was not; -1 if CRYPTO_atomic_cmp_exch_ptr() could not take its lock.
 */
static ossl_inline int demux_free_swap_head(DGRAM_DEMUX *demux, void **expect,
    void *head)
{
    int lock_failed;

    if (!demux->require_mutex) {
        if (demux->urx_free != *expect) {
            *expect = demux->urx_free;
            return 0;
        }
        demux->urx_free = head;
        return 1;
    }

    if (CRYPTO_atomic_cmp_exch_ptr(&demux->urx_free, expect, head,
            demux->free_lock, &lock_failed))
        return 1;

    return lock_failed ? -1 : 0;
}

/* Add |n| to the count of free URXEs. Returns 0 on failure to take a lock. */
static ossl_inline int demux_free_count(DGRAM_DEMUX *demux, int n, int *num)
{
    if (demux->require_mutex)
        return CRYPTO_atomic_add(&demux->num_free, n, num, demux->free_lock);

    *num = demux->num_free += n;
    return 1;
}

/* List management helpers */
void ossl_dgram_urxe_remove(DGRAM_URXE_LIST *l, DGRAM_URXE *e)
{
    ossl_list_urxe_remove(l, e);
}

void ossl_dgram_urxe_insert_head(DGRAM_URXE_LIST *l, DGRAM_URXE *e)
{
    ossl_list_urxe_insert_head(l, e);
}

void ossl_dgram_urxe_insert_tail(DGRAM_URXE_LIST *l, DGRAM_URXE *e)
{
    ossl_list_urxe_insert_tail(l, e);
}

DGRAM_DEMUX *ossl_dgram_demux_new(BIO *net_bio,
    int threadsafe,
    OSSL_TIME (*now)(void *arg),
    void *now_arg)
{
    DGRAM_DEMUX *demux;

    demux = OPENSSL_zalloc(sizeof(DGRAM_DEMUX));
    if (demux == NULL)
        return NULL;

    if (threadsafe) {
        demux->require_mutex = 1;
        demux->recv_mutex = ossl_crypto_mutex_new();
        demux->free_lock = CRYPTO_THREAD_lock_new();
#ifdef OPENSSL_THREADS
        if (demux->recv_mutex == NULL)
            goto err;
#endif
        if (demux->free_lock == NULL)
            goto err;
    }

    /* We update this if possible when we get a BIO. */
    demux->mtu = DEMUX_DEFAULT_MTU;
    demux->now = now;
    demux->now_arg = now_arg;

    ossl_dgram_demux_set_bio(demux, net_bio);

    return demux;

err:
    ERR_raise(ERR_LIB_SSL, ERR_R_CRYPTO_LIB);
    ossl_crypto_mutex_free(&demux->recv_mutex);
    CRYPTO_THREAD_lock_free(demux->free_lock);
    OPENSSL_free(demux);
    return NULL;
}

static void dgram_demux_free_urxl(DGRAM_URXE_LIST *l)
{
    DGRAM_URXE *e, *enext;

    for (e = ossl_list_urxe_head(l); e != NULL; e = enext) {
        enext = ossl_list_urxe_next(e);
        ossl_list_urxe_remove(l, e);
        OPENSSL_free(e);
    }
}

void ossl_dgram_demux_free(DGRAM_DEMUX *demux)
{
    DGRAM_URXE *e, *enext;

    if (demux == NULL)
        return;

    /* Free all URXEs we are holding. */
    for (e = demux->urx_free; e != NULL; e = enext) {
        enext = e->ossl_list_urxe.next;
        OPENSSL_free(e);
    }
    dgram_demux_free_urxl(&demux->urx_rx);
    dgram_demux_free_urxl(&demux->urx_pending);

    if (demux->require_mutex) {
        ossl_crypto_mutex_free(&demux->recv_mutex);
        CRYPTO_THREAD_lock_free(demux->free_lock);
    }

    OPENSSL_free(demux);
}

void ossl_dgram_demux_set_bio(DGRAM_DEMUX *demux, BIO *net_bio)
{
    unsigned int mtu = 0;
    int use_local_addr = 0;

    if (net_bio != NULL) {
        /*
         * Try to determine our MTU if possible. The BIO is not required to
         * support this, in which case we remain at the last known MTU, or our
         * initial default.
         */
        mtu = BIO_dgram_get_mtu(net_bio);

        use_local_addr = BIO_dgram_get_local_addr_cap(net_bio)
            && BIO_dgram_set_local_addr_enable(net_bio, 1);
    }

    /* The receive path reads all three under its lock. */
    demux_lock_recv(demux);
    demux->net_bio = net_bio;
    if (mtu >= DEMUX_MIN_INITIAL_DGRAM_LEN)
        demux->mtu = mtu;
    if (use_local_addr)
        demux->use_local_addr = 1;
    demux_unlock_recv(demux);
}

int ossl_dgram_demux_set_mtu(DGRAM_DEMUX *demux, unsigned int mtu)
{
    if (mtu < DEMUX_MIN_INITIAL_DGRAM_LEN)
        return 0;

    /* mtu is read under recv_mutex by the receive path. */
    demux_lock_recv(demux);
    demux->mtu = mtu;
    demux_unlock_recv(demux);
    return 1;
}

void ossl_dgram_demux_set_max_free_urxe(DGRAM_DEMUX *demux, size_t max_free)
{
    /* Read without a lock by whoever returns a URXE: set it before sharing. */
    demux->max_free_urxe = max_free;
}

size_t ossl_dgram_demux_get_free_list_len(DGRAM_DEMUX *demux)
{
    int n;

    if (!demux->require_mutex)
        return (size_t)demux->num_free;

    if (!CRYPTO_atomic_load_int(&demux->num_free, &n, demux->free_lock))
        return 0;

    /* A thread at the limit counts its URXE in before it counts it out. */
    if (demux->max_free_urxe != 0 && (size_t)n > demux->max_free_urxe)
        return demux->max_free_urxe;

    return (size_t)n;
}

void ossl_dgram_demux_set_default_handler(DGRAM_DEMUX *demux,
    ossl_dgram_demux_cb_fn *cb,
    void *cb_arg)
{
    demux->default_cb = cb;
    demux->route_cb = NULL;
    demux->default_cb_arg = cb_arg;
}

void ossl_dgram_demux_set_route_handler(DGRAM_DEMUX *demux,
    ossl_dgram_demux_route_fn *cb,
    void *cb_arg)
{
    demux->default_cb = NULL;
    demux->route_cb = cb;
    demux->default_cb_arg = cb_arg;
}

/*
 * Take back |num| URXEs that are on no list, chained from |first| to |last|
 * through their next pointers: cache them on the free list, or free those
 * that would take it past its limit. Takes no lock, and pushes the whole
 * chain with one compare-and-swap.
 */
static void dgram_demux_return_urxes(DGRAM_DEMUX *demux, DGRAM_URXE *first,
    DGRAM_URXE *last, int num)
{
    DGRAM_URXE *e;
    void *head;
    int total, ret, excess = num;

    /* Count them in first: what is counted has room on the list. */
    if (demux_free_count(demux, num, &total)) {
        excess = 0;
        if (demux->max_free_urxe != 0
            && (size_t)total > demux->max_free_urxe) {
            excess = (int)((size_t)total - demux->max_free_urxe);
            if (excess > num)
                excess = num;
            (void)demux_free_count(demux, -excess, &total);
        }
    }

    for (; excess > 0; excess--, num--) {
        e = first;
        first = e->ossl_list_urxe.next;
        OPENSSL_free(e);
    }

    if (num == 0)
        return;

    /* The head is only compared, never followed, so a plain load will do. */
    if (!demux->require_mutex)
        head = demux->urx_free;
    else if (!CRYPTO_atomic_load_ptr(&demux->urx_free, &head,
                 demux->free_lock))
        goto err;

    do {
        last->ossl_list_urxe.next = head;
    } while ((ret = demux_free_swap_head(demux, &head, first)) == 0);

    if (ret > 0)
        return;

err:
    /* No lock to be had where there are no atomics: do not cache them. */
    (void)demux_free_count(demux, -num, &total);
    last->ossl_list_urxe.next = NULL;
    for (; first != NULL; first = e) {
        e = first->ossl_list_urxe.next;
        OPENSSL_free(first);
    }
}

/* Take back a single URXE that is on no list. */
static void dgram_demux_return_urxe(DGRAM_DEMUX *demux, DGRAM_URXE *e)
{
    e->demux_state = URXE_DEMUX_STATE_FREE;
    dgram_demux_return_urxes(demux, e, e, 1);
}

/*
 * Move up to |num| URXEs from the free list to the tail of the receive
 * reserve and return how many there were. Caller holds recv_mutex, which
 * makes it the only taker.
 */
static size_t dgram_demux_take_free(DGRAM_DEMUX *demux, size_t num)
{
    DGRAM_URXE *e, *enext, *last;
    void *head = NULL, *rest = NULL;
    size_t n = 0, i;
    int ret, total;

    /*
     * The first swap succeeds on an empty stack, replacing nothing with
     * nothing, and fails on any other, which tells us its head. A later one
     * detaches the URXEs walked from that head, unless a thread has pushed
     * more on top meanwhile; then the walk starts again from the new head.
     * The walk reads URXEs that only the taker removes and nobody writes to.
     */
    while ((ret = demux_free_swap_head(demux, &head, rest)) == 0) {
        last = head;
        for (n = 1; n < num && last->ossl_list_urxe.next != NULL; n++)
            last = last->ossl_list_urxe.next;
        rest = last->ossl_list_urxe.next;
    }

    if (ret < 0 || n == 0)
        return 0;

    (void)demux_free_count(demux, -(int)n, &total);
    for (i = 0, e = head; i < n; i++, e = enext) {
        enext = e->ossl_list_urxe.next;
        ossl_list_urxe_insert_tail(&demux->urx_rx, e);
    }

    return n;
}

/*
 * Hand an issued URXE, which is on no list, to the handler. Returns 1 if the
 * handler took it, 0 if it is still the demux's to return to the free list:
 * a route handler declined it, or there is no handler. Called without either
 * lock: a handler takes one if it releases or reinjects a URXE.
 */
static int dgram_demux_dispatch_urxe(DGRAM_DEMUX *demux, DGRAM_URXE *e)
{
    if (demux->route_cb != NULL)
        return demux->route_cb(e, demux->default_cb_arg);

    if (demux->default_cb != NULL) {
        demux->default_cb(e, demux->default_cb_arg);
        return 1;
    }

    return 0;
}

static DGRAM_URXE *dgram_demux_alloc_urxe(size_t alloc_len)
{
    DGRAM_URXE *e;

    if (alloc_len >= SIZE_MAX - sizeof(DGRAM_URXE))
        return NULL;

    e = OPENSSL_zalloc(sizeof(DGRAM_URXE) + alloc_len);
    if (e == NULL)
        return NULL;

    ossl_list_urxe_init_elem(e);
    e->alloc_len = alloc_len;
    e->data_len = 0;
    return e;
}

/* Resize a URXE of the receive reserve in place. Caller holds recv_mutex. */
static DGRAM_URXE *dgram_demux_resize_urxe(DGRAM_DEMUX *demux, DGRAM_URXE *e,
    size_t new_alloc_len)
{
    DGRAM_URXE *e2, *prev;

    if (!ossl_assert(e->demux_state == URXE_DEMUX_STATE_FREE))
        /* Never attempt to resize a URXE which the demux does not hold. */
        return NULL;

    prev = ossl_list_urxe_prev(e);
    ossl_list_urxe_remove(&demux->urx_rx, e);

    if (new_alloc_len >= SIZE_MAX - sizeof(DGRAM_URXE))
        goto rollback;

    e2 = OPENSSL_realloc(e, sizeof(DGRAM_URXE) + new_alloc_len);

    /* Failed to resize, abort. */
    if (e2 == NULL)
        goto rollback;

    if (prev == NULL)
        ossl_list_urxe_insert_head(&demux->urx_rx, e2);
    else
        ossl_list_urxe_insert_after(&demux->urx_rx, prev, e2);

    e2->alloc_len = new_alloc_len;
    return e2;

rollback:
    /* Reinsert e back into the list on failures */
    if (prev == NULL)
        ossl_list_urxe_insert_head(&demux->urx_rx, e);
    else
        ossl_list_urxe_insert_after(&demux->urx_rx, prev, e);

    return NULL;
}

static DGRAM_URXE *dgram_demux_reserve_urxe(DGRAM_DEMUX *demux, DGRAM_URXE *e,
    size_t alloc_len)
{
    return e->alloc_len < alloc_len
        ? dgram_demux_resize_urxe(demux, e, alloc_len)
        : e;
}

/*
 * Top the receive reserve up to |num| URXEs: from the free list as far as it
 * goes, then by allocating. A reserve that is full already, as it is after a
 * read that received nothing, does not touch the free list at all. Caller
 * holds recv_mutex.
 */
static int dgram_demux_refill_rx(DGRAM_DEMUX *demux, size_t num)
{
    DGRAM_URXE *e;
    size_t have = ossl_list_urxe_num(&demux->urx_rx);

    if (have >= num)
        return 1;

    have += dgram_demux_take_free(demux, num - have);

    /* Allocate the rest. */
    for (; have < num; have++) {
        e = dgram_demux_alloc_urxe(demux->mtu);
        if (e == NULL)
            return 0;

        ossl_list_urxe_insert_tail(&demux->urx_rx, e);
        e->demux_state = URXE_DEMUX_STATE_FREE;
    }

    return 1;
}

/*
 * Receive datagrams from network, placing them into URXEs of the receive
 * reserve. The ones received are moved to the tail of |out| in |state|:
 * the pending list, or the caller's own batch of issued URXEs.
 *
 * Returns DGRAM_DEMUX_PUMP_RES_* value.
 *
 * Precondition: the receive reserve holds at least one URXE
 * Precondition: there are no pending URXEs
 * Precondition: Caller holds recv_mutex
 */
static int dgram_demux_recv(DGRAM_DEMUX *demux, DGRAM_URXE_LIST *out,
    char state)
{
    BIO_MSG msg[DEMUX_MAX_MSGS_PER_CALL];
    size_t rd, i;
    DGRAM_URXE *urxe = ossl_list_urxe_head(&demux->urx_rx), *unext;
    OSSL_TIME now;

    /* This should never be called when we have any pending URXE. */
    assert(ossl_list_urxe_head(&demux->urx_pending) == NULL);
    assert(urxe->demux_state == URXE_DEMUX_STATE_FREE);

    if (demux->net_bio == NULL)
        /*
         * If no BIO is plugged in, treat this as no datagram being available.
         */
        return DGRAM_DEMUX_PUMP_RES_TRANSIENT_FAIL;

    /*
     * Opportunistically receive as many messages as possible in a single
     * syscall, determined by how many URXEs the reserve holds.
     */
    for (i = 0; i < (ossl_ssize_t)OSSL_NELEM(msg);
        ++i, urxe = ossl_list_urxe_next(urxe)) {
        if (urxe == NULL) {
            /* We need at least one URXE to receive into. */
            if (!ossl_assert(i > 0))
                return DGRAM_DEMUX_PUMP_RES_PERMANENT_FAIL;

            break;
        }

        /* Ensure the URXE is big enough. */
        urxe = dgram_demux_reserve_urxe(demux, urxe, demux->mtu);
        if (urxe == NULL)
            /* Allocation error, fail. */
            return DGRAM_DEMUX_PUMP_RES_PERMANENT_FAIL;

        /* Ensure we zero any fields added to BIO_MSG at a later date. */
        memset(&msg[i], 0, sizeof(BIO_MSG));
        msg[i].data = ossl_dgram_urxe_data(urxe);
        msg[i].data_len = urxe->alloc_len;
        msg[i].peer = &urxe->peer;
        BIO_ADDR_clear(&urxe->peer);
        if (demux->use_local_addr)
            msg[i].local = &urxe->local;
        else
            BIO_ADDR_clear(&urxe->local);
    }

    ERR_set_mark();
    if (!BIO_recvmmsg(demux->net_bio, msg, sizeof(BIO_MSG), i, 0, &rd)) {
        if (BIO_err_is_non_fatal(ERR_peek_last_error())) {
            /* Transient error, clear the error and stop. */
            ERR_pop_to_mark();
            return DGRAM_DEMUX_PUMP_RES_TRANSIENT_FAIL;
        } else {
            /* Non-transient error, do not clear the error. */
            ERR_clear_last_mark();
            return DGRAM_DEMUX_PUMP_RES_PERMANENT_FAIL;
        }
    }

    ERR_clear_last_mark();
    now = demux->now != NULL ? demux->now(demux->now_arg) : ossl_time_zero();

    urxe = ossl_list_urxe_head(&demux->urx_rx);
    for (i = 0; i < rd; ++i, urxe = unext) {
        unext = ossl_list_urxe_next(urxe);
        /* Set URXE with actual length of received datagram. */
        urxe->data_len = msg[i].data_len;
        /* Time we received datagram. */
        urxe->time = now;
        urxe->datagram_id = demux->next_datagram_id++;
        /* Move from the reserve to the caller's list. */
        ossl_list_urxe_remove(&demux->urx_rx, urxe);
        ossl_list_urxe_insert_tail(out, urxe);
        urxe->demux_state = state;
    }

    return DGRAM_DEMUX_PUMP_RES_OK;
}

/*
 * Process a single pending URXE.
 * Returning 1 on success, 0 on failure.
 *
 * Precondition: Caller holds recv_mutex
 * Note: Lock is released before callback and reacquired after.
 */
static int dgram_demux_process_pending_urxe(DGRAM_DEMUX *demux, DGRAM_URXE *e)
{

    /* The next URXE we process should be at the head of the pending list. */
    if (!ossl_assert(e == ossl_list_urxe_head(&demux->urx_pending)))
        return 0;

    assert(e->demux_state == URXE_DEMUX_STATE_PENDING);

    ossl_list_urxe_remove(&demux->urx_pending, e);
    e->demux_state = URXE_DEMUX_STATE_ISSUED;

    /*
     * Pass to the handler for routing. Release the lock around it to avoid a
     * deadlock if it calls release_urxe or reinject_urxe.
     */
    demux_unlock_recv(demux);
    /* Not taken: back to the free list. */
    if (!dgram_demux_dispatch_urxe(demux, e))
        dgram_demux_return_urxe(demux, e);
    demux_lock_recv(demux);

    return 1; /* keep processing pending URXEs */
}

/*
 * Process pending URXEs to generate callbacks.
 * Precondition: Caller holds recv_mutex
 */
static int dgram_demux_process_pending_urxl(DGRAM_DEMUX *demux)
{
    DGRAM_URXE *e;
    int ret;

    while ((e = ossl_list_urxe_head(&demux->urx_pending)) != NULL)
        if ((ret = dgram_demux_process_pending_urxe(demux, e)) <= 0)
            return ret;

    return 1;
}

/*
 * Thread-safe pump: receive a batch under recv_mutex, straight into a list of
 * our own, and make its callbacks without the lock, so that other threads
 * read and route the next batch meanwhile instead of taking datagrams of this
 * one one at a time. A thread returning a URXE takes no lock, so it does not
 * wait for the network read either. URXEs the route handler declines are
 * chained up and returned to the free list together, once for the whole
 * batch. A reinjected URXE goes on the shared pending list, for this or
 * another thread's next pump, which takes it in place of a network read.
 */
static int dgram_demux_pump_batch(DGRAM_DEMUX *demux)
{
    DGRAM_URXE_LIST batch;
    DGRAM_URXE *e, *declined = NULL, *declined_last = NULL;
    int ret, num_declined = 0;

    ossl_list_urxe_init(&batch);

    ossl_crypto_mutex_lock(demux->recv_mutex);
    if (ossl_list_urxe_head(&demux->urx_pending) == NULL) {
        if (!dgram_demux_refill_rx(demux, DEMUX_MAX_MSGS_PER_CALL)) {
            ossl_crypto_mutex_unlock(demux->recv_mutex);
            return DGRAM_DEMUX_PUMP_RES_PERMANENT_FAIL;
        }
        ret = dgram_demux_recv(demux, &batch, URXE_DEMUX_STATE_ISSUED);
        if (ret != DGRAM_DEMUX_PUMP_RES_OK) {
            ossl_crypto_mutex_unlock(demux->recv_mutex);
            return ret;
        }
    } else {
        while ((e = ossl_list_urxe_head(&demux->urx_pending)) != NULL) {
            ossl_list_urxe_remove(&demux->urx_pending, e);
            ossl_list_urxe_insert_tail(&batch, e);
            e->demux_state = URXE_DEMUX_STATE_ISSUED;
        }
    }
    ossl_crypto_mutex_unlock(demux->recv_mutex);

    while ((e = ossl_list_urxe_head(&batch)) != NULL) {
        /* The callee gets the URXE on no list. */
        ossl_list_urxe_remove(&batch, e);
        if (dgram_demux_dispatch_urxe(demux, e))
            continue;

        /* Declined: chain it to what the batch returns. */
        e->demux_state = URXE_DEMUX_STATE_FREE;
        e->ossl_list_urxe.next = declined;
        if (declined == NULL)
            declined_last = e;
        declined = e;
        num_declined++;
    }

    if (declined != NULL)
        dgram_demux_return_urxes(demux, declined, declined_last, num_declined);

    return DGRAM_DEMUX_PUMP_RES_OK;
}

/*
 * Drain the pending URXE list, processing any pending URXEs by making their
 * callbacks. If no URXEs are pending, a network read is attempted first.
 */
int ossl_dgram_demux_pump(DGRAM_DEMUX *demux)
{
    int ret;

    if (demux->require_mutex)
        return dgram_demux_pump_batch(demux);

    /* Not thread-safe, so there is no lock to take from here on. */
    if (ossl_list_urxe_head(&demux->urx_pending) == NULL) {
        if (!dgram_demux_refill_rx(demux, DEMUX_MAX_MSGS_PER_CALL))
            return DGRAM_DEMUX_PUMP_RES_PERMANENT_FAIL;

        ret = dgram_demux_recv(demux, &demux->urx_pending,
            URXE_DEMUX_STATE_PENDING);
        if (ret != DGRAM_DEMUX_PUMP_RES_OK)
            return ret;

        /*
         * If dgram_demux_recv returned successfully, we should always have
         * something.
         */
        assert(ossl_list_urxe_head(&demux->urx_pending) != NULL);
    }

    if (dgram_demux_process_pending_urxl(demux) <= 0)
        return DGRAM_DEMUX_PUMP_RES_PERMANENT_FAIL;

    return DGRAM_DEMUX_PUMP_RES_OK;
}

/* Artificially inject a packet into the demuxer for testing purposes. */
int ossl_dgram_demux_inject(DGRAM_DEMUX *demux,
    const unsigned char *buf,
    size_t buf_len,
    const BIO_ADDR *peer,
    const BIO_ADDR *local)
{
    int ret = 0;
    DGRAM_URXE *urxe;

    demux_lock_recv(demux);

    if (!dgram_demux_refill_rx(demux, 1))
        goto end;

    urxe = ossl_list_urxe_head(&demux->urx_rx);

    assert(urxe->demux_state == URXE_DEMUX_STATE_FREE);

    urxe = dgram_demux_reserve_urxe(demux, urxe, buf_len);
    if (urxe == NULL)
        goto end;

    memcpy(ossl_dgram_urxe_data(urxe), buf, buf_len);
    urxe->data_len = buf_len;

    if (peer != NULL)
        BIO_ADDR_copy(&urxe->peer, peer);
    else
        BIO_ADDR_clear(&urxe->peer);

    if (local != NULL)
        BIO_ADDR_copy(&urxe->local, local);
    else
        BIO_ADDR_clear(&urxe->local);

    urxe->time
        = demux->now != NULL ? demux->now(demux->now_arg) : ossl_time_zero();

    /* Move from the receive reserve to the pending list. */
    ossl_list_urxe_remove(&demux->urx_rx, urxe);
    urxe->datagram_id = demux->next_datagram_id++;
    ossl_list_urxe_insert_tail(&demux->urx_pending, urxe);
    urxe->demux_state = URXE_DEMUX_STATE_PENDING;

    ret = dgram_demux_process_pending_urxl(demux) > 0;

end:
    demux_unlock_recv(demux);
    return ret;
}

/*
 * Called by our user to return a URXE to the free list. If the free list
 * is already at its limit the URXE is freed instead of being cached;
 * callers must not reference a URXE after releasing it, so freeing here
 * is safe even inside the routing callback.
 */
void ossl_dgram_demux_release_urxe(DGRAM_DEMUX *demux, DGRAM_URXE *e)
{
    assert(ossl_list_urxe_prev(e) == NULL && ossl_list_urxe_next(e) == NULL);
    assert(e->demux_state == URXE_DEMUX_STATE_ISSUED);

    dgram_demux_return_urxe(demux, e);
}

void ossl_dgram_demux_reinject_urxe(DGRAM_DEMUX *demux, DGRAM_URXE *e)
{
    assert(ossl_list_urxe_prev(e) == NULL && ossl_list_urxe_next(e) == NULL);
    assert(e->demux_state == URXE_DEMUX_STATE_ISSUED);

    demux_lock_recv(demux);
    ossl_list_urxe_insert_head(&demux->urx_pending, e);
    e->demux_state = URXE_DEMUX_STATE_PENDING;
    demux_unlock_recv(demux);
}

int ossl_dgram_demux_has_pending(const DGRAM_DEMUX *demux)
{
    return ossl_list_urxe_head(&demux->urx_pending) != NULL;
}

#endif /* !OPENSSL_NO_QUIC || !OPENSSL_NO_DTLS */
