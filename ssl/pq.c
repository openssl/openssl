/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <assert.h>
#include "internal/pq.h"
#include "internal/safe_math.h"

OSSL_SAFE_MATH_UNSIGNED(pq_size, size_t)

/*
 * Binary min-heap, array-backed.  Each slot in heap[] is a pointer to an
 * OSSL_PQ_NODE embedded in the user's struct; the node tracks its current
 * heap index in node->posn, so arbitrary delete is O(log n) without a
 * parallel handle table.
 *
 *     peek          O(1)
 *     push          O(log n)
 *     pop           O(log n)
 *     remove(node)  O(log n)
 */

struct ossl_pq_st {
    OSSL_PQ_NODE **heap;
    int (*cmp)(const OSSL_PQ_NODE *, const OSSL_PQ_NODE *);
    size_t htop; /* number of elements currently in heap */
    size_t hmax; /* allocated slots in heap[] */
};

#ifndef NDEBUG
/*
 * Basic sanity checking of the data structure.
 *
 *  ASSERT_USED(pq, idx)      -- the node at heap[idx] knows it is at idx.
 *  ASSERT_NODE_USED(pq, n)   -- the user-supplied node n is currently in
 *                               this queue at the position it claims.
 */
#define ASSERT_USED(pq, idx)                    \
    do {                                        \
        assert((idx) < (pq)->htop);             \
        assert((pq)->heap[idx]->posn == (idx)); \
    } while (0)
#define ASSERT_NODE_USED(pq, n)                    \
    do {                                           \
        assert((n)->posn != OSSL_PQ_NOT_IN_QUEUE); \
        assert((n)->posn < (pq)->htop);            \
        assert((pq)->heap[(n)->posn] == (n));      \
    } while (0)
#else
#define ASSERT_USED(pq, idx)
#define ASSERT_NODE_USED(pq, n)
#endif

static const size_t min_nodes = 8;
static const size_t max_nodes = SIZE_MAX / sizeof(OSSL_PQ_NODE *);

/*
 * Calculate the array growth based on the target size.
 *
 * The growth factor is a rational number and is defined by a numerator
 * and a denominator.  According to Andrew Koenig in his paper "Why Are
 * Vectors Efficient?" from JOOP 11(5) 1998, this factor should be less
 * than the golden ratio (1.618...).
 *
 * We use an expansion factor of 8 / 5 = 1.6
 */
static ossl_inline size_t compute_growth(size_t target, size_t current)
{
    int err = 0;

    while (current < target) {
        if (current >= max_nodes)
            return 0;
        current = safe_muldiv_pq_size(current, 8, 5, &err);
        if (err)
            return 0;
        if (current >= max_nodes)
            current = max_nodes;
    }

    return current;
}

static ossl_inline void pq_set(OSSL_PQ *pq, size_t i, OSSL_PQ_NODE *n)
{
    pq->heap[i] = n;
    n->posn = i;
}

static ossl_inline void pq_swap(OSSL_PQ *pq, size_t i, size_t j)
{
    OSSL_PQ_NODE *a = pq->heap[i], *b = pq->heap[j];

    ASSERT_USED(pq, i);
    ASSERT_USED(pq, j);

    pq_set(pq, i, b);
    pq_set(pq, j, a);
}

/* Sift up: restore heap property after insertion. */
static void pq_sift_up(OSSL_PQ *pq, size_t n)
{
    ASSERT_USED(pq, n);
    while (n > 0) {
        size_t p = (n - 1) / 2;

        ASSERT_USED(pq, p);
        if (pq->cmp(pq->heap[n], pq->heap[p]) >= 0)
            break;
        pq_swap(pq, n, p);
        n = p;
    }
}

/*
 * Force the specified element to the front of the heap.  This breaks
 * the heap partial ordering pre-condition.
 */
static void pq_force_top(OSSL_PQ *pq, size_t n)
{
    ASSERT_USED(pq, n);
    while (n > 0) {
        size_t p = (n - 1) / 2;

        ASSERT_USED(pq, p);
        pq_swap(pq, n, p);
        n = p;
    }
}

/* Sift down: restore heap property after root replacement. */
static void pq_sift_down(OSSL_PQ *pq, size_t n)
{
    size_t p = n * 2 + 1;

    ASSERT_USED(pq, n);
    while (p < pq->htop) {
        ASSERT_USED(pq, p);
        if (p + 1 < pq->htop) {
            ASSERT_USED(pq, p + 1);
            if (pq->cmp(pq->heap[p], pq->heap[p + 1]) > 0)
                p++;
        }
        if (pq->cmp(pq->heap[p], pq->heap[n]) >= 0)
            break;
        pq_swap(pq, n, p);
        n = p;
        p = n * 2 + 1;
    }
}

int ossl_pq_reserve(OSSL_PQ *pq, size_t n)
{
    size_t new_max, cur_max, need, target;
    OSSL_PQ_NODE **h;
    int err = 0;

    if (pq == NULL)
        return 0;
    cur_max = pq->hmax;

    /*
     * Required slot count after this reservation.  Overflow here means
     * the caller asked for more than size_t can index -- no allocation
     * can satisfy it.
     */
    need = safe_add_pq_size(pq->htop, n, &err);
    if (err) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (need < cur_max)
        return 1;

    /* Growth target preserves the prior policy of n + cur_max. */
    target = safe_add_pq_size(n, cur_max, &err);
    if (err) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    new_max = compute_growth(target, cur_max);
    if (new_max == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    h = OPENSSL_realloc_array(pq->heap, new_max, sizeof(*pq->heap));
    if (h == NULL)
        return 0;
    pq->heap = h;
    pq->hmax = new_max;

    return 1;
}

int ossl_pq_push(OSSL_PQ *pq, OSSL_PQ_NODE *n)
{
    size_t i;

    if (pq == NULL || n == NULL || n->posn != OSSL_PQ_NOT_IN_QUEUE)
        return 0;

    if (!ossl_pq_reserve(pq, 1))
        return 0;

    i = pq->htop++;
    pq_set(pq, i, n);
    pq_sift_up(pq, i);

    return 1;
}

OSSL_PQ_NODE *ossl_pq_peek(const OSSL_PQ *pq)
{
    if (pq == NULL || pq->htop == 0)
        return NULL;
    ASSERT_USED(pq, 0);
    return pq->heap[0];
}

OSSL_PQ_NODE *ossl_pq_pop(OSSL_PQ *pq)
{
    OSSL_PQ_NODE *res;

    if (pq == NULL || pq->htop == 0)
        return NULL;

    ASSERT_USED(pq, 0);
    res = pq->heap[0];
    res->posn = OSSL_PQ_NOT_IN_QUEUE;

    if (--pq->htop != 0) {
        pq_set(pq, 0, pq->heap[pq->htop]);
        pq_sift_down(pq, 0);
    }

    return res;
}

OSSL_PQ_NODE *ossl_pq_remove(OSSL_PQ *pq, OSSL_PQ_NODE *n)
{
    size_t i;

    if (pq == NULL || n == NULL || n->posn == OSSL_PQ_NOT_IN_QUEUE)
        return NULL;

    ASSERT_NODE_USED(pq, n);
    i = n->posn;
    if (i == OSSL_PQ_NOT_IN_QUEUE || i >= pq->htop || pq->heap[i] != n) {
        assert(0 && "ossl_pq_remove: node not in this queue");
        return NULL;
    }

    if (i == pq->htop - 1) {
        n->posn = OSSL_PQ_NOT_IN_QUEUE;
        --pq->htop;
        return n;
    }

    pq_force_top(pq, i);

    return ossl_pq_pop(pq);
}

size_t ossl_pq_num(const OSSL_PQ *pq)
{
    return pq != NULL ? pq->htop : 0;
}

OSSL_PQ *ossl_pq_new(int (*cmp)(const OSSL_PQ_NODE *,
    const OSSL_PQ_NODE *))
{
    OSSL_PQ *pq;

    if (cmp == NULL)
        return NULL;

    pq = OPENSSL_malloc(sizeof(*pq));
    if (pq == NULL)
        return NULL;
    pq->cmp = cmp;
    pq->htop = 0;
    pq->hmax = min_nodes;
    pq->heap = OPENSSL_malloc_array(min_nodes, sizeof(*pq->heap));
    if (pq->heap == NULL) {
        OPENSSL_free(pq);
        return NULL;
    }

    return pq;
}

void ossl_pq_free(OSSL_PQ *pq)
{
    if (pq == NULL)
        return;

    OPENSSL_free(pq->heap);
    OPENSSL_free(pq);
}

void ossl_pq_pop_free(OSSL_PQ *pq, void (*freefunc)(OSSL_PQ_NODE *))
{
    if (pq == NULL)
        return;
    if (freefunc == NULL)
        goto out;

    for (size_t i = 0; i < pq->htop; i++)
        (*freefunc)(pq->heap[i]);
out:
    ossl_pq_free(pq);
}
