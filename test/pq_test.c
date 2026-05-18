/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "internal/pq.h"
#include "internal/nelem.h"
#include "testutil.h"

#define MAX_SAMPLES 500000

typedef struct elem_st {
    size_t value;
    OSSL_PQ_NODE pqn;
} ELEM;

/*
 * Large static-storage arrays: the helper is invoked many times by
 * ADD_ALL_TESTS, so keeping them out of the stack avoids overflow at
 * MAX_SAMPLES, mirroring priority_queue_test.c's allocation style.
 */
static ELEM elems[MAX_SAMPLES];
static size_t sorted[MAX_SAMPLES];

static size_t num_rec_freed;

static int elem_compare(const OSSL_PQ_NODE *a, const OSSL_PQ_NODE *b)
{
    size_t va = CONTAINER_OF(a, ELEM, pqn)->value;
    size_t vb = CONTAINER_OF(b, ELEM, pqn)->value;

    if (va < vb)
        return -1;
    if (va > vb)
        return 1;
    return 0;
}

static int qsort_size_t_compare(const void *a, const void *b)
{
    size_t va = *(const size_t *)a, vb = *(const size_t *)b;

    if (va < vb)
        return -1;
    if (va > vb)
        return 1;
    return 0;
}

static void free_checker(ossl_unused OSSL_PQ_NODE *n)
{
    num_rec_freed++;
}

/*
 * Parameterized priority-queue exerciser.  Pushes 'count' elements,
 * optionally removes 'remove' random ones, drains the queue and
 * verifies the survivors come out in sorted order.  Mirrors
 * test_size_t_priority_queue_int() in priority_queue_test.c.
 */
static int test_priority_queue_int(int reserve, int order, int count,
    int remove, int random, int popfree)
{
    OSSL_PQ *pq = NULL;
    size_t n;
    int i, res = 0;
    static const char *orders[3] = { "unordered", "ascending", "descending" };

    TEST_info("testing count %d, %s, %s, values %s, remove %d, %sfree",
        count, orders[order], reserve ? "reserve" : "grow",
        random ? "random" : "deterministic", remove,
        popfree ? "pop " : "");

    if (!TEST_size_t_le(count, MAX_SAMPLES))
        return 0;

    memset(elems, 0, sizeof(elems));
    memset(sorted, 0, sizeof(sorted));

    for (i = 0; i < count; i++) {
        elems[i].value = random ? (size_t)test_random() : (size_t)(count - i);
        ossl_pq_node_init(&elems[i].pqn);
        sorted[i] = elems[i].value;
    }
    qsort(sorted, count, sizeof(*sorted), &qsort_size_t_compare);

    /* Optionally reshape the push order. */
    if (order == 1) {
        for (i = 0; i < count; i++)
            elems[i].value = sorted[i];
    } else if (order == 2) {
        for (i = 0; i < count; i++)
            elems[i].value = sorted[count - 1 - i];
    }

    if (!TEST_ptr(pq = ossl_pq_new(elem_compare))
        || !TEST_size_t_eq(ossl_pq_num(pq), 0))
        goto err;

    if (reserve && !TEST_true(ossl_pq_reserve(pq, count)))
        goto err;

    for (i = 0; i < count; i++)
        if (!TEST_true(ossl_pq_push(pq, &elems[i].pqn)))
            goto err;

    if (!TEST_ptr(ossl_pq_peek(pq))
        || !TEST_size_t_eq(CONTAINER_OF(ossl_pq_peek(pq), ELEM, pqn)->value,
            sorted[0])
        || !TEST_size_t_eq(ossl_pq_num(pq), count))
        goto err;

    if (remove) {
        while (remove-- > 0) {
            i = test_random() % count;
            if (ossl_pq_node_in_queue(&elems[i].pqn)) {
                if (!TEST_ptr_eq(ossl_pq_remove(pq, &elems[i].pqn),
                        &elems[i].pqn))
                    goto err;
                /*
                 * Mark as "removed" with a sentinel that sorts to the end
                 * of sorted[].  We use ossl_pq_node_in_queue() as the real
                 * "is it still here?" predicate above; this sentinel is
                 * purely so the qsort below pushes removed entries past
                 * the position the peek/pop loop will iterate to.
                 */
                elems[i].value = SIZE_MAX;
            }
        }
        for (i = 0; i < count; i++)
            sorted[i] = elems[i].value;
        qsort(sorted, count, sizeof(*sorted), &qsort_size_t_compare);
    }

    for (i = 0; ossl_pq_peek(pq) != NULL; i++) {
        OSSL_PQ_NODE *peeked = ossl_pq_peek(pq);
        OSSL_PQ_NODE *popped;

        if (!TEST_size_t_eq(CONTAINER_OF(peeked, ELEM, pqn)->value, sorted[i]))
            goto err;
        popped = ossl_pq_pop(pq);
        if (!TEST_size_t_eq(CONTAINER_OF(popped, ELEM, pqn)->value, sorted[i]))
            goto err;
    }

    if (popfree) {
        num_rec_freed = 0;
        n = ossl_pq_num(pq);
        ossl_pq_pop_free(pq, &free_checker);
        pq = NULL;
        if (!TEST_size_t_eq(num_rec_freed, n))
            goto err;
    }
    res = 1;
err:
    ossl_pq_free(pq);
    return res;
}

static const int test_priority_counts[] = {
    10, 11, 6, 5, 3, 1, 2, 7500
};

static int test_priority_queue(int n)
{
    int reserve, order, count, remove, random, popfree;

    count = n % OSSL_NELEM(test_priority_counts);
    n /= OSSL_NELEM(test_priority_counts);
    order = n % 3;
    n /= 3;
    random = n % 2;
    n /= 2;
    reserve = n % 2;
    n /= 2;
    remove = n % 6;
    n /= 6;
    popfree = n % 2;

    count = test_priority_counts[count];
    return test_priority_queue_int(reserve, order, count, remove,
        random, popfree);
}

static int test_large_priority_queue(void)
{
    return test_priority_queue_int(0, 0, MAX_SAMPLES, MAX_SAMPLES / 100,
        1, 1);
}

/*
 * Regression for issue 22644: a specific push/remove/pop sequence used
 * to crash on the second pop due to mishandled heap state.  In the
 * intrusive API there is no separate handle table, but the underlying
 * heap state machine is the same; the operation sequence remains a
 * useful smoke test.
 */
typedef struct info_st {
    uint64_t seq_num;
    uint64_t sub_seq;
    OSSL_PQ_NODE pqn;
} INFO;

static int info_cmp(const OSSL_PQ_NODE *a, const OSSL_PQ_NODE *b)
{
    const INFO *ia = CONTAINER_OF(a, INFO, pqn);
    const INFO *ib = CONTAINER_OF(b, INFO, pqn);

    if (ia->seq_num < ib->seq_num)
        return -1;
    if (ia->seq_num > ib->seq_num)
        return 1;
    if (ia->sub_seq < ib->sub_seq)
        return -1;
    if (ia->sub_seq > ib->sub_seq)
        return 1;
    return 0;
}

static int test_22644(void)
{
    size_t i;
    INFO infos[32];
    int res = 0;
    OSSL_PQ *pq = ossl_pq_new(info_cmp);

    memset(infos, 0, sizeof(infos));
    for (i = 0; i < 32; i++) {
        infos[i].sub_seq = i;
        ossl_pq_node_init(&infos[i].pqn);
    }

    infos[0].seq_num = 70650219160667140;
    if (!TEST_true(ossl_pq_push(pq, &infos[0].pqn))
        || !TEST_ptr_eq(ossl_pq_remove(pq, &infos[0].pqn), &infos[0].pqn))
        goto err;

    infos[1].seq_num = 289360691352306692;
    if (!TEST_true(ossl_pq_push(pq, &infos[1].pqn))
        || !TEST_ptr_eq(ossl_pq_remove(pq, &infos[1].pqn), &infos[1].pqn))
        goto err;

    for (i = 2; i <= 8; i++) {
        infos[i].seq_num = 289360691352306692;
        if (!TEST_true(ossl_pq_push(pq, &infos[i].pqn)))
            goto err;
    }

    if (!TEST_ptr(ossl_pq_pop(pq))
        || !TEST_ptr(ossl_pq_pop(pq))) /* crash if bug present */
        goto err;
    res = 1;

err:
    ossl_pq_free(pq);
    return res;
}

/*
 * Edge cases not exercised by the combinatorial driver: NULL queue,
 * empty queue, remove() on a node that has never been in the queue, and
 * single-element push/peek/pop.  No analog in priority_queue_test.c.
 */
static int test_edge_cases(void)
{
    OSSL_PQ *pq = NULL;
    ELEM e;
    int res = 0;

    if (!TEST_ptr_null(ossl_pq_new(NULL)))
        goto err;

    if (!TEST_size_t_eq(ossl_pq_num(NULL), 0)
        || !TEST_ptr_null(ossl_pq_peek(NULL))
        || !TEST_ptr_null(ossl_pq_pop(NULL)))
        goto err;

    if (!TEST_ptr(pq = ossl_pq_new(elem_compare)))
        goto err;

    if (!TEST_ptr_null(ossl_pq_peek(pq))
        || !TEST_ptr_null(ossl_pq_pop(pq))
        || !TEST_size_t_eq(ossl_pq_num(pq), 0))
        goto err;

    /* Remove on a detached node is a no-op. */
    e.value = 42;
    ossl_pq_node_init(&e.pqn);
    if (!TEST_ptr_null(ossl_pq_remove(pq, &e.pqn))
        || !TEST_false(ossl_pq_node_in_queue(&e.pqn)))
        goto err;

    /* Single-element push/pop. */
    if (!TEST_true(ossl_pq_push(pq, &e.pqn))
        || !TEST_size_t_eq(ossl_pq_num(pq), 1)
        || !TEST_ptr_eq(ossl_pq_peek(pq), &e.pqn)
        || !TEST_ptr_eq(ossl_pq_pop(pq), &e.pqn)
        || !TEST_size_t_eq(ossl_pq_num(pq), 0)
        || !TEST_false(ossl_pq_node_in_queue(&e.pqn)))
        goto err;

    ossl_pq_free(NULL); /* must not crash */
    res = 1;
err:
    ossl_pq_free(pq);
    return res;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_priority_queue,
        OSSL_NELEM(test_priority_counts) /* count */
            * 3 /* order */
            * 2 /* random */
            * 2 /* reserve */
            * 6 /* remove */
            * 2); /* pop & free */
    ADD_TEST(test_large_priority_queue);
    ADD_TEST(test_22644);
    ADD_TEST(test_edge_cases);
    return 1;
}
