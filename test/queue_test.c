/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/crypto.h>

#include "internal/queue.h"
#include "internal/nelem.h"
#include "testutil.h"

typedef struct qitem_st {
    int n;
    OSSL_QUEUE_MEMBER(fizz);
    OSSL_QUEUE_MEMBER(buzz);
} QITEM;

DEFINE_QUEUE_OF(fizz, QITEM);
DEFINE_QUEUE_OF(buzz, QITEM);

/*
 * Walk |q| and check that it holds exactly the nodes in |exp|, in that order,
 * and that every back-link points at the slot which points at the node.
 */
static int check_node_order(const OSSL_QUEUE *q, OSSL_QNODE *const *exp,
    size_t n)
{
    const OSSL_QNODE *it;
    size_t i = 0;

    OSSL_QUEUE_WALK (it, q) {
        if (!TEST_size_t_lt(i, n)
            || !TEST_ptr_eq(it, exp[i])
            || !TEST_ptr_eq(*it->prev, it))
            return 0;
        i++;
    }
    return TEST_size_t_eq(i, n);
}

static int check_fizz_order(const OSSL_QUEUE *q, const int *exp, size_t n)
{
    const QITEM *p;
    size_t i = 0;

    OSSL_QUEUE_FOREACH (p, fizz, q) {
        if (!TEST_size_t_lt(i, n)
            || !TEST_int_eq(p->n, exp[i])
            || !TEST_ptr_eq(*p->ossl_queue_fizz.prev, &p->ossl_queue_fizz))
            return 0;
        i++;
    }
    return TEST_size_t_eq(i, n);
}

static int check_buzz_order(const OSSL_QUEUE *q, const int *exp, size_t n)
{
    const QITEM *p;
    size_t i = 0;

    OSSL_QUEUE_FOREACH (p, buzz, q) {
        if (!TEST_size_t_lt(i, n)
            || !TEST_int_eq(p->n, exp[i])
            || !TEST_ptr_eq(*p->ossl_queue_buzz.prev, &p->ossl_queue_buzz))
            return 0;
        i++;
    }
    return TEST_size_t_eq(i, n);
}

/* The node-level operations on bare OSSL_QNODEs. */
static int test_node_ops(void)
{
    OSSL_QUEUE q = OSSL_QUEUE_INIT, q2;
    OSSL_QNODE n[5], *it, *tmp;
    OSSL_QNODE *exp1[] = { &n[2], &n[1], &n[0] };
    OSSL_QNODE *exp2[] = { &n[2], &n[3], &n[1], &n[4], &n[0] };
    OSSL_QNODE *exp3[] = { &n[3], &n[4] };
    OSSL_QNODE *exp4[] = { &n[4] };
    size_t i, count = 0;

    ossl_queue_init(&q2);
    for (i = 0; i < OSSL_NELEM(n); i++)
        ossl_qnode_init(&n[i]);

    if (!TEST_true(ossl_queue_empty(&q))
        || !TEST_true(ossl_queue_empty(&q2))
        || !TEST_ptr_null(ossl_queue_head(&q))
        || !TEST_true(ossl_qnode_unhashed(&n[0]))
        || !TEST_false(ossl_qnode_hashed(&n[0])))
        return 0;

    /* Insertion is at the head, so the order is reversed */
    ossl_queue_add_head(&q, &n[0]);
    ossl_queue_add_head(&q, &n[1]);
    ossl_queue_add(&q, &n[2]);
    if (!TEST_false(ossl_queue_empty(&q))
        || !TEST_true(ossl_qnode_hashed(&n[0]))
        || !TEST_false(ossl_qnode_unhashed(&n[2]))
        || !TEST_ptr_eq(ossl_queue_head(&q), &n[2])
        || !TEST_ptr_eq(ossl_qnode_next(&n[2]), &n[1])
        || !TEST_ptr_null(ossl_qnode_next(&n[0]))
        || !check_node_order(&q, exp1, OSSL_NELEM(exp1)))
        return 0;

    /* Relative insertion before and behind a node in the middle */
    ossl_qnode_add_before(&n[3], &n[1]);
    ossl_qnode_add_behind(&n[4], &n[1]);
    if (!check_node_order(&q, exp2, OSSL_NELEM(exp2)))
        return 0;

    /* prev() walks back through the back-links, to NULL at the head */
    if (!TEST_ptr_null(ossl_qnode_prev(&q, &n[2]))
        || !TEST_ptr_eq(ossl_qnode_prev(&q, &n[3]), &n[2])
        || !TEST_ptr_eq(ossl_qnode_prev(&q, &n[1]), &n[3])
        || !TEST_ptr_eq(ossl_qnode_prev(&q, &n[0]), &n[4]))
        return 0;

    /* Delete the head, the tail and a node in the middle */
    ossl_qnode_del(&n[2]);
    ossl_qnode_del(&n[0]);
    ossl_qnode_del(&n[1]);
    if (!TEST_true(ossl_qnode_unhashed(&n[2]))
        || !TEST_ptr_null(n[2].next)
        || !TEST_ptr_eq(ossl_queue_head(&q), &n[3])
        || !check_node_order(&q, exp3, OSSL_NELEM(exp3)))
        return 0;

    /* del_init removes a queued node and ignores one that is not queued */
    ossl_qnode_del_init(&n[2]);
    ossl_qnode_del_init(&n[3]);
    if (!TEST_true(ossl_qnode_unhashed(&n[3]))
        || !check_node_order(&q, exp4, OSSL_NELEM(exp4)))
        return 0;

    /* A move re-points the head's back-link, so deletion still works */
    ossl_queue_move(&q2, &q);
    if (!TEST_true(ossl_queue_empty(&q))
        || !check_node_order(&q2, exp4, OSSL_NELEM(exp4)))
        return 0;
    ossl_qnode_del(&n[4]);
    if (!TEST_true(ossl_queue_empty(&q2)))
        return 0;

    /* A deletion-safe walk may remove every node it visits */
    for (i = 0; i < OSSL_NELEM(n); i++)
        ossl_queue_add_head(&q, &n[i]);
    OSSL_QUEUE_WALK_DELSAFE (it, tmp, &q) {
        ossl_qnode_del(it);
        count++;
    }
    if (!TEST_size_t_eq(count, OSSL_NELEM(n))
        || !TEST_true(ossl_queue_empty(&q)))
        return 0;
    for (i = 0; i < OSSL_NELEM(n); i++)
        if (!TEST_true(ossl_qnode_unhashed(&n[i])))
            return 0;
    return 1;
}

/* The typed operations of DEFINE_QUEUE_OF, with elements in two queues. */
static int test_typed_queue(void)
{
    OSSL_QUEUE a = OSSL_QUEUE_INIT, b = OSSL_QUEUE_INIT;
    QITEM elem[16], *p, *pn;
    const int fizz1[] = { 15, 12, 9, 6, 3 };
    const int fizz2[] = { 15, 12, 9, 6, 1, 3, 2 };
    const int buzz1[] = { 15, 10, 5 };
    int i, na = 0, nb = 0;
    size_t count = 0;

    for (i = 0; i < (int)OSSL_NELEM(elem); i++) {
        elem[i].n = i;
        ossl_queue_fizz_init_elem(&elem[i]);
        ossl_queue_buzz_init_elem(&elem[i]);
    }

    /* entry() maps a node back to its element, and NULL to NULL */
    if (!TEST_ptr_eq(ossl_queue_fizz_entry(&elem[3].ossl_queue_fizz), &elem[3])
        || !TEST_ptr_eq(ossl_queue_buzz_entry(&elem[3].ossl_queue_buzz),
            &elem[3])
        || !TEST_ptr_null(ossl_queue_fizz_entry(NULL))
        || !TEST_ptr_null(ossl_queue_fizz_head(&a))
        || !TEST_ptr_null(ossl_queue_buzz_head(&b)))
        return 0;

    for (i = 1; i < (int)OSSL_NELEM(elem); i++) {
        if (i % 3 == 0) {
            ossl_queue_fizz_add(&a, &elem[i]);
            na++;
        }
        if (i % 5 == 0) {
            ossl_queue_buzz_add(&b, &elem[i]);
            nb++;
        }
    }

    /* An element sits in two queues at once through its two members */
    if (!TEST_true(ossl_queue_fizz_hashed(&elem[15]))
        || !TEST_true(ossl_queue_buzz_hashed(&elem[15]))
        || !TEST_true(ossl_queue_fizz_hashed(&elem[3]))
        || !TEST_false(ossl_queue_buzz_hashed(&elem[3]))
        || !TEST_false(ossl_queue_fizz_hashed(&elem[5]))
        || !TEST_true(ossl_queue_buzz_hashed(&elem[5]))
        || !TEST_ptr_eq(ossl_queue_fizz_head(&a), &elem[15])
        || !TEST_ptr_eq(ossl_queue_fizz_next(&elem[15]), &elem[12])
        || !TEST_ptr_null(ossl_queue_fizz_next(&elem[3]))
        || !check_fizz_order(&a, fizz1, OSSL_NELEM(fizz1))
        || !check_buzz_order(&b, buzz1, OSSL_NELEM(buzz1)))
        return 0;

    /* Relative insertion around the tail */
    ossl_queue_fizz_add_before(&elem[1], &elem[3]);
    ossl_queue_fizz_add_behind(&elem[2], &elem[3]);
    if (!check_fizz_order(&a, fizz2, OSSL_NELEM(fizz2))
        || !TEST_ptr_null(ossl_queue_fizz_prev(&a, &elem[15]))
        || !TEST_ptr_eq(ossl_queue_fizz_prev(&a, &elem[1]), &elem[6])
        || !TEST_ptr_eq(ossl_queue_fizz_prev(&a, &elem[2]), &elem[3]))
        return 0;

    ossl_queue_fizz_del(&elem[1]);
    ossl_queue_fizz_del_init(&elem[2]);
    ossl_queue_fizz_del_init(&elem[2]); /* a no-op once removed */
    if (!TEST_false(ossl_queue_fizz_hashed(&elem[1]))
        || !TEST_false(ossl_queue_fizz_hashed(&elem[2]))
        || !check_fizz_order(&a, fizz1, OSSL_NELEM(fizz1)))
        return 0;

    /* Emptying one queue while walking it leaves the other untouched */
    OSSL_QUEUE_FOREACH_DELSAFE (p, pn, fizz, &a) {
        ossl_queue_fizz_del(p);
        count++;
    }
    if (!TEST_size_t_eq(count, (size_t)na)
        || !TEST_ptr_null(ossl_queue_fizz_head(&a))
        || !TEST_false(ossl_queue_fizz_hashed(&elem[15]))
        || !TEST_true(ossl_queue_buzz_hashed(&elem[15]))
        || !check_buzz_order(&b, buzz1, OSSL_NELEM(buzz1)))
        return 0;
    count = 0;
    OSSL_QUEUE_FOREACH (p, buzz, &b)
        count++;
    return TEST_size_t_eq(count, (size_t)nb);
}

/* _add_tail() and _del_keep_tail() keep a tail pointer the caller holds. */
static int test_tail(void)
{
    OSSL_QUEUE q = OSSL_QUEUE_INIT;
    QITEM elem[4], *tail = NULL;
    const int all[] = { 0, 1, 2, 3 };
    const int mid[] = { 1, 2 };
    const int back[] = { 1, 2, 3 };
    int i;

    for (i = 0; i < (int)OSSL_NELEM(elem); i++) {
        elem[i].n = i;
        ossl_queue_fizz_init_elem(&elem[i]);
    }

    /* Appending keeps the order of insertion and moves the tail along */
    for (i = 0; i < (int)OSSL_NELEM(elem); i++) {
        ossl_queue_fizz_add_tail(&q, &tail, &elem[i]);
        if (!TEST_ptr_eq(tail, &elem[i]))
            return 0;
    }
    if (!check_fizz_order(&q, all, OSSL_NELEM(all)))
        return 0;

    /* Removing the tail moves it back; removing the head leaves it */
    ossl_queue_fizz_del_keep_tail(&q, &tail, &elem[3]);
    if (!TEST_ptr_eq(tail, &elem[2]))
        return 0;
    ossl_queue_fizz_del_keep_tail(&q, &tail, &elem[0]);
    if (!TEST_ptr_eq(tail, &elem[2])
        || !check_fizz_order(&q, mid, OSSL_NELEM(mid)))
        return 0;

    /* An append after removals still goes behind the tail */
    ossl_queue_fizz_add_tail(&q, &tail, &elem[3]);
    if (!TEST_ptr_eq(tail, &elem[3])
        || !check_fizz_order(&q, back, OSSL_NELEM(back)))
        return 0;

    /* Emptied from the tail, the queue ends with no tail */
    for (i = 3; i >= 1; i--) {
        ossl_queue_fizz_del_keep_tail(&q, &tail, &elem[i]);
        if (!TEST_ptr_eq(tail, i > 1 ? &elem[i - 1] : NULL))
            return 0;
    }
    return TEST_true(ossl_queue_empty(&q));
}

int setup_tests(void)
{
    ADD_TEST(test_node_ops);
    ADD_TEST(test_typed_queue);
    ADD_TEST(test_tail);
    return 1;
}
