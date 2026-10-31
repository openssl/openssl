/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_QUEUE_H
#define OSSL_INTERNAL_QUEUE_H
#pragma once

#include <stddef.h>
#include <assert.h>
#include <openssl/e_os2.h>
#include "internal/rcu.h"

#define OSSL_CONTAINER_OF(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

#define OSSL_CONTAINER_OF_SAFE(ptr, type, member) \
    ((ptr) == NULL ? NULL : OSSL_CONTAINER_OF(ptr, type, member))

typedef struct ossl_qnode_st OSSL_QNODE;
struct ossl_qnode_st {
    OSSL_QNODE *next;
    OSSL_QNODE **prev;
};

typedef struct ossl_queue_st {
    OSSL_QNODE *head;
} OSSL_QUEUE;

#define OSSL_QUEUE_INIT { NULL }

static ossl_inline void ossl_qnode_init(OSSL_QNODE *n)
{
    n->next = NULL;
    n->prev = NULL;
}

static ossl_inline void ossl_queue_init(OSSL_QUEUE *a)
{
    a->head = NULL;
}

/* A node is "hashed" while it is linked into some queue. */
static ossl_unused ossl_inline int ossl_qnode_hashed(const OSSL_QNODE *n)
{
    return n->prev != NULL;
}

static ossl_unused ossl_inline int ossl_qnode_unhashed(const OSSL_QNODE *n)
{
    return n->prev == NULL;
}

static ossl_unused ossl_inline int ossl_queue_empty(const OSSL_QUEUE *q)
{
    return q->head == NULL;
}

static ossl_unused ossl_inline OSSL_QNODE *ossl_queue_head(const OSSL_QUEUE *q)
{
    return q->head;
}

static ossl_unused ossl_inline OSSL_QNODE *ossl_qnode_next(const OSSL_QNODE *n)
{
    return n->next;
}

/*
 * The node before |n| in |a|, or NULL when |n| is its head. |n->prev| points
 * at the field that points at |n|: the head of |l| or the |next| of the node
 * before it, which is how BSD's LIST_PREV finds it too.
 */
static ossl_unused ossl_inline OSSL_QNODE *ossl_qnode_prev(const OSSL_QUEUE *q,
    const OSSL_QNODE *n)
{
    assert(ossl_qnode_hashed(n));
    if ((const void *)n->prev == (const void *)&q->head)
        return NULL;
    return OSSL_CONTAINER_OF(n->prev, OSSL_QNODE, next);
}

static ossl_inline void ossl_queue_add_head(OSSL_QUEUE *q, OSSL_QNODE *n)
{
    OSSL_QNODE *head = q->head;

    assert(!ossl_qnode_hashed(n));
    n->next = head;
    if (head != NULL)
        head->prev = &n->next;
    q->head = n;
    n->prev = &q->head;
}

static ossl_inline void ossl_queue_add(OSSL_QUEUE *q, OSSL_QNODE *n)
{
    ossl_queue_add_head(q, n);
}

/* Insert |n| before |n|, which must already be in a queue. */
static ossl_inline void ossl_qnode_add_before(OSSL_QNODE *c, OSSL_QNODE *n)
{
    assert(!ossl_qnode_hashed(c) && ossl_qnode_hashed(n));
    c->prev = n->prev;
    c->next = n;
    n->prev = &c->next;
    *(c->prev) = c;
}

/* Insert |c| after |p|, which must already be in a queue. */
static ossl_inline void ossl_qnode_add_behind(OSSL_QNODE *c, OSSL_QNODE *p)
{
    assert(!ossl_qnode_hashed(c) && ossl_qnode_hashed(p));
    c->next = p->next;
    p->next = c;
    c->prev = &p->next;
    if (c->next != NULL)
        c->next->prev = &c->next;
}

static ossl_inline void ossl_qnode_unlink(OSSL_QNODE *n)
{
    OSSL_QNODE *next = n->next, **prev = n->prev;

    *prev = next;
    if (next != NULL)
        next->prev = prev;
}

/* Remove |n|, which must be in a queue, and reset it to the unhashed state. */
static ossl_inline void ossl_qnode_del(OSSL_QNODE *n)
{
    assert(ossl_qnode_hashed(n));
    ossl_qnode_unlink(n);
    ossl_qnode_init(n);
}

/* Like ossl_qnode_del() but a no-op on a node that is not in a queue. */
static ossl_inline void ossl_qnode_del_init(OSSL_QNODE *n)
{
    if (ossl_qnode_hashed(n))
        ossl_qnode_del(n);
}

/* Move every node of |from| onto the (assumed empty) head |to|. */
static ossl_unused ossl_inline void ossl_queue_move(OSSL_QUEUE *to,
    OSSL_QUEUE *from)
{
    assert(ossl_queue_empty(to));
    to->head = from->head;
    if (to->head != NULL)
        to->head->prev = &to->head;
    from->head = NULL;
}

/*
 * Writers still serialise against each other. Readers walk a queue inside a
 * read-side section (ossl_rcu_read_lock()) using the _rcu accessors.
 * ossl_qnode_del_rcu() leaves |next| intact so a reader parked on the victim
 * can still advance; the node must not be reused or freed before a grace
 * period has elapsed.
 */
static ossl_unused ossl_inline OSSL_QNODE *ossl_queue_head_rcu(OSSL_QUEUE *a)
{
    return (OSSL_QNODE *)ossl_rcu_deref(&a->head);
}

static ossl_unused ossl_inline OSSL_QNODE *ossl_qnode_next_rcu(OSSL_QNODE *n)
{
    return (OSSL_QNODE *)ossl_rcu_deref(&n->next);
}

static ossl_inline void ossl_queue_add_head_rcu(OSSL_QUEUE *a, OSSL_QNODE *n)
{
    OSSL_QNODE *head = a->head;

    assert(!ossl_qnode_hashed(n));
    n->next = head;
    n->prev = &a->head;
    ossl_rcu_assign_ptr(&a->head, &n);
    if (head != NULL)
        head->prev = &n->next;
}

static ossl_inline void ossl_qnode_add_before_rcu(OSSL_QNODE *q, OSSL_QNODE *n)
{
    assert(!ossl_qnode_hashed(q) && ossl_qnode_hashed(n));
    q->prev = n->prev;
    q->next = n;
    ossl_rcu_assign_ptr(q->prev, &q);
    n->prev = &q->next;
}

static ossl_inline void ossl_qnode_add_behind_rcu(OSSL_QNODE *n, OSSL_QNODE *p)
{
    assert(!ossl_qnode_hashed(n) && ossl_qnode_hashed(p));
    n->next = p->next;
    n->prev = &p->next;
    ossl_rcu_assign_ptr(&p->next, &n);
    if (n->next != NULL)
        n->next->prev = &n->next;
}

static ossl_unused ossl_inline void ossl_qnode_del_rcu(OSSL_QNODE *n)
{
    OSSL_QNODE *next = n->next, **prev = n->prev;

    assert(ossl_qnode_hashed(n));
    ossl_rcu_assign_ptr(prev, &next);
    if (next != NULL)
        next->prev = prev;
    n->prev = NULL;
}

/* Define the field embedding an element in the queue |name|. */
#define OSSL_QUEUE_MEMBER(name) OSSL_QNODE ossl_queue_##name

#define DEFINE_QUEUE_OF(name, type)                                  \
    static ossl_unused ossl_inline type *                            \
    ossl_queue_##name##_entry(OSSL_QNODE *n)                         \
    {                                                                \
        return OSSL_CONTAINER_OF_SAFE(n, type, ossl_queue_##name);   \
    }                                                                \
    static ossl_unused ossl_inline void                              \
    ossl_queue_##name##_init_elem(type *e)                           \
    {                                                                \
        ossl_qnode_init(&e->ossl_queue_##name);                      \
    }                                                                \
    static ossl_unused ossl_inline int                               \
    ossl_queue_##name##_hashed(const type *e)                        \
    {                                                                \
        return ossl_qnode_hashed(&e->ossl_queue_##name);             \
    }                                                                \
    static ossl_unused ossl_inline type *                            \
    ossl_queue_##name##_head(const OSSL_QUEUE *l)                    \
    {                                                                \
        return ossl_queue_##name##_entry(l->head);                   \
    }                                                                \
    static ossl_unused ossl_inline type *                            \
    ossl_queue_##name##_next(const type *e)                          \
    {                                                                \
        return ossl_queue_##name##_entry(e->ossl_queue_##name.next); \
    }                                                                \
    static ossl_unused ossl_inline type *                            \
    ossl_queue_##name##_prev(const OSSL_QUEUE *a, const type *e)     \
    {                                                                \
        OSSL_QNODE *n = ossl_qnode_prev(a, &e->ossl_queue_##name);   \
        return ossl_queue_##name##_entry(n);                         \
    }                                                                \
    static ossl_unused ossl_inline void                              \
    ossl_queue_##name##_add(OSSL_QUEUE *l, type *e)                  \
    {                                                                \
        ossl_queue_add_head(l, &e->ossl_queue_##name);               \
    }                                                                \
    static ossl_unused ossl_inline void                              \
    ossl_queue_##name##_add_before(type *e, type *next)              \
    {                                                                \
        ossl_qnode_add_before(&e->ossl_queue_##name,                 \
            &next->ossl_queue_##name);                               \
    }                                                                \
    static ossl_unused ossl_inline void                              \
    ossl_queue_##name##_add_behind(type *e, type *prev)              \
    {                                                                \
        ossl_qnode_add_behind(&e->ossl_queue_##name,                 \
            &prev->ossl_queue_##name);                               \
    }                                                                \
    static ossl_unused ossl_inline void                              \
    ossl_queue_##name##_del(type *e)                                 \
    {                                                                \
        ossl_qnode_del(&e->ossl_queue_##name);                       \
    }                                                                \
    static ossl_unused ossl_inline void                              \
    ossl_queue_##name##_del_init(type *e)                            \
    {                                                                \
        ossl_qnode_del_init(&e->ossl_queue_##name);                  \
    }                                                                \
    static ossl_unused ossl_inline type *                            \
    ossl_queue_##name##_head_rcu(OSSL_QUEUE *l)                      \
    {                                                                \
        return ossl_queue_##name##_entry(ossl_queue_head_rcu(l));    \
    }                                                                \
    static ossl_unused ossl_inline type *                            \
    ossl_queue_##name##_next_rcu(type *e)                            \
    {                                                                \
        return ossl_queue_##name##_entry(                            \
            ossl_qnode_next_rcu(&e->ossl_queue_##name));             \
    }                                                                \
    static ossl_unused ossl_inline void                              \
    ossl_queue_##name##_add_rcu(OSSL_QUEUE *a, type *e)              \
    {                                                                \
        ossl_queue_add_head_rcu(a, &e->ossl_queue_##name);           \
    }                                                                \
    static ossl_unused ossl_inline void                              \
    ossl_queue_##name##_del_rcu(type *e)                             \
    {                                                                \
        ossl_qnode_del_rcu(&e->ossl_queue_##name);                   \
    }                                                                \
    struct ossl_queue_dummy_st_##name

#define OSSL_QUEUE_WALK(it, q) \
    for ((it) = (q)->head; (it) != NULL; (it) = (it)->next)

#define OSSL_QUEUE_WALK_DELSAFE(it, t, q) \
    for ((it) = (q)->head; (it) != NULL && (((t) = (it)->next), 1); (it) = (t))

#define OSSL_QUEUE_FOREACH(p, name, l)                   \
    for ((p) = ossl_queue_##name##_head(l); (p) != NULL; \
        (p) = ossl_queue_##name##_next(p))

#define OSSL_QUEUE_FOREACH_DELSAFE(p, pn, name, l) \
    for ((p) = ossl_queue_##name##_head(l);        \
        (p) != NULL && (((pn) = ossl_queue_##name##_next(p)), 1); (p) = (pn))

#define OSSL_QUEUE_FOREACH_RCU(p, name, l)                   \
    for ((p) = ossl_queue_##name##_head_rcu(l); (p) != NULL; \
        (p) = ossl_queue_##name##_next_rcu(p))

#endif /* OSSL_INTERNAL_QUEUE_H */
