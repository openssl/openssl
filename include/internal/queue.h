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

#define OSSL_CONTAINER_OF(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

#define OSSL_CONTAINER_OF_SAFE(ptr, type, member) \
    ((ptr) == NULL ? NULL : OSSL_CONTAINER_OF(ptr, type, member))

/*
 * A node's |prev| does not point at the node before it but at the pointer that
 * points at the node: the |next| of the node before it or, for the first node,
 * the |head| of its queue.
 *
 * What that buys over a list whose nodes point at each other, such as
 * OSSL_LIST (internal/list.h):
 *
 * - A head is one pointer, where OSSL_LIST has a head, a tail and a count.
 *   A table is an array of heads, most of them with no node or one, so it
 *   takes a third of the memory and, with 64-bit pointers, eight heads share
 *   a cache line.
 * - A node is unlinked without its head: *n->prev = n->next is the same for
 *   the first node as for any other. Taking an element out of a table needs
 *   neither its key, nor its hash, nor the table; only the element.
 * - |prev| is NULL exactly while the node is in no queue, so membership
 *   needs no flag of its own (ossl_qnode_hashed()).
 * - An empty head is a NULL pointer, not a sentinel that points at itself as
 *   the head of a circular list is, so a zeroed or statically initialised
 *   table is empty and ready for use.
 * - Walking forward follows |head| and |next| only, to a NULL: a node can be
 *   published to readers that hold no lock with a single store
 *   (internal/htable_rcu.h).
 *
 * What it gives up: a queue has no tail and no count, and cannot be walked
 * backwards from its end. A caller that needs the tail keeps it itself
 * (ossl_queue_<name>_add_tail()). Where both ends, the order or the count
 * matter and the heads are few, OSSL_LIST is the better fit.
 */
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
 * The node before |n| in |q|, or NULL when |n| is its head. |n->prev| points
 * at the field that points at |n|: the head of |q| or the |next| of the node
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

/* Insert |c| before |n|, which must already be in a queue. */
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
    /*                                                               \
     * Append |e| to |l|, whose tail is |*tail| (NULL when empty),   \
     * and make it the tail. A queue has no tail of its own; this    \
     * and _del_keep_tail() keep one the caller holds right.         \
     */                                                              \
    static ossl_unused ossl_inline void                              \
    ossl_queue_##name##_add_tail(OSSL_QUEUE *l, type **tail,         \
        type *e)                                                     \
    {                                                                \
        assert((*tail == NULL) == ossl_queue_empty(l));              \
        if (*tail == NULL)                                           \
            ossl_queue_##name##_add(l, e);                           \
        else                                                         \
            ossl_queue_##name##_add_behind(e, *tail);                \
        *tail = e;                                                   \
    }                                                                \
    /* Remove |e|, moving |*tail| back if |e| was the tail. */       \
    static ossl_unused ossl_inline void                              \
    ossl_queue_##name##_del_keep_tail(const OSSL_QUEUE *l,           \
        type **tail, type *e)                                        \
    {                                                                \
        if (e == *tail)                                              \
            *tail = ossl_queue_##name##_prev(l, e);                  \
        ossl_queue_##name##_del(e);                                  \
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

#endif /* OSSL_INTERNAL_QUEUE_H */
