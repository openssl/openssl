/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_PRIOQ_H
#define OSSL_INTERNAL_PRIOQ_H
#pragma once

#include <stddef.h>
#include <openssl/e_os2.h>
#include "internal/container_of.h"

/*
 * Intrusive binary-heap priority queue.
 *
 * Each element embeds an OSSL_PRIOQ_NODE; the queue stores pointers to those
 * nodes and tracks each element's current heap position inside the node
 * itself.  No void* casts in the API, no per-type wrapper macros, no
 * parallel handle table.
 *
 *     typedef struct foo_st {
 *         uint64_t     key;
 *         OSSL_PRIOQ_NODE pqn;
 *         ...
 *     } FOO;
 *
 *     static int foo_cmp(const OSSL_PRIOQ_NODE *a, const OSSL_PRIOQ_NODE *b)
 *     {
 *         const FOO *fa = CONTAINER_OF(a, FOO, pqn);
 *         const FOO *fb = CONTAINER_OF(b, FOO, pqn);
 *         return fa->key < fb->key ? -1 : fa->key > fb->key;
 *     }
 *
 *     OSSL_PRIOQ *pq = ossl_prioq_new(foo_cmp);
 *     ossl_prioq_node_init(&foo->pqn);
 *     ossl_prioq_push(pq, &foo->pqn);
 *     ...
 *     OSSL_PRIOQ_NODE *n = ossl_prioq_pop(pq);
 *     FOO *got = CONTAINER_OF(n, FOO, pqn);
 *
 * An element may belong to at most one queue at a time.  Re-pushing a node
 * that is already enqueued is a programming error (asserted in debug builds).
 */

#define OSSL_PRIOQ_NOT_IN_QUEUE ((size_t)-1)

typedef struct ossl_prioq_node_st {
    /*
     * internal: do not touch
     *
     * index in heap[]; OSSL_PRIOQ_NOT_IN_QUEUE if detached
     */
    size_t posn;
} OSSL_PRIOQ_NODE;

typedef struct ossl_prioq_st OSSL_PRIOQ;

static ossl_unused ossl_inline void ossl_prioq_node_init(OSSL_PRIOQ_NODE *n)
{
    n->posn = OSSL_PRIOQ_NOT_IN_QUEUE;
}

static ossl_unused ossl_inline int ossl_prioq_node_in_queue(const OSSL_PRIOQ_NODE *n)
{
    return n->posn != OSSL_PRIOQ_NOT_IN_QUEUE;
}

OSSL_PRIOQ *ossl_prioq_new(int (*cmp)(const OSSL_PRIOQ_NODE *, const OSSL_PRIOQ_NODE *));
void ossl_prioq_free(OSSL_PRIOQ *pq);
int ossl_prioq_reserve(OSSL_PRIOQ *pq, size_t n);
size_t ossl_prioq_num(const OSSL_PRIOQ *pq);
int ossl_prioq_push(OSSL_PRIOQ *pq, OSSL_PRIOQ_NODE *n);
OSSL_PRIOQ_NODE *ossl_prioq_peek(const OSSL_PRIOQ *pq);
OSSL_PRIOQ_NODE *ossl_prioq_pop(OSSL_PRIOQ *pq);
OSSL_PRIOQ_NODE *ossl_prioq_remove(OSSL_PRIOQ *pq, OSSL_PRIOQ_NODE *n);
void ossl_prioq_pop_free(OSSL_PRIOQ *pq, void (*freefunc)(OSSL_PRIOQ_NODE *));

#endif
