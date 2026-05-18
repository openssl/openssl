/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_PQ_H
#define OSSL_INTERNAL_PQ_H
#pragma once

#include <stddef.h>
#include <openssl/e_os2.h>
#include "internal/container_of.h"

/*
 * Intrusive binary-heap priority queue.
 *
 * Each element embeds an OSSL_PQ_NODE; the queue stores pointers to those
 * nodes and tracks each element's current heap position inside the node
 * itself.  No void* casts in the API, no per-type wrapper macros, no
 * parallel handle table.
 *
 *     typedef struct foo_st {
 *         uint64_t     key;
 *         OSSL_PQ_NODE pqn;
 *         ...
 *     } FOO;
 *
 *     static int foo_cmp(const OSSL_PQ_NODE *a, const OSSL_PQ_NODE *b)
 *     {
 *         const FOO *fa = CONTAINER_OF(a, FOO, pqn);
 *         const FOO *fb = CONTAINER_OF(b, FOO, pqn);
 *         return fa->key < fb->key ? -1 : fa->key > fb->key;
 *     }
 *
 *     OSSL_PQ *pq = ossl_pq_new(foo_cmp);
 *     ossl_pq_node_init(&foo->pqn);
 *     ossl_pq_push(pq, &foo->pqn);
 *     ...
 *     OSSL_PQ_NODE *n = ossl_pq_pop(pq);
 *     FOO *got = CONTAINER_OF(n, FOO, pqn);
 *
 * An element may belong to at most one queue at a time.  Re-pushing a node
 * that is already enqueued is a programming error (asserted in debug builds).
 */

#define OSSL_PQ_NOT_IN_QUEUE ((size_t)-1)

typedef struct ossl_pq_node_st {
    size_t posn; /* index in heap[]; OSSL_PQ_NOT_IN_QUEUE if detached */
} OSSL_PQ_NODE;

typedef struct ossl_pq_st OSSL_PQ;

static ossl_unused ossl_inline void ossl_pq_node_init(OSSL_PQ_NODE *n)
{
    n->posn = OSSL_PQ_NOT_IN_QUEUE;
}

static ossl_unused ossl_inline int ossl_pq_node_in_queue(const OSSL_PQ_NODE *n)
{
    return n->posn != OSSL_PQ_NOT_IN_QUEUE;
}

OSSL_PQ *ossl_pq_new(int (*cmp)(const OSSL_PQ_NODE *, const OSSL_PQ_NODE *));
void ossl_pq_free(OSSL_PQ *pq);
int ossl_pq_reserve(OSSL_PQ *pq, size_t n);
size_t ossl_pq_num(const OSSL_PQ *pq);
int ossl_pq_push(OSSL_PQ *pq, OSSL_PQ_NODE *n);
OSSL_PQ_NODE *ossl_pq_peek(const OSSL_PQ *pq);
OSSL_PQ_NODE *ossl_pq_pop(OSSL_PQ *pq);
OSSL_PQ_NODE *ossl_pq_remove(OSSL_PQ *pq, OSSL_PQ_NODE *n);
void ossl_pq_pop_free(OSSL_PQ *pq, void (*freefunc)(OSSL_PQ_NODE *));

#endif
