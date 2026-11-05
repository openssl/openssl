/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_HTABLE_RCU_H
#define OSSL_INTERNAL_HTABLE_RCU_H
#pragma once

#include "internal/htable.h"
#include "internal/rcu.h"

/*
 * Lock-free readers for an insert-only OSSL_HTABLE.
 *
 * DEFINE_HTABLE_RCU_OF(name, type), placed after the DEFINE_HTABLE_OF or
 * DEFINE_HTABLE_KEYED_OF of the same name, adds
 *
 *     void ossl_htable_<name>_add_rcu(table *ht, type *el, uint64_t hash);
 *     OSSL_HTABLE_FOREACH_RCU(p, name, ht, hash)
 *     OSSL_HTABLE_FIND_RCU(p, name, ht, hash, cond)
 *
 * _add_rcu() publishes an element: it links the fully initialised element
 * and then stores the bucket head with release semantics, so a reader that
 * sees the element sees everything written to it beforehand. The two reader
 * macros load the head and each link with acquire semantics. Readers take no
 * lock and need no ossl_rcu_read_lock().
 *
 * The rules that make this safe:
 *
 * - Writers serialise among themselves (the caller's lock). Readers never
 *   block and never retry.
 * - Elements are only ever added. While a reader may be running, an element
 *   must not be removed, moved (_del, _ruc) or freed, and the fields the
 *   readers' |cond| looks at must not change after _add_rcu(). There is
 *   therefore no grace period to wait for; the elements are freed when the
 *   table's owner is, once no reader can exist.
 * - The table is of the fixed-size kind. A growable table re-links its
 *   elements when it grows, which would lead a concurrent reader into the
 *   wrong chain, so DEFINE_HTABLE_RCU_OF does not compile for a table
 *   defined with DEFINE_HTABLE_DYN_OF.
 * - The entry gauge (ossl_htable_num()) and every non-_rcu operation belong
 *   to the writer side and need the writers' lock.
 *
 *     typedef struct foo_st { uint64_t key; OSSL_QUEUE_MEMBER(idx); } FOO;
 *     DEFINE_QUEUE_OF(idx, FOO);
 *     DEFINE_HTABLE_OF(idx, FOO, 10);
 *     DEFINE_HTABLE_RCU_OF(idx, FOO);
 *
 *     writer, under its lock:
 *         foo->key = key;
 *         ossl_htable_idx_add_rcu(&table, foo, ossl_hash_mix64(key));
 *     reader, no lock:
 *         OSSL_HTABLE_FIND_RCU(p, idx, &table, ossl_hash_mix64(key),
 *             p->key == key);
 *
 * The ossl_rcu_*() primitives are internal to libcrypto, so this header is
 * for libcrypto and the FIPS module only; libssl cannot link against them.
 */

/* Publish |n| at the head of |q|. Writer side. */
static ossl_unused ossl_inline void ossl_queue_add_head_rcu(OSSL_QUEUE *q,
    OSSL_QNODE *n)
{
    OSSL_QNODE *head = q->head;

    assert(!ossl_qnode_hashed(n));
    n->next = head;
    n->prev = &q->head;
    /* |prev| is never followed by a reader */
    if (head != NULL)
        head->prev = &n->next;
    ossl_rcu_assign_ptr(&q->head, &n);
}

/* The first node of |q|, for a reader. */
static ossl_unused ossl_inline OSSL_QNODE *
ossl_queue_head_rcu(const OSSL_QUEUE *q)
{
    return ossl_rcu_deref(&((OSSL_QUEUE *)q)->head);
}

/* The node after |n|, for a reader. */
static ossl_unused ossl_inline OSSL_QNODE *
ossl_qnode_next_rcu(const OSSL_QNODE *n)
{
    return ossl_rcu_deref(&((OSSL_QNODE *)n)->next);
}

#define DEFINE_HTABLE_RCU_OF(name, type)                                    \
    /* Only a fixed-size table defines this type; see above. */             \
    typedef ossl_htable_##name##_fixed_size ossl_htable_##name##_rcu_check; \
    static ossl_unused ossl_inline void                                     \
    ossl_htable_##name##_add_rcu(OSSL_HTABLE(name) *ht, type *el,           \
        uint64_t hash)                                                      \
    {                                                                       \
        ossl_queue_add_head_rcu(ossl_htable_##name##_bucket(ht, hash),      \
            &el->ossl_queue_##name);                                        \
        ht->num++;                                                          \
    }                                                                       \
    static ossl_unused ossl_inline type *                                   \
    ossl_htable_##name##_head_rcu(const OSSL_HTABLE(name) *ht,              \
        uint64_t hash)                                                      \
    {                                                                       \
        return ossl_queue_##name##_entry(                                   \
            ossl_queue_head_rcu(ossl_htable_##name##_bucket(ht, hash)));    \
    }                                                                       \
    static ossl_unused ossl_inline type *                                   \
    ossl_htable_##name##_next_rcu(const type *el)                           \
    {                                                                       \
        return ossl_queue_##name##_entry(                                   \
            ossl_qnode_next_rcu(&el->ossl_queue_##name));                   \
    }                                                                       \
    struct ossl_htable_rcu_dummy_st_##name

#define OSSL_HTABLE_FOREACH_RCU(p, name, ht, hash)                       \
    for ((p) = ossl_htable_##name##_head_rcu((ht), (hash)); (p) != NULL; \
        (p) = ossl_htable_##name##_next_rcu(p))

/*
 * As OSSL_HTABLE_FIND, for a reader: leaves in |p| the first element of the
 * bucket for |hash| for which |cond| holds, or NULL.
 */
#define OSSL_HTABLE_FIND_RCU(p, name, ht, hash, cond)                 \
    do {                                                              \
        const uint64_t ossl_htable_find_hash_ = (hash);               \
                                                                      \
        OSSL_HTABLE_FOREACH_RCU (p, name, ht, ossl_htable_find_hash_) \
            if (cond)                                                 \
                break;                                                \
    } while (0)

#endif /* OSSL_INTERNAL_HTABLE_RCU_H */
