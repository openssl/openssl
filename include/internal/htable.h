/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_HTABLE_H
#define OSSL_INTERNAL_HTABLE_H
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <openssl/e_os2.h>
#include "internal/nelem.h"
#include "internal/queue.h"

/*
 * A table is an array of 1 << bits OSSL_QUEUE buckets plus an entry gauge.
 * The number of buckets is fixed at compile time:
 * DEFINE_HTABLE_OF(name, type, bits) defines the type OSSL_HTABLE(name) as
 * the table of |type| elements linked through OSSL_QUEUE_MEMBER(name), with
 * 1 << bits buckets. A table lives wherever it is declared (a struct
 * member, a local, a static) and has no separate storage, so it never
 * allocates, never rehashes and has nothing to free; chains simply grow when
 * the table holds more elements than it has buckets. The caller passes the
 * (already computed) hash to every operation and the table masks it with
 * its compile-time bucket mask.
 *
 *     typedef struct foo_st { uint64_t key; OSSL_QUEUE_MEMBER(idx); } FOO;
 *     DEFINE_QUEUE_OF(idx, FOO);
 *     DEFINE_HTABLE_OF(idx, FOO, 10);          1024 buckets, 8 KB on LP64
 *
 *     OSSL_HTABLE(idx) table;                  or: static ... = OSSL_HTABLE_INIT;
 *     ossl_htable_idx_init(&table);
 *     ossl_htable_idx_add(&table, foo, ossl_hash_u64(foo->key));
 *     OSSL_HTABLE_FIND(p, idx, &table, ossl_hash_u64(key), p->key == key);
 *     ossl_htable_idx_del(&table, foo);
 */

/* The table type defined by DEFINE_HTABLE_OF(name, ...). */
#define OSSL_HTABLE(name) OSSL_HTABLE_##name

/* Sanity bound on |bits|: a table never has more than 1 << 30 buckets. */
#define OSSL_HTABLE_MAX_BITS 30

/* Static initialiser: every bucket empty and the gauge zero. */
#define OSSL_HTABLE_INIT { { OSSL_QUEUE_INIT }, 0 }

/*
 * Accessors valid for a pointer to any OSSL_HTABLE(name). The bucket count
 * and mask are compile-time constants of the table's type.
 */
#define ossl_htable_num_buckets(ht) OSSL_NELEM((ht)->buckets)
#define ossl_htable_mask(ht) ((uint64_t)ossl_htable_num_buckets(ht) - 1)
#define ossl_htable_bucket(ht, hash) \
    (&(ht)->buckets[(hash) & ossl_htable_mask(ht)])
#define ossl_htable_num(ht) ((ht)->num)
#define ossl_htable_is_empty(ht) ((ht)->num == 0)

/*
 * The table masks the hash with the bucket mask, so the low bits must be
 * well mixed. Sequence-like keys (stream IDs, packet numbers) distribute
 * perfectly by themselves and may be passed through unchanged; arbitrary
 * integers and pointers should go through ossl_hash_u64()/ossl_hash_ptr()
 * (the splitmix64 finaliser). Keys that an attacker controls need a keyed
 * hash (SipHash) instead to resist hash flooding.
 */
static ossl_inline uint64_t ossl_hash_u64(uint64_t x)
{
    x ^= x >> 30;
    x *= UINT64_C(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x *= UINT64_C(0x94d049bb133111eb);
    x ^= x >> 31;
    return x;
}

static ossl_inline uint64_t ossl_hash_ptr(const void *ptr)
{
    return ossl_hash_u64((uint64_t)(uintptr_t)ptr);
}

/*
 * Define OSSL_HTABLE(name), the table of 1 << |bits| buckets of |type|
 * elements linked through OSSL_QUEUE_MEMBER(name), and its operations. The
 * matching DEFINE_QUEUE_OF(name, type) must come first.
 */
#define DEFINE_HTABLE_OF(name, type, bits)                                   \
    typedef char ossl_htable_##name##_bits_check                             \
        [(unsigned)(bits) <= OSSL_HTABLE_MAX_BITS ? 1 : -1];                 \
    typedef struct ossl_htable_##name##_st {                                 \
        OSSL_QUEUE buckets[(size_t)1 << (bits)];                             \
        size_t num; /* elements currently in the table */                    \
    } OSSL_HTABLE(name);                                                     \
    static ossl_unused ossl_inline void                                      \
    ossl_htable_##name##_init(OSSL_HTABLE(name) *ht)                         \
    {                                                                        \
        for (size_t i = 0; i < ossl_htable_num_buckets(ht); i++)             \
            ossl_queue_init(&ht->buckets[i]);                                \
        ht->num = 0;                                                         \
    }                                                                        \
    static ossl_unused ossl_inline void                                      \
    ossl_htable_##name##_add(OSSL_HTABLE(name) *ht, type *el, uint64_t hash) \
    {                                                                        \
        ossl_queue_##name##_add(ossl_htable_bucket(ht, hash), el);           \
        ht->num++;                                                           \
    }                                                                        \
    static ossl_unused ossl_inline void                                      \
    ossl_htable_##name##_add_rcu(OSSL_HTABLE(name) *ht, type *el,            \
        uint64_t hash)                                                       \
    {                                                                        \
        ossl_queue_##name##_add_rcu(ossl_htable_bucket(ht, hash), el);       \
        ht->num++;                                                           \
    }                                                                        \
    static ossl_unused ossl_inline void                                      \
    ossl_htable_##name##_del(OSSL_HTABLE(name) *ht, type *el)                \
    {                                                                        \
        ossl_queue_##name##_del(el);                                         \
        ht->num--;                                                           \
    }                                                                        \
    static ossl_unused ossl_inline void                                      \
    ossl_htable_##name##_del_rcu(OSSL_HTABLE(name) *ht, type *el)            \
    {                                                                        \
        ossl_queue_##name##_del_rcu(el);                                     \
        ht->num--;                                                           \
    }                                                                        \
    /*                                                                       \
     * Recently-used-cache promotion: move |el| to the head of the bucket    \
     * for |hash| (which may differ from its current bucket if the key       \
     * changed). The entry count is unchanged.                               \
     */                                                                      \
    static ossl_unused ossl_inline void                                      \
    ossl_htable_##name##_ruc(OSSL_HTABLE(name) *ht, type *el, uint64_t hash) \
    {                                                                        \
        ossl_queue_##name##_del(el);                                         \
        ossl_queue_##name##_add(ossl_htable_bucket(ht, hash), el);           \
    }                                                                        \
    static ossl_unused ossl_inline type *                                    \
    ossl_htable_##name##_head(const OSSL_HTABLE(name) *ht, uint64_t hash)    \
    {                                                                        \
        return ossl_queue_##name##_head(ossl_htable_bucket(ht, hash));       \
    }                                                                        \
    static ossl_unused ossl_inline type *                                    \
    ossl_htable_##name##_head_rcu(OSSL_HTABLE(name) *ht, uint64_t hash)      \
    {                                                                        \
        return ossl_queue_##name##_head_rcu(ossl_htable_bucket(ht, hash));   \
    }                                                                        \
    /*                                                                       \
     * Visit every element. |fn| may remove the element it is handed but no  \
     * other one, and may not add elements.                                  \
     */                                                                      \
    static ossl_unused ossl_inline void                                      \
    ossl_htable_##name##_doall_arg(OSSL_HTABLE(name) *ht,                    \
        void (*fn)(type * el, void *arg), void *arg)                         \
    {                                                                        \
        type *p, *pn;                                                        \
        for (size_t i = 0; i < ossl_htable_num_buckets(ht); i++)             \
            OSSL_QUEUE_FOREACH_DELSAFE (p, pn, name, &ht->buckets[i])        \
                fn(p, arg);                                                  \
    }                                                                        \
    struct ossl_htable_dummy_st_##name

#define OSSL_HTABLE_FOREACH(p, name, ht, hash) \
    OSSL_QUEUE_FOREACH (p, name, ossl_htable_bucket((ht), (hash)))

#define OSSL_HTABLE_FOREACH_DELSAFE(p, pn, name, ht, hash) \
    OSSL_QUEUE_FOREACH_DELSAFE (p, pn, name, ossl_htable_bucket((ht), (hash)))

#define OSSL_HTABLE_FOREACH_RCU(p, name, ht, hash) \
    OSSL_QUEUE_FOREACH_RCU (p, name, ossl_htable_bucket((ht), (hash)))

/*
 * Search the bucket for |hash|, leaving in |p| the first element for which
 * |cond| (an expression over |p|) holds, or NULL.
 */
#define OSSL_HTABLE_FIND(p, name, ht, hash, cond) \
    do {                                          \
        OSSL_HTABLE_FOREACH (p, name, ht, hash)   \
            if (cond)                             \
                break;                            \
    } while (0)

#define OSSL_HTABLE_FIND_RCU(p, name, ht, hash, cond) \
    do {                                              \
        OSSL_HTABLE_FOREACH_RCU (p, name, ht, hash)   \
            if (cond)                                 \
                break;                                \
    } while (0)

#endif /* OSSL_INTERNAL_HTABLE_H */
