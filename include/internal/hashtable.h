/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_HASHTABLE_H
#define OSSL_INTERNAL_HASHTABLE_H
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <openssl/e_os2.h>
#include <openssl/crypto.h>
#include "internal/nelem.h"
#include "internal/hashfunc.h"
#include "internal/queue.h"
#include "internal/rcu.h"
#include "internal/threads_common.h"

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
 *     OSSL_HTABLE(idx) table;                  or static, = OSSL_HTABLE_INIT
 *     ossl_htable_idx_init(&table);
 *     ossl_queue_idx_init_elem(foo);           unless foo was zeroed
 *     ossl_htable_idx_add(&table, foo, ossl_hash_mix64(foo->key));
 *     OSSL_HTABLE_FIND(p, idx, &table, ossl_hash_mix64(key), p->key == key);
 *     ossl_htable_idx_del(&table, foo);
 *
 * When the peer chooses the keys, use DEFINE_HTABLE_KEYED_OF instead; see
 * the keyed tables section below. When the number of elements has no small
 * bound, use the growable table DEFINE_HTABLE_DYN_OF, also below. Nothing
 * here synchronises: the caller's lock covers every operation. For an
 * insert-only table read without a lock, see DEFINE_HTABLE_RCU_OF, the last
 * section below.
 *
 * Elements. An element's link records whether the element is in a table, so
 * it must be clear before the element is added for the first time: the
 * element comes from OPENSSL_zalloc() or from static storage, or
 * ossl_queue_<name>_init_elem() is called on it. Adding asserts that the
 * link is clear, and so reads it: over uninitialised memory a debug build
 * may abort, and a release build, which has no assertion, hides the mistake.
 * _del() clears the link again, so an element taken out of a table can be
 * added straight back.
 *
 * Cleanup. ossl_htable_<name>_cleanup() ends the use of a table of any kind.
 * It frees what the table allocated, which is nothing but the grown buckets
 * of a growable table, and it never looks at the elements, so they may have
 * been freed already. It does not unlink them either: an element that was
 * still in the table is left with a link into buckets that are gone. Such an
 * element must not be given to _del(), _del_init() or _ruc(), which write
 * through that link; it is freed, or cleared with
 * ossl_queue_<name>_init_elem() before it is added to a table again. To use
 * the table itself again, _init() it first.
 */

/* The table type defined by DEFINE_HTABLE_OF(name, ...). */
#define OSSL_HTABLE(name) OSSL_HTABLE_##name

/* Sanity bound on |bits|: a table never has more than 1 << 30 buckets. */
#define OSSL_HTABLE_MAX_BITS 30

/* Static initialiser: every bucket empty and the gauge zero. */
#define OSSL_HTABLE_INIT { { OSSL_QUEUE_INIT }, 0 }

/* The entry gauge, for a pointer to a table of any kind. */
#define ossl_htable_num(ht) ((ht)->num)
#define ossl_htable_is_empty(ht) ((ht)->num == 0)

/*
 * The buckets of a static table (DEFINE_HTABLE_OF, DEFINE_HTABLE_KEYED_OF),
 * whose count and mask are compile-time constants of the table's type. A
 * growable table keeps them at run time and has no |buckets| member, so
 * these three do not compile for one. ossl_htable_<name>_num_buckets() and
 * ossl_htable_<name>_bucket() are defined for every kind of table.
 */
#define ossl_htable_num_buckets(ht) OSSL_NELEM((ht)->buckets)
#define ossl_htable_mask(ht) ((uint64_t)ossl_htable_num_buckets(ht) - 1)
#define ossl_htable_bucket(ht, hash) \
    (&(ht)->buckets[(hash) & ossl_htable_mask(ht)])

/*
 * The table masks the hash with the bucket mask, so the low bits must be
 * well mixed. Sequence-like keys (stream IDs, packet numbers) distribute
 * perfectly by themselves and may be passed through unchanged; arbitrary
 * integers and pointers should go through ossl_hash_mix64()/ossl_hash_ptr()
 * (the splitmix64 finaliser, internal/hashfunc.h). Keys that an attacker
 * controls need a keyed hash instead to resist hash flooding:
 * DEFINE_HTABLE_KEYED_OF below.
 */

/*
 * Define OSSL_HTABLE(name), the table of 1 << |bits| buckets of |type|
 * elements linked through OSSL_QUEUE_MEMBER(name), and its operations. The
 * matching DEFINE_QUEUE_OF(name, type) must come first.
 */
#define DEFINE_HTABLE_OF(name, type, bits)                                  \
    OSSL_HTABLE_BITS_CHECK_(name, bits);                                    \
    typedef struct ossl_htable_##name##_st {                                \
        OSSL_QUEUE buckets[(size_t)1 << (bits)];                            \
        size_t num; /* elements currently in the table */                   \
    } OSSL_HTABLE(name);                                                    \
    static ossl_unused ossl_inline void                                     \
    ossl_htable_##name##_init(OSSL_HTABLE(name) *ht)                        \
    {                                                                       \
        ossl_htable_init_buckets(ht->buckets, ossl_htable_num_buckets(ht)); \
        ht->num = 0;                                                        \
    }                                                                       \
    OSSL_HTABLE_DEFINE_STATIC_ACCESS_(name, type)                           \
    OSSL_HTABLE_DEFINE_OPS_(name, type)                                     \
    struct ossl_htable_dummy_st_##name

/*
 * Keyed tables, for keys the peer chooses.
 *
 * An unkeyed hash over wire data (the OIDs of a certificate's extensions, a
 * peer address, a connection ID) lets the sender precompute keys that share
 * a bucket and turn every lookup into a chain walk. DEFINE_HTABLE_KEYED_OF
 * defines the same table with a 128-bit key, which
 * ossl_htable_<name>_init(ht, key) copies from the caller, and generates
 *
 *     uint64_t ossl_htable_<name>_hash(const table *ht, const void *data,
 *                                      size_t len);
 *     uint64_t ossl_htable_<name>_hash_u64(const table *ht, uint64_t x);
 *
 * which are SipHash-2-4 under that key (ossl_siphash24_u64() of
 * internal/hashfunc.h). The hash is bound to the table by
 * name at its definition: no function pointer is stored and every other
 * operation still takes the computed hash, exactly as for an unkeyed table.
 * OSSL_HTABLE_INIT cannot key a table, so a keyed table is always
 * initialised at run time.
 *
 * The caller draws the key, a new one for each table. It has to be
 * unpredictable to the peer, not secret, and where it comes from depends on
 * the library the table is in. libcrypto uses ossl_rand_hash_salt()
 * (crypto/rand.h), which has other sources to fall back on in a library
 * context without a usable RAND, such as one with only the null provider:
 * a certificate must not become invalid there because a table could not be
 * keyed. That function is not available to libssl and the FIPS module,
 * which use RAND_bytes_ex().
 *
 *     DEFINE_QUEUE_OF(oid, OID_ENTRY);
 *     DEFINE_HTABLE_KEYED_OF(oid, OID_ENTRY, 6);
 *
 *     unsigned char key[OSSL_HTABLE_KEY_SIZE];
 *
 *     if (!ossl_rand_hash_salt(libctx, key, sizeof(key)))
 *         return 0;
 *     ossl_htable_oid_init(&table, key);
 *     h = ossl_htable_oid_hash(&table, OBJ_get0_data(obj), OBJ_length(obj));
 *     OSSL_HTABLE_FIND(p, oid, &table, h, OBJ_cmp(p->obj, obj) == 0);
 */
#define OSSL_HTABLE_KEY_SIZE OSSL_SIPHASH24_KEY_SIZE

#define DEFINE_HTABLE_KEYED_OF(name, type, bits)                             \
    OSSL_HTABLE_BITS_CHECK_(name, bits);                                     \
    typedef struct ossl_htable_##name##_st {                                 \
        OSSL_QUEUE buckets[(size_t)1 << (bits)];                             \
        size_t num; /* elements currently in the table */                    \
        unsigned char key[OSSL_HTABLE_KEY_SIZE]; /* set by _init() */        \
    } OSSL_HTABLE(name);                                                     \
    static ossl_unused ossl_inline void                                      \
    ossl_htable_##name##_init(OSSL_HTABLE(name) *ht,                         \
        const unsigned char key[OSSL_HTABLE_KEY_SIZE])                       \
    {                                                                        \
        ossl_htable_init_buckets(ht->buckets, ossl_htable_num_buckets(ht));  \
        ht->num = 0;                                                         \
        memcpy(ht->key, key, sizeof(ht->key));                               \
    }                                                                        \
    static ossl_unused ossl_inline uint64_t                                  \
    ossl_htable_##name##_hash(const OSSL_HTABLE(name) *ht, const void *data, \
        size_t len)                                                          \
    {                                                                        \
        return ossl_siphash24_u64(ht->key, data, len);                       \
    }                                                                        \
    static ossl_unused ossl_inline uint64_t                                  \
    ossl_htable_##name##_hash_u64(const OSSL_HTABLE(name) *ht, uint64_t x)   \
    {                                                                        \
        unsigned char b[8];                                                  \
        size_t i;                                                            \
                                                                             \
        for (i = 0; i < sizeof(b); i++)                                      \
            b[i] = (unsigned char)(x >> (8 * i));                            \
        return ossl_siphash24_u64(ht->key, b, sizeof(b));                    \
    }                                                                        \
    OSSL_HTABLE_DEFINE_STATIC_ACCESS_(name, type)                            \
    OSSL_HTABLE_DEFINE_OPS_(name, type)                                      \
    struct ossl_htable_dummy_st_##name

/*
 * Growable tables.
 *
 * DEFINE_HTABLE_DYN_OF(name, type, min_bits, max_bits) defines
 * OSSL_HTABLE(name) as a table that starts with 1 << min_bits buckets held
 * in the table itself, and doubles its buckets, up to 1 << max_bits, as soon
 * as it holds more elements than it has buckets, so chains stay short
 * whatever the number of elements. Growing allocates the new bucket array;
 * when that fails the table keeps its buckets and its longer chains and
 * tries again at the next add, so add still cannot fail. The table never
 * shrinks.
 *
 * The element embeds OSSL_HTABLE_MEMBER(name) instead of
 * OSSL_QUEUE_MEMBER(name): the link plus the hash the element was added
 * under. Growing re-links the elements by that stored hash without hashing
 * them again, and OSSL_HTABLE_FIND compares it before evaluating |cond|, so
 * a lookup only compares the keys of elements whose full 64-bit hash
 * matches. Keep the member next to the key in the element so that both
 * share a cache line.
 *
 *     typedef struct foo_st { OSSL_HTABLE_MEMBER(idx); uint64_t key; } FOO;
 *     DEFINE_QUEUE_OF(idx, FOO);
 *     DEFINE_HTABLE_DYN_OF(idx, FOO, 4, 20);   16 buckets inline, up to 1M
 *
 *     ossl_htable_idx_init(&table);
 *     ossl_queue_idx_init_elem(foo);           unless foo was zeroed
 *     ossl_htable_idx_add(&table, foo, ossl_hash_mix64(foo->key));
 *     OSSL_HTABLE_FIND(p, idx, &table, ossl_hash_mix64(key), p->key == key);
 *     ossl_htable_idx_del(&table, foo);
 *     ossl_htable_idx_cleanup(&table);         frees the grown buckets
 *
 * Every per-name operation and macro of a static table works on a growable
 * one; ossl_htable_num_buckets(), ossl_htable_mask() and ossl_htable_bucket()
 * above, which read the bucket count off a static table's type, do not
 * compile for it. Since the buckets may live in the table itself, a growable
 * table must not be copied or moved once initialised (the elements' links
 * point into the buckets anyway, for either kind of table), has no static
 * initialiser, and must be cleaned up with ossl_htable_<name>_cleanup(),
 * which leaves the elements linked: see "Cleanup" above.
 * ossl_htable_<name>_reserve(ht, n) grows the buckets up front for |n|
 * elements.
 */
#define OSSL_HTABLE_MEMBER(name)  \
    OSSL_QNODE ossl_queue_##name; \
    uint64_t ossl_htable_hash_##name

/*
 * The current buckets are |dyn_buckets|, not |buckets|, to keep the static
 * tables' accessors, which take OSSL_NELEM() of |buckets|, from compiling.
 */
#define DEFINE_HTABLE_DYN_OF(name, type, min_bits, max_bits)                      \
    OSSL_HTABLE_BITS_CHECK_(name, max_bits);                                      \
    typedef char ossl_htable_##name##_min_bits_check                              \
        [(unsigned)(min_bits) <= (unsigned)(max_bits) ? 1 : -1];                  \
    typedef struct ossl_htable_##name##_st {                                      \
        OSSL_QUEUE *dyn_buckets; /* inline_buckets, or a grown heap array */      \
        size_t mask; /* number of buckets - 1 */                                  \
        size_t num; /* elements currently in the table */                         \
        OSSL_QUEUE inline_buckets[(size_t)1 << (min_bits)];                       \
    } OSSL_HTABLE(name);                                                          \
    static ossl_unused ossl_inline void                                           \
    ossl_htable_##name##_init(OSSL_HTABLE(name) *ht)                              \
    {                                                                             \
        ht->dyn_buckets = ht->inline_buckets;                                     \
        ht->mask = OSSL_NELEM(ht->inline_buckets) - 1;                            \
        ht->num = 0;                                                              \
        ossl_htable_init_buckets(ht->dyn_buckets, ht->mask + 1);                  \
    }                                                                             \
    /*                                                                            \
     * Free the grown buckets. The elements are neither visited nor unlinked:     \
     * see "Cleanup" above. The table is left as _init() leaves it, so that a     \
     * second cleanup is harmless.                                                \
     */                                                                           \
    static ossl_unused ossl_inline void                                           \
    ossl_htable_##name##_cleanup(OSSL_HTABLE(name) *ht)                           \
    {                                                                             \
        if (ht->dyn_buckets != ht->inline_buckets)                                \
            OPENSSL_free(ht->dyn_buckets);                                        \
        ossl_htable_##name##_init(ht);                                            \
    }                                                                             \
    static ossl_unused ossl_inline size_t                                         \
    ossl_htable_##name##_num_buckets(const OSSL_HTABLE(name) *ht)                 \
    {                                                                             \
        return ht->mask + 1;                                                      \
    }                                                                             \
    static ossl_unused ossl_inline OSSL_QUEUE *                                   \
    ossl_htable_##name##_bucket(const OSSL_HTABLE(name) *ht, uint64_t hash)       \
    {                                                                             \
        return &ht->dyn_buckets[(size_t)hash & ht->mask];                         \
    }                                                                             \
    static ossl_unused ossl_inline uint64_t                                       \
    ossl_htable_##name##_hash_of(const type *el)                                  \
    {                                                                             \
        return el->ossl_htable_hash_##name;                                       \
    }                                                                             \
    static ossl_unused ossl_inline int                                            \
    ossl_htable_##name##_hash_eq(const type *el, uint64_t hash)                   \
    {                                                                             \
        return el->ossl_htable_hash_##name == hash;                               \
    }                                                                             \
    /* Re-link every element into |n| buckets by its stored hash. */              \
    static ossl_unused int                                                        \
    ossl_htable_##name##_resize_(OSSL_HTABLE(name) *ht, size_t n)                 \
    {                                                                             \
        OSSL_QUEUE *nb;                                                           \
        type *p, *pn;                                                             \
        size_t i;                                                                 \
                                                                                  \
        /*                                                                        \
         * Growing is best effort, so a failure here is not an error of the       \
         * operation that asked for it: no file and line, nothing is raised.      \
         */                                                                       \
        nb = CRYPTO_malloc_array(n, sizeof(*nb), NULL, 0);                        \
        if (nb == NULL)                                                           \
            return 0;                                                             \
        ossl_htable_init_buckets(nb, n);                                          \
        for (i = 0; i <= ht->mask; i++)                                           \
            OSSL_QUEUE_FOREACH_DELSAFE (p, pn, name, &ht->dyn_buckets[i]) {       \
                /* The old buckets are discarded whole: no unlinking needed */    \
                ossl_queue_##name##_init_elem(p);                                 \
                ossl_queue_##name##_add(                                          \
                    &nb[(size_t)p->ossl_htable_hash_##name & (n - 1)], p);        \
            }                                                                     \
        if (ht->dyn_buckets != ht->inline_buckets)                                \
            OPENSSL_free(ht->dyn_buckets);                                        \
        ht->dyn_buckets = nb;                                                     \
        ht->mask = n - 1;                                                         \
        return 1;                                                                 \
    }                                                                             \
    /*                                                                            \
     * Grow the buckets for |n| elements at one per bucket, within max_bits.      \
     * Returns 0 if the allocation failed, the table being unchanged.             \
     */                                                                           \
    static ossl_unused ossl_inline int                                            \
    ossl_htable_##name##_reserve(OSSL_HTABLE(name) *ht, size_t n)                 \
    {                                                                             \
        size_t nb = ht->mask + 1;                                                 \
                                                                                  \
        while (nb < n && nb < ((size_t)1 << (max_bits)))                          \
            nb <<= 1;                                                             \
        return nb == ht->mask + 1 || ossl_htable_##name##_resize_(ht, nb);        \
    }                                                                             \
    static ossl_unused ossl_inline void                                           \
    ossl_htable_##name##_add(OSSL_HTABLE(name) *ht, type *el, uint64_t hash)      \
    {                                                                             \
        el->ossl_htable_hash_##name = hash;                                       \
        ossl_queue_##name##_add(ossl_htable_##name##_bucket(ht, hash), el);       \
        if (++ht->num > ht->mask + 1 && ht->mask < ((size_t)1 << (max_bits)) - 1) \
            (void)ossl_htable_##name##_resize_(ht, (ht->mask + 1) * 2);           \
    }                                                                             \
    static ossl_unused ossl_inline void                                           \
    ossl_htable_##name##_del(OSSL_HTABLE(name) *ht, type *el)                     \
    {                                                                             \
        ossl_queue_##name##_del(el);                                              \
        ht->num--;                                                                \
    }                                                                             \
    /* As for a static table; |hash| becomes the element's stored hash. */        \
    static ossl_unused ossl_inline void                                           \
    ossl_htable_##name##_ruc(OSSL_HTABLE(name) *ht, type *el, uint64_t hash)      \
    {                                                                             \
        ossl_queue_##name##_del(el);                                              \
        el->ossl_htable_hash_##name = hash;                                       \
        ossl_queue_##name##_add(ossl_htable_##name##_bucket(ht, hash), el);       \
    }                                                                             \
    OSSL_HTABLE_DEFINE_COMMON_OPS_(name, type)                                    \
    struct ossl_htable_dummy_st_##name

/* Implementation details shared by the table definitions. */

#define OSSL_HTABLE_BITS_CHECK_(name, bits)      \
    typedef char ossl_htable_##name##_bits_check \
        [(unsigned)(bits) <= OSSL_HTABLE_MAX_BITS ? 1 : -1]

/*
 * The per-name accessors of a static table, which the macros below use so
 * that they work on either kind. A static table stores no hashes, so
 * _hash_eq() lets every element through to the caller's comparison.
 */
#define OSSL_HTABLE_DEFINE_STATIC_ACCESS_(name, type)             \
    /* Marks a table that never re-links: DEFINE_HTABLE_RCU_OF */ \
    typedef char ossl_htable_##name##_fixed_size;                 \
    static ossl_unused ossl_inline size_t                         \
    ossl_htable_##name##_num_buckets(const OSSL_HTABLE(name) *ht) \
    {                                                             \
        return ossl_htable_num_buckets(ht);                       \
    }                                                             \
    static ossl_unused ossl_inline OSSL_QUEUE *                   \
    ossl_htable_##name##_bucket(const OSSL_HTABLE(name) *ht,      \
        uint64_t hash)                                            \
    {                                                             \
        return (OSSL_QUEUE *)ossl_htable_bucket(ht, hash);        \
    }                                                             \
    static ossl_unused ossl_inline int                            \
    ossl_htable_##name##_hash_eq(const type *el, uint64_t hash)   \
    {                                                             \
        (void)el;                                                 \
        (void)hash;                                               \
        return 1;                                                 \
    }                                                             \
    /* Nothing to free. Same contract as for a growable table. */ \
    static ossl_unused ossl_inline void                           \
    ossl_htable_##name##_cleanup(OSSL_HTABLE(name) *ht)           \
    {                                                             \
        (void)ht;                                                 \
    }

static ossl_unused ossl_inline void
ossl_htable_init_buckets(OSSL_QUEUE *buckets, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        ossl_queue_init(&buckets[i]);
}

#define OSSL_HTABLE_DEFINE_OPS_(name, type)                                  \
    static ossl_unused ossl_inline void                                      \
    ossl_htable_##name##_add(OSSL_HTABLE(name) *ht, type *el, uint64_t hash) \
    {                                                                        \
        ossl_queue_##name##_add(ossl_htable_bucket(ht, hash), el);           \
        ht->num++;                                                           \
    }                                                                        \
    static ossl_unused ossl_inline void                                      \
    ossl_htable_##name##_del(OSSL_HTABLE(name) *ht, type *el)                \
    {                                                                        \
        ossl_queue_##name##_del(el);                                         \
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
    OSSL_HTABLE_DEFINE_COMMON_OPS_(name, type)

/* The operations that are the same for static and growable tables. */
#define OSSL_HTABLE_DEFINE_COMMON_OPS_(name, type)                              \
    static ossl_unused ossl_inline type *                                       \
    ossl_htable_##name##_head(const OSSL_HTABLE(name) *ht, uint64_t hash)       \
    {                                                                           \
        return ossl_queue_##name##_head(ossl_htable_##name##_bucket(ht, hash)); \
    }                                                                           \
    /*                                                                          \
     * Visit every element. |fn| may remove the element it is handed but no     \
     * other one, and may not add elements.                                     \
     */                                                                         \
    static ossl_unused ossl_inline void                                         \
    ossl_htable_##name##_doall_arg(OSSL_HTABLE(name) *ht,                       \
        void (*fn)(type * el, void *arg), void *arg)                            \
    {                                                                           \
        type *p, *pn;                                                           \
        size_t i, n = ossl_htable_##name##_num_buckets(ht);                     \
                                                                                \
        for (i = 0; i < n; i++)                                                 \
            OSSL_QUEUE_FOREACH_DELSAFE (p, pn, name,                            \
                ossl_htable_##name##_bucket(ht, i))                             \
                fn(p, arg);                                                     \
    }

#define OSSL_HTABLE_FOREACH(p, name, ht, hash) \
    OSSL_QUEUE_FOREACH (p, name, ossl_htable_##name##_bucket((ht), (hash)))

#define OSSL_HTABLE_FOREACH_DELSAFE(p, pn, name, ht, hash) \
    OSSL_QUEUE_FOREACH_DELSAFE (p, pn, name,               \
        ossl_htable_##name##_bucket((ht), (hash)))

/*
 * Search the bucket for |hash|, leaving in |p| the first element for which
 * |cond| (an expression over |p|) holds, or NULL. |hash| is evaluated once.
 * In a growable table |cond| is only evaluated for the elements stored under
 * the same |hash|.
 */
#define OSSL_HTABLE_FIND(p, name, ht, hash, cond)                       \
    do {                                                                \
        const uint64_t ossl_htable_find_hash_ = (hash);                 \
                                                                        \
        OSSL_HTABLE_FOREACH (p, name, ht, ossl_htable_find_hash_)       \
            if (ossl_htable_##name##_hash_eq(p, ossl_htable_find_hash_) \
                && (cond))                                              \
                break;                                                  \
    } while (0)

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
 *         ossl_queue_idx_init_elem(foo);       unless foo was zeroed
 *         foo->key = key;
 *         ossl_htable_idx_add_rcu(&table, foo, ossl_hash_mix64(key));
 *     reader, no lock:
 *         OSSL_HTABLE_FIND_RCU(p, idx, &table, ossl_hash_mix64(key),
 *             p->key == key);
 *
 * The ossl_rcu_*() primitives are internal to libcrypto, so this section is
 * for libcrypto and the FIPS module only; libssl cannot link against them.
 */

/*
 * A reader's load of a published link. ossl_rcu_deref() is a function call
 * around one load; where that load is the compiler's own atomic (the same
 * condition under which crypto/threads_pthread.c uses it), do it in place.
 */
#if defined(OSSL_USE_GCC_ATOMICS)
#define ossl_htable_rcu_load_(pp) __atomic_load_n((pp), __ATOMIC_ACQUIRE)
#else
#define ossl_htable_rcu_load_(pp) ((OSSL_QNODE *)ossl_rcu_deref(pp))
#endif

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
    return ossl_htable_rcu_load_(&((OSSL_QUEUE *)q)->head);
}

/* The node after |n|, for a reader. */
static ossl_unused ossl_inline OSSL_QNODE *
ossl_qnode_next_rcu(const OSSL_QNODE *n)
{
    return ossl_htable_rcu_load_(&((OSSL_QNODE *)n)->next);
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

#endif /* OSSL_INTERNAL_HASHTABLE_H */
