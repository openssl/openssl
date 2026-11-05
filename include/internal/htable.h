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
#include <openssl/crypto.h>
#include <openssl/rand.h>
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
 *
 * When the peer chooses the keys, use DEFINE_HTABLE_KEYED_OF instead; see
 * the keyed tables section below. When the number of elements has no small
 * bound, use the growable table DEFINE_HTABLE_DYN_OF, also below.
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
 * hash instead to resist hash flooding: DEFINE_HTABLE_KEYED_OF below.
 */

static ossl_unused ossl_inline uint64_t ossl_hash_u64(uint64_t x)
{
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

static ossl_unused ossl_inline uint64_t ossl_hash_ptr(const void *ptr)
{
    return ossl_hash_u64((uint64_t)(uintptr_t)ptr);
}

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
 * defines the same table with a 128-bit key that
 * ossl_htable_<name>_init(ht, libctx) draws from the private DRBG, so init
 * can fail and returns 0 when it does, and generates
 *
 *     uint64_t ossl_htable_<name>_hash(const table *ht, const void *d, size_t len);
 *     uint64_t ossl_htable_<name>_hash_u64(const table *ht, uint64_t x);
 *
 * which are SipHash-2-4 under that key. The hash is bound to the table by
 * name at its definition: no function pointer is stored and every other
 * operation still takes the computed hash, exactly as for an unkeyed table.
 * OSSL_HTABLE_INIT cannot salt a table, so a keyed table is always
 * initialised at run time, and a table whose init failed must not be used.
 *
 *     DEFINE_QUEUE_OF(oid, OID_ENTRY);
 *     DEFINE_HTABLE_KEYED_OF(oid, OID_ENTRY, 6);
 *
 *     if (!ossl_htable_oid_init(&table, libctx))
 *         return 0;
 *     h = ossl_htable_oid_hash(&table, OBJ_get0_data(obj), OBJ_length(obj));
 *     OSSL_HTABLE_FIND(p, oid, &table, h, OBJ_cmp(p->obj, obj) == 0);
 */
#define OSSL_HTABLE_KEY_SIZE 16

#define DEFINE_HTABLE_KEYED_OF(name, type, bits)                             \
    OSSL_HTABLE_BITS_CHECK_(name, bits);                                     \
    typedef struct ossl_htable_##name##_st {                                 \
        OSSL_QUEUE buckets[(size_t)1 << (bits)];                             \
        size_t num; /* elements currently in the table */                    \
        unsigned char key[OSSL_HTABLE_KEY_SIZE]; /* drawn by _init() */      \
    } OSSL_HTABLE(name);                                                     \
    static ossl_unused ossl_inline int                                       \
    ossl_htable_##name##_init(OSSL_HTABLE(name) *ht, OSSL_LIB_CTX *libctx)   \
    {                                                                        \
        ossl_htable_init_buckets(ht->buckets, ossl_htable_num_buckets(ht));  \
        ht->num = 0;                                                         \
        return RAND_priv_bytes_ex(libctx, ht->key, sizeof(ht->key),          \
                   sizeof(ht->key) * 8)                                      \
            == 1;                                                            \
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
 *     ossl_htable_idx_add(&table, foo, ossl_hash_u64(foo->key));
 *     OSSL_HTABLE_FIND(p, idx, &table, ossl_hash_u64(key), p->key == key);
 *     ossl_htable_idx_del(&table, foo);
 *     ossl_htable_idx_cleanup(&table);         frees the grown buckets
 *
 * Every other operation of a static table works on a growable one. Since
 * the buckets may live in the table itself, a growable table must not be
 * copied or moved once initialised (the elements' links point
 * into the buckets anyway, for either kind of table), has no static
 * initialiser, and must be cleaned up with ossl_htable_<name>_cleanup().
 * ossl_htable_<name>_reserve(ht, n) grows the buckets up front for |n|
 * elements.
 */
#define OSSL_HTABLE_MEMBER(name)  \
    OSSL_QNODE ossl_queue_##name; \
    uint64_t ossl_htable_hash_##name

#define DEFINE_HTABLE_DYN_OF(name, type, min_bits, max_bits)                      \
    OSSL_HTABLE_BITS_CHECK_(name, max_bits);                                      \
    typedef char ossl_htable_##name##_min_bits_check                              \
        [(unsigned)(min_bits) <= (unsigned)(max_bits) ? 1 : -1];                  \
    typedef struct ossl_htable_##name##_st {                                      \
        OSSL_QUEUE *buckets; /* inline_buckets, or a grown heap array */          \
        size_t mask; /* number of buckets - 1 */                                  \
        size_t num; /* elements currently in the table */                         \
        OSSL_QUEUE inline_buckets[(size_t)1 << (min_bits)];                       \
    } OSSL_HTABLE(name);                                                          \
    static ossl_unused ossl_inline void                                           \
    ossl_htable_##name##_init(OSSL_HTABLE(name) *ht)                              \
    {                                                                             \
        ht->buckets = ht->inline_buckets;                                         \
        ht->mask = OSSL_NELEM(ht->inline_buckets) - 1;                            \
        ht->num = 0;                                                              \
        ossl_htable_init_buckets(ht->buckets, ht->mask + 1);                      \
    }                                                                             \
    /* Free the grown buckets; the table is empty and reusable afterwards. */     \
    static ossl_unused ossl_inline void                                           \
    ossl_htable_##name##_cleanup(OSSL_HTABLE(name) *ht)                           \
    {                                                                             \
        if (ht->buckets != ht->inline_buckets)                                    \
            OPENSSL_free(ht->buckets);                                            \
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
        return &ht->buckets[(size_t)hash & ht->mask];                             \
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
        OSSL_QUEUE *nb = OPENSSL_malloc_array(n, sizeof(*nb));                    \
        type *p, *pn;                                                             \
        size_t i;                                                                 \
                                                                                  \
        if (nb == NULL)                                                           \
            return 0;                                                             \
        ossl_htable_init_buckets(nb, n);                                          \
        for (i = 0; i <= ht->mask; i++)                                           \
            OSSL_QUEUE_FOREACH_DELSAFE (p, pn, name, &ht->buckets[i]) {           \
                /* The old buckets are discarded whole: no unlinking needed */    \
                ossl_queue_##name##_init_elem(p);                                 \
                ossl_queue_##name##_add(                                          \
                    &nb[(size_t)p->ossl_htable_hash_##name & (n - 1)], p);        \
            }                                                                     \
        if (ht->buckets != ht->inline_buckets)                                    \
            OPENSSL_free(ht->buckets);                                            \
        ht->buckets = nb;                                                         \
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
    /* Nothing to free: for symmetry with the growable tables. */ \
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

/*
 * One-shot SipHash-2-4 with a 64-bit result under the 128-bit key |k|, the
 * same function as SipHash_Init(ctx, k, 0, 0) with an 8-byte hash size.
 */
#define OSSL_HTABLE_SIPHASH_C_ROUNDS 2
#define OSSL_HTABLE_SIPHASH_D_ROUNDS 4

#define OSSL_HTABLE_ROTL_(x, b) (((x) << (b)) | ((x) >> (64 - (b))))
#define OSSL_HTABLE_SIPROUND_(v0, v1, v2, v3) \
    do {                                      \
        v0 += v1;                             \
        v1 = OSSL_HTABLE_ROTL_(v1, 13);       \
        v1 ^= v0;                             \
        v0 = OSSL_HTABLE_ROTL_(v0, 32);       \
        v2 += v3;                             \
        v3 = OSSL_HTABLE_ROTL_(v3, 16);       \
        v3 ^= v2;                             \
        v0 += v3;                             \
        v3 = OSSL_HTABLE_ROTL_(v3, 21);       \
        v3 ^= v0;                             \
        v2 += v1;                             \
        v1 = OSSL_HTABLE_ROTL_(v1, 17);       \
        v1 ^= v2;                             \
        v2 = OSSL_HTABLE_ROTL_(v2, 32);       \
    } while (0)

static ossl_unused ossl_inline uint64_t
ossl_htable_u8to64_le(const unsigned char *p)
{
    return (uint64_t)p[0] | (uint64_t)p[1] << 8 | (uint64_t)p[2] << 16
        | (uint64_t)p[3] << 24 | (uint64_t)p[4] << 32 | (uint64_t)p[5] << 40
        | (uint64_t)p[6] << 48 | (uint64_t)p[7] << 56;
}

static ossl_unused ossl_inline uint64_t
ossl_siphash24_u64(const unsigned char k[OSSL_HTABLE_KEY_SIZE],
    const void *data, size_t len)
{
    const unsigned char *in = data;
    const unsigned char *end = in + (len & ~(size_t)7);
    uint64_t k0 = ossl_htable_u8to64_le(k);
    uint64_t k1 = ossl_htable_u8to64_le(k + 8);
    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;
    uint64_t b = (uint64_t)len << 56, m;
    size_t i;

    for (; in != end; in += 8) {
        m = ossl_htable_u8to64_le(in);
        v3 ^= m;
        for (i = 0; i < OSSL_HTABLE_SIPHASH_C_ROUNDS; i++)
            OSSL_HTABLE_SIPROUND_(v0, v1, v2, v3);
        v0 ^= m;
    }
    for (i = 0; i < (len & 7); i++)
        b |= (uint64_t)in[i] << (8 * i);
    v3 ^= b;
    for (i = 0; i < OSSL_HTABLE_SIPHASH_C_ROUNDS; i++)
        OSSL_HTABLE_SIPROUND_(v0, v1, v2, v3);
    v0 ^= b;
    v2 ^= 0xff;
    for (i = 0; i < OSSL_HTABLE_SIPHASH_D_ROUNDS; i++)
        OSSL_HTABLE_SIPROUND_(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
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
            OSSL_QUEUE_FOREACH_DELSAFE (p, pn, name, &ht->buckets[i])           \
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

#endif /* OSSL_INTERNAL_HTABLE_H */
