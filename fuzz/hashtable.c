/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * Fuzz the intrusive hash tables of internal/hashtable.h.
 *
 * The same elements go into four tables, one of each kind: a static table
 * (DEFINE_HTABLE_OF), a keyed one (DEFINE_HTABLE_KEYED_OF), a growable one
 * (DEFINE_HTABLE_DYN_OF), and a static one that is added to and read through
 * the lock-free interface (DEFINE_HTABLE_RCU_OF). An element has a link for
 * each table, so it can be in any number of them at a time. A model records
 * which tables an element is in and under which hash, and the tables are
 * checked against it as the operations go.
 *
 * The input is a sequence of 11-byte records. The fuzzer of the ossl_ht hash
 * table, which this one replaces, took one such record per input, so its
 * corpus applies here:
 *
 *   u8   the operation in the low six bits, modulo OP_END, and FLAG_ALT
 *   u16  little endian: the element in the low eight bits; in bits 8 to 11
 *        the tables to work on, all four if none of them is set; in bits 12
 *        to 15 how many more of the elements that follow it to work on
 *   u64  little endian: the hash to add or look up under, or an argument
 *
 * An operation on several elements takes them under consecutive hashes, so
 * a few records are enough to fill the tables well beyond their buckets.
 *
 * The tables are empty at the start of every input and emptied at its end,
 * so an input behaves the same whatever ran before it. The first 16 bytes of
 * the input, zero padded, also serve as the key of the keyed table.
 *
 * The ossl_ht fuzzer kept its table from one input to the next instead, so
 * an input of its corpus is a single operation that finds the tables empty
 * here. test/recipes/99-test_fuzz_hashtable.t therefore also runs the
 * records of the whole corpus as one input.
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "crypto/siphash.h"
#include "internal/hashtable.h"
#include "fuzzer.h"

/*
 * The first three work on every element the record names, the others once.
 *
 * OP_INSERT   Add the element if it is not in the table. If it is, promote
 *             it with _ruc() under the given hash (FLAG_ALT), or find it.
 * OP_DELETE   Remove the element if it is in the table.
 * OP_LOOKUP   Find the element under the hash it is in the table with, or
 *             under the given hash (FLAG_ALT), which may not lead to it.
 * OP_FLUSH    Empty the table: remove every element from within
 *             _doall_arg(), or (FLAG_ALT) clean the table up and initialise
 *             it again.
 * OP_FOREACH  Check the whole table against the model.
 * OP_FILTER   Walk the element's bucket and remove from it the elements the
 *             given value selects.
 * OP_RESERVE  Reserve buckets for the given number of elements; growable
 *             table only.
 */
#define OP_INSERT 0
#define OP_DELETE 1
#define OP_LOOKUP 2
#define OP_FLUSH 3
#define OP_FOREACH 4
#define OP_FILTER 5
#define OP_RESERVE 6
#define OP_END 7

#define OP_MASK 0x3f
#define FLAG_ALT 0x40
#define OPERATION(x) (((x) & OP_MASK) % OP_END)

#define FZ_RECORD 11

/* Few enough elements that operations keep meeting the ones in the tables */
#define FZ_ELEMS 256

enum {
    T_STATIC,
    T_KEYED,
    T_DYN,
    T_RCU,
    T_COUNT
};

#define FZ_ALL_TABLES ((1u << T_COUNT) - 1)

typedef struct fz_elem_st {
    OSSL_QUEUE_MEMBER(fzs);
    OSSL_QUEUE_MEMBER(fzk);
    OSSL_HTABLE_MEMBER(fzd);
    OSSL_QUEUE_MEMBER(fzr);
    unsigned int num; /* which of the FZ_ELEMS elements it is */
} FZ_ELEM;

/*
 * Small tables, of 8, 4 and 16 buckets and, for the growable one, of 2 that
 * double four times: a couple of records fill any of them, make chains and
 * take the growable table to its maximum and past it.
 */
DEFINE_QUEUE_OF(fzs, FZ_ELEM);
DEFINE_HTABLE_OF(fzs, FZ_ELEM, 3);

DEFINE_QUEUE_OF(fzk, FZ_ELEM);
DEFINE_HTABLE_KEYED_OF(fzk, FZ_ELEM, 2);

#define FZD_MAX_BITS 5
#define FZD_MAX_BUCKETS ((size_t)1 << FZD_MAX_BITS)
DEFINE_QUEUE_OF(fzd, FZ_ELEM);
DEFINE_HTABLE_DYN_OF(fzd, FZ_ELEM, 1, FZD_MAX_BITS);

DEFINE_QUEUE_OF(fzr, FZ_ELEM);
DEFINE_HTABLE_OF(fzr, FZ_ELEM, 4);
DEFINE_HTABLE_RCU_OF(fzr, FZ_ELEM);

/*
 * The model: what is known of an element without asking a table. The
 * element itself is allocated when the first table gets it and freed when
 * the last one lets go of it, so that a link some table kept to it shows.
 */
typedef struct fz_model_st {
    FZ_ELEM *e;
    uint64_t hash[T_COUNT]; /* the hash it is in each table under */
    unsigned char in[T_COUNT]; /* whether it is in each table */
    unsigned char seen; /* by the _doall_arg() of a check */
} FZ_MODEL;

/* What _doall_arg() calls for each element */
typedef void FZ_VISIT(FZ_ELEM *e, void *arg);

/* The operations of one table, for the code that is the same for all four */
typedef struct fz_table_st {
    void (*init)(void);
    void (*cleanup)(void);
    void (*add)(FZ_ELEM *e, uint64_t hash);
    void (*del)(FZ_ELEM *e);
    void (*ruc)(FZ_ELEM *e, uint64_t hash);
    FZ_ELEM *(*find)(const FZ_ELEM *e, uint64_t hash);
    FZ_ELEM *(*head)(uint64_t hash);
    size_t (*walk)(void);
    void (*doall)(FZ_VISIT *fn, void *arg);
    void (*filter)(uint64_t hash, uint64_t drop);
    int (*hashed)(const FZ_ELEM *e);
    void (*init_elem)(FZ_ELEM *e);
    size_t (*num)(void);
    size_t (*num_buckets)(void);
    /* The hash of |m|, or with |alt| some other hash, made from |value| */
    uint64_t (*hash)(const FZ_MODEL *m, uint64_t value, int alt);
    /* FIND compares the whole hash, not only the bucket it selects */
    int whole_hash;
    /* What only this kind of table has, or NULL */
    void (*check)(void);
    void (*reserve)(uint64_t value);
} FZ_TABLE;

static FZ_MODEL fz_model[FZ_ELEMS];
static size_t fz_count[T_COUNT]; /* the model's number of elements */
static unsigned char fz_key[OSSL_HTABLE_KEY_SIZE];

static int fz_cond(int t, const FZ_ELEM *p, uint64_t hash, const FZ_ELEM *e);
static uint64_t fz_check_elem(int t, const FZ_ELEM *p, size_t bucket);
static void fz_filter_elem(int t, FZ_ELEM *p, uint64_t drop);

/*
 * The table |name| and its operations, which every kind of table spells the
 * same way. |t| is the table's index in the model. _add() is unused for a
 * table that is added to in another way.
 */
#define FZ_DEFINE_TABLE(name, t)                                             \
    static OSSL_HTABLE(name) name##_table;                                   \
    static void name##_cleanup(void)                                         \
    {                                                                        \
        ossl_htable_##name##_cleanup(&name##_table);                         \
    }                                                                        \
    static ossl_unused void name##_add(FZ_ELEM *e, uint64_t hash)            \
    {                                                                        \
        ossl_htable_##name##_add(&name##_table, e, hash);                    \
    }                                                                        \
    static void name##_del(FZ_ELEM *e)                                       \
    {                                                                        \
        ossl_htable_##name##_del(&name##_table, e);                          \
    }                                                                        \
    static void name##_ruc(FZ_ELEM *e, uint64_t hash)                        \
    {                                                                        \
        ossl_htable_##name##_ruc(&name##_table, e, hash);                    \
    }                                                                        \
    static FZ_ELEM *name##_find(const FZ_ELEM *e, uint64_t hash)             \
    {                                                                        \
        FZ_ELEM *p;                                                          \
                                                                             \
        OSSL_HTABLE_FIND(p, name, &name##_table, hash,                       \
            fz_cond(t, p, hash, e));                                         \
        return p;                                                            \
    }                                                                        \
    static FZ_ELEM *name##_head(uint64_t hash)                               \
    {                                                                        \
        return ossl_htable_##name##_head(&name##_table, hash);               \
    }                                                                        \
    /* Check every element of every bucket and its links; return how many */ \
    static size_t name##_walk(void)                                          \
    {                                                                        \
        FZ_ELEM *p, *last;                                                   \
        OSSL_QUEUE *bucket;                                                  \
        uint64_t hash;                                                       \
        size_t i, total = 0;                                                 \
        size_t n = ossl_htable_##name##_num_buckets(&name##_table);          \
                                                                             \
        for (i = 0; i < n; i++) {                                            \
            bucket = ossl_htable_##name##_bucket(&name##_table, i);          \
            last = NULL;                                                     \
            OSSL_HTABLE_FOREACH (p, name, &name##_table, i) {                \
                hash = fz_check_elem(t, p, i);                               \
                /* A growable table stores the hash: this one */             \
                OPENSSL_assert(ossl_htable_##name##_hash_eq(p, hash));       \
                /* The back link leads to the element before */              \
                OPENSSL_assert(ossl_queue_##name##_prev(bucket, p) == last); \
                last = p;                                                    \
                total++;                                                     \
            }                                                                \
        }                                                                    \
        return total;                                                        \
    }                                                                        \
    static void name##_doall(FZ_VISIT *fn, void *arg)                        \
    {                                                                        \
        ossl_htable_##name##_doall_arg(&name##_table, fn, arg);              \
    }                                                                        \
    /* Remove from the bucket of |hash| the elements that |drop| selects */  \
    static void name##_filter(uint64_t hash, uint64_t drop)                  \
    {                                                                        \
        FZ_ELEM *p, *pn;                                                     \
                                                                             \
        OSSL_HTABLE_FOREACH_DELSAFE (p, pn, name, &name##_table, hash)       \
            fz_filter_elem(t, p, drop);                                      \
    }                                                                        \
    static int name##_hashed(const FZ_ELEM *e)                               \
    {                                                                        \
        return ossl_queue_##name##_hashed(e);                                \
    }                                                                        \
    static void name##_init_elem(FZ_ELEM *e)                                 \
    {                                                                        \
        ossl_queue_##name##_init_elem(e);                                    \
    }                                                                        \
    static size_t name##_num(void)                                           \
    {                                                                        \
        return ossl_htable_num(&name##_table);                               \
    }                                                                        \
    static size_t name##_num_buckets(void)                                   \
    {                                                                        \
        return ossl_htable_##name##_num_buckets(&name##_table);              \
    }                                                                        \
    struct fz_dummy_st_##name

FZ_DEFINE_TABLE(fzs, T_STATIC);
FZ_DEFINE_TABLE(fzk, T_KEYED);
FZ_DEFINE_TABLE(fzd, T_DYN);
FZ_DEFINE_TABLE(fzr, T_RCU);

/* What differs from one kind of table to the next */

static void fzs_init(void)
{
    ossl_htable_fzs_init(&fzs_table);
}

/* The fuzzer chooses the hashes of all tables but the keyed one */
static uint64_t fz_given_hash(const FZ_MODEL *m, uint64_t value, int alt)
{
    return value;
}

static void fzk_init(void)
{
    ossl_htable_fzk_init(&fzk_table, fz_key);
}

/* The keyed table hashes the element's number, or else |value| */
static uint64_t fzk_hash(const FZ_MODEL *m, uint64_t value, int alt)
{
    uint64_t x = alt ? value : (uint64_t)(m - fz_model), h;
    unsigned char le[8];
    size_t i;

    for (i = 0; i < sizeof(le); i++)
        le[i] = (unsigned char)(x >> (8 * i));
    h = ossl_htable_fzk_hash_u64(&fzk_table, x);
    /* The integer form hashes the integer's little-endian bytes */
    OPENSSL_assert(h == ossl_htable_fzk_hash(&fzk_table, le, sizeof(le)));
    return h;
}

/*
 * The hash of the keyed table is SipHash-2-4 with a 64-bit result, which
 * crypto/siphash implements too: the two agree on any key and any data.
 */
static void fzk_check_hash(const uint8_t *buf, size_t len)
{
    SIPHASH sip;
    unsigned char out[SIPHASH_MIN_DIGEST_SIZE];
    uint64_t ref = 0;
    size_t i;

    memset(&sip, 0, sizeof(sip));
    OPENSSL_assert(SipHash_set_hash_size(&sip, sizeof(out))
        && SipHash_Init(&sip, fz_key, 0, 0));
    SipHash_Update(&sip, buf, len);
    OPENSSL_assert(SipHash_Final(&sip, out, sizeof(out)));
    for (i = 0; i < sizeof(out); i++)
        ref |= (uint64_t)out[i] << (8 * i);
    OPENSSL_assert(ossl_htable_fzk_hash(&fzk_table, buf, len) == ref);
}

/* A growable table has had this many buckets since it was initialised */
static size_t fzd_low_buckets;

static void fzd_init(void)
{
    ossl_htable_fzd_init(&fzd_table);
    fzd_low_buckets = fzd_num_buckets();
}

/* Its buckets are a power of two within its bounds, and it never shrinks */
static void fzd_check(void)
{
    size_t n = fzd_num_buckets();

    OPENSSL_assert((n & (n - 1)) == 0
        && n >= fzd_low_buckets && n <= FZD_MAX_BUCKETS);
    fzd_low_buckets = n;
}

static void fzd_reserve(uint64_t value)
{
    size_t want = (size_t)(value % (2 * FZD_MAX_BUCKETS + 1));
    size_t had = fzd_num_buckets(), n;

    if (!ossl_htable_fzd_reserve(&fzd_table, want)) {
        /* Out of memory: the table is as it was */
        OPENSSL_assert(fzd_num_buckets() == had);
        return;
    }
    n = fzd_num_buckets();
    /* A bucket for each of |want| elements, as far as the maximum allows */
    OPENSSL_assert(n >= had && (n >= want || n == FZD_MAX_BUCKETS));
    /* and no doubling beyond that */
    OPENSSL_assert(n == had || n / 2 < want);
}

/*
 * The last table is added to with _add_rcu() and read with the lock-free
 * macros, which must see what the locked ones see. Nothing here runs
 * concurrently, so no reader exists while an element is removed or moved,
 * and the table is otherwise treated as the static one is.
 */
static void fzr_init(void)
{
    ossl_htable_fzr_init(&fzr_table);
}

static void fzr_add_rcu(FZ_ELEM *e, uint64_t hash)
{
    ossl_htable_fzr_add_rcu(&fzr_table, e, hash);
}

static FZ_ELEM *fzr_find_rcu(const FZ_ELEM *e, uint64_t hash)
{
    FZ_ELEM *p;

    OSSL_HTABLE_FIND_RCU(p, fzr, &fzr_table, hash,
        fz_cond(T_RCU, p, hash, e));
    OPENSSL_assert(p == fzr_find(e, hash));
    return p;
}

static FZ_ELEM *fzr_head_rcu(uint64_t hash)
{
    FZ_ELEM *p = ossl_htable_fzr_head_rcu(&fzr_table, hash);

    OPENSSL_assert(p == fzr_head(hash));
    return p;
}

static size_t fzr_walk_rcu(void)
{
    FZ_ELEM *p, *q;
    size_t i, total = 0;

    for (i = 0; i < fzr_num_buckets(); i++) {
        q = fzr_head(i);
        OSSL_HTABLE_FOREACH_RCU (p, fzr, &fzr_table, i) {
            OPENSSL_assert(p == q);
            q = ossl_queue_fzr_next(q);
            total++;
        }
        OPENSSL_assert(q == NULL);
    }
    OPENSSL_assert(total == fzr_walk());
    return total;
}

#define FZ_TABLE_OPS(name, add, find, head, walk)             \
    name##_init, name##_cleanup, add, name##_del, name##_ruc, \
        find, head, walk, name##_doall, name##_filter,        \
        name##_hashed, name##_init_elem, name##_num, name##_num_buckets

static const FZ_TABLE fz_tables[T_COUNT] = {
    { FZ_TABLE_OPS(fzs, fzs_add, fzs_find, fzs_head, fzs_walk),
        fz_given_hash, 0, NULL, NULL },
    { FZ_TABLE_OPS(fzk, fzk_add, fzk_find, fzk_head, fzk_walk),
        fzk_hash, 0, NULL, NULL },
    { FZ_TABLE_OPS(fzd, fzd_add, fzd_find, fzd_head, fzd_walk),
        fz_given_hash, 1, fzd_check, fzd_reserve },
    { FZ_TABLE_OPS(fzr, fzr_add_rcu, fzr_find_rcu, fzr_head_rcu, fzr_walk_rcu),
        fz_given_hash, 0, NULL, NULL },
};

/* The model, and the tables against it */

static size_t fz_bucket(int t, uint64_t hash)
{
    return (size_t)hash & (fz_tables[t].num_buckets() - 1);
}

/* A new element for |m|, in no table yet, or NULL if there is no memory */
static FZ_ELEM *fz_new_elem(FZ_MODEL *m)
{
    int t;

    if ((m->e = OPENSSL_malloc(sizeof(*m->e))) == NULL)
        return NULL;
    m->e->num = (unsigned int)(m - fz_model);
    for (t = 0; t < T_COUNT; t++)
        fz_tables[t].init_elem(m->e);
    return m->e;
}

/* |m| has left a table: free its element if that was the last one */
static void fz_release(FZ_MODEL *m)
{
    int t;

    for (t = 0; t < T_COUNT; t++)
        if (m->in[t])
            return;
    OPENSSL_free(m->e);
    m->e = NULL;
}

/* An element met in a table is the one the model has under its number */
static FZ_MODEL *fz_model_of(const FZ_ELEM *p)
{
    FZ_MODEL *m = &fz_model[p->num % FZ_ELEMS];

    OPENSSL_assert(m->e == p);
    return m;
}

/* Whether a FIND under |hash| is to come across the element of |m| */
static int fz_reaches(int t, const FZ_MODEL *m, uint64_t hash)
{
    if (!m->in[t])
        return 0;
    if (fz_tables[t].whole_hash)
        return m->hash[t] == hash;
    return fz_bucket(t, m->hash[t]) == fz_bucket(t, hash);
}

/*
 * The condition of a FIND for |e| under |hash|, asked about |p|. It is only
 * asked about elements of the bucket |hash| selects and, in a growable
 * table, only about those stored under |hash| itself.
 */
static int fz_cond(int t, const FZ_ELEM *p, uint64_t hash, const FZ_ELEM *e)
{
    OPENSSL_assert(fz_reaches(t, fz_model_of(p), hash));
    return p == e;
}

/* |p| was met in bucket number |bucket|; return the hash it is there under */
static uint64_t fz_check_elem(int t, const FZ_ELEM *p, size_t bucket)
{
    const FZ_MODEL *m = fz_model_of(p);

    OPENSSL_assert(m->in[t] && fz_bucket(t, m->hash[t]) == bucket);
    return m->hash[t];
}

/* Take |m| out of table |t|, which it is in */
static void fz_remove(int t, FZ_MODEL *m)
{
    fz_tables[t].del(m->e);
    OPENSSL_assert(!fz_tables[t].hashed(m->e));
    m->in[t] = 0;
    fz_count[t]--;
    fz_release(m);
}

/* A filter met |p|, and removes it if |drop| has a bit set for its number */
static void fz_filter_elem(int t, FZ_ELEM *p, uint64_t drop)
{
    FZ_MODEL *m = fz_model_of(p);

    OPENSSL_assert(m->in[t]);
    if (((drop >> (p->num & 63)) & 1) != 0)
        fz_remove(t, m);
}

static void fz_insert(int t, FZ_MODEL *m, uint64_t value, int alt)
{
    const FZ_TABLE *T = &fz_tables[t];
    uint64_t hash = T->hash(m, value, 0);
    size_t buckets = T->num_buckets();

    if (!m->in[t]) {
        /* Out of memory: the element stays out of the table */
        if (m->e == NULL && fz_new_elem(m) == NULL)
            return;
        OPENSSL_assert(!T->hashed(m->e) && T->find(m->e, hash) == NULL);
        T->add(m->e, hash);
        m->in[t] = 1;
        fz_count[t]++;
    } else if (alt) {
        /* Into another bucket if the hash is another one */
        T->ruc(m->e, hash);
    } else {
        /* A caller looks before it adds, and finds the element */
        OPENSSL_assert(T->find(m->e, m->hash[t]) == m->e);
        return;
    }
    m->hash[t] = hash;
    OPENSSL_assert(T->hashed(m->e) && T->find(m->e, hash) == m->e);
    /*
     * Added or promoted, the element leads its bucket, unless the table
     * grew: that re-links the elements, which does not keep their order.
     */
    if (T->num_buckets() == buckets)
        OPENSSL_assert(T->head(hash) == m->e);
}

static void fz_delete(int t, FZ_MODEL *m)
{
    const FZ_TABLE *T = &fz_tables[t];
    uint64_t hash;

    if (m->in[t]) {
        hash = m->hash[t];
        fz_remove(t, m);
        OPENSSL_assert(T->find(m->e, hash) == NULL);
    }
    OPENSSL_assert(m->e == NULL || !T->hashed(m->e));
}

static void fz_lookup(int t, const FZ_MODEL *m, uint64_t value, int alt)
{
    const FZ_TABLE *T = &fz_tables[t];
    uint64_t hash = m->in[t] && !alt ? m->hash[t] : T->hash(m, value, alt);

    OPENSSL_assert(T->find(m->e, hash)
        == (fz_reaches(t, m, hash) ? m->e : NULL));
}

/* For _doall_arg(), which may remove the element it hands out */
static void fz_flush_cb(FZ_ELEM *e, void *arg)
{
    fz_remove(*(int *)arg, fz_model_of(e));
}

static void fz_flush(int t, int alt)
{
    const FZ_TABLE *T = &fz_tables[t];
    FZ_MODEL *m;

    if (!alt) {
        T->doall(fz_flush_cb, &t);
    } else {
        /*
         * Cleanup neither visits nor unlinks the elements. Those that are in
         * no other table are freed before it, which it must not notice. The
         * others are cleared after it, before they are used again, and so
         * is the table. Cleaning up twice is harmless.
         */
        for (m = fz_model; m < fz_model + FZ_ELEMS; m++)
            if (m->in[t]) {
                m->in[t] = 0;
                fz_release(m);
                m->in[t] = m->e != NULL;
            }
        T->cleanup();
        T->cleanup();
        for (m = fz_model; m < fz_model + FZ_ELEMS; m++)
            if (m->in[t]) {
                T->init_elem(m->e);
                m->in[t] = 0;
            }
        fz_count[t] = 0;
        T->init();
    }
    OPENSSL_assert(fz_count[t] == 0 && T->num() == 0 && T->walk() == 0);
}

static void fz_seen_cb(FZ_ELEM *e, void *arg)
{
    fz_model_of(e)->seen++;
}

static void fz_foreach(int t)
{
    const FZ_TABLE *T = &fz_tables[t];
    FZ_MODEL *m;

    /* Bucket by bucket: every element is where its hash puts it */
    OPENSSL_assert(T->walk() == fz_count[t]);
    /* _doall_arg() hands out the elements of the table, each one once */
    T->doall(fz_seen_cb, NULL);
    for (m = fz_model; m < fz_model + FZ_ELEMS; m++) {
        OPENSSL_assert(m->seen == m->in[t]
            && (m->e != NULL && T->hashed(m->e)) == m->in[t]);
        m->seen = 0;
    }
}

static void fz_filter(int t, const FZ_MODEL *m, uint64_t value)
{
    fz_tables[t].filter(m->in[t] ? m->hash[t] : value, value);
}

/* One record's operation on table |t|: on |run| elements from |first| on */
static void fz_operate(int t, unsigned int op, int alt, unsigned int first,
    unsigned int run, uint64_t value)
{
    const FZ_TABLE *T = &fz_tables[t];
    FZ_MODEL *m = &fz_model[first];
    unsigned int i;

    switch (op) {
    case OP_INSERT:
    case OP_DELETE:
    case OP_LOOKUP:
        for (i = 0; i < run; i++) {
            m = &fz_model[(first + i) % FZ_ELEMS];
            if (op == OP_INSERT)
                fz_insert(t, m, value + i, alt);
            else if (op == OP_DELETE)
                fz_delete(t, m);
            else
                fz_lookup(t, m, value + i, alt);
        }
        break;
    case OP_FLUSH:
        fz_flush(t, alt);
        break;
    case OP_FOREACH:
        fz_foreach(t);
        break;
    case OP_FILTER:
        fz_filter(t, m, value);
        break;
    case OP_RESERVE:
        if (T->reserve != NULL)
            T->reserve(value);
        break;
    }

    OPENSSL_assert(T->num() == fz_count[t]);
    if (T->check != NULL)
        T->check();
}

int FuzzerInitialize(int *argc, char ***argv)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_clear_error();
    return 0;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    uint64_t value;
    unsigned int sel, tables;
    size_t i;
    int t;

    /* One record at least: an operation, an element and a value */
    if (len < FZ_RECORD)
        return -1;

    memset(fz_key, 0, sizeof(fz_key));
    memcpy(fz_key, buf, len < sizeof(fz_key) ? len : sizeof(fz_key));
    for (t = 0; t < T_COUNT; t++)
        fz_tables[t].init();
    fzk_check_hash(buf, len);

    for (; len >= FZ_RECORD; buf += FZ_RECORD, len -= FZ_RECORD) {
        sel = buf[1] | (unsigned int)buf[2] << 8;
        tables = (sel >> 8) & FZ_ALL_TABLES;
        if (tables == 0)
            tables = FZ_ALL_TABLES;
        for (value = 0, i = 0; i < 8; i++)
            value |= (uint64_t)buf[3 + i] << (8 * i);

        for (t = 0; t < T_COUNT; t++)
            if ((tables & (1u << t)) != 0)
                fz_operate(t, OPERATION(buf[0]), (buf[0] & FLAG_ALT) != 0,
                    sel % FZ_ELEMS, 1 + (sel >> 12), value);
    }

    /*
     * Check what is left and empty the tables, one way or the other, which
     * frees every element, then give back what the tables allocated.
     */
    for (t = 0; t < T_COUNT; t++) {
        fz_foreach(t);
        fz_flush(t, t & 1);
        fz_tables[t].cleanup();
    }
    for (i = 0; i < FZ_ELEMS; i++)
        OPENSSL_assert(fz_model[i].e == NULL);
    return 0;
}

void FuzzerCleanup(void)
{
    OPENSSL_cleanup();
}
