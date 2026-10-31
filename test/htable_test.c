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

#include "internal/htable.h"
#include "internal/nelem.h"
#include "testutil.h"

typedef struct entry_st {
    uint64_t key;
    int visits;
    OSSL_QUEUE_MEMBER(ent);
    OSSL_QUEUE_MEMBER(one);
} ENTRY;

#define ENT_BITS 4
#define ENT_BUCKETS ((size_t)1 << ENT_BITS)
DEFINE_QUEUE_OF(ent, ENTRY);
DEFINE_HTABLE_OF(ent, ENTRY, ENT_BITS);

/* A single-bucket table over the same elements, so every insertion collides */
DEFINE_QUEUE_OF(one, ENTRY);
DEFINE_HTABLE_OF(one, ENTRY, 0);

static OSSL_HTABLE(ent) static_table = OSSL_HTABLE_INIT;

static uint64_t key_hash(uint64_t key)
{
    return ossl_hash_u64(key);
}

/* The number of non-empty buckets and the length of the longest chain. */
static void chain_shape(const OSSL_QUEUE *buckets, size_t nbuckets,
    size_t *used, size_t *max_chain)
{
    const OSSL_QNODE *n;
    size_t i, len;

    *used = 0;
    *max_chain = 0;
    for (i = 0; i < nbuckets; i++) {
        len = 0;
        OSSL_QUEUE_WALK (n, &buckets[i])
            len++;
        *used += len != 0;
        if (len > *max_chain)
            *max_chain = len;
    }
}

static void init_entries(ENTRY *e, size_t n, uint64_t stride)
{
    size_t i;

    for (i = 0; i < n; i++) {
        e[i].key = (uint64_t)i * stride;
        e[i].visits = 0;
        ossl_queue_ent_init_elem(&e[i]);
        ossl_queue_one_init_elem(&e[i]);
    }
}

static int check_empty(OSSL_HTABLE(ent) *ht)
{
    ENTRY *p;
    size_t i;

    if (!TEST_size_t_eq(ossl_htable_num(ht), 0)
        || !TEST_true(ossl_htable_is_empty(ht))
        || !TEST_size_t_eq(ossl_htable_num_buckets(ht), ENT_BUCKETS)
        || !TEST_uint64_t_eq(ossl_htable_mask(ht), ENT_BUCKETS - 1)
        || !TEST_ptr_eq(ossl_htable_bucket(ht, 0x123), &ht->buckets[3])
        || !TEST_ptr_eq(ossl_htable_bucket(ht, UINT64_MAX),
            &ht->buckets[ENT_BUCKETS - 1]))
        return 0;
    for (i = 0; i < ossl_htable_num_buckets(ht); i++)
        if (!TEST_true(ossl_queue_empty(&ht->buckets[i])))
            return 0;

    /* A search of an empty table is a miss */
    OSSL_HTABLE_FIND(p, ent, ht, 7, p->key == 7);
    return TEST_ptr_null(p) && TEST_ptr_null(ossl_htable_ent_head(ht, 7));
}

/* A statically initialised table and a run-time initialised one agree. */
static int test_init(void)
{
    OSSL_HTABLE(ent)
    table;

    memset(&table, 0xff, sizeof(table));
    ossl_htable_ent_init(&table);
    return check_empty(&static_table) && check_empty(&table);
}

static void count_visit(ENTRY *e, void *arg)
{
    e->visits++;
    (*(size_t *)arg)++;
}

static void del_visit(ENTRY *e, void *arg)
{
    ossl_htable_ent_del(arg, e);
    e->visits++;
}

#define NENTRIES 64

static int test_add_find_del(void)
{
    OSSL_HTABLE(ent)
    table;
    ENTRY e[NENTRIES], *p;
    size_t i, count = 0, used, max_chain;
    uint64_t b;

    ossl_htable_ent_init(&table);
    init_entries(e, NENTRIES, 7919);

    for (i = 0; i < NENTRIES; i++) {
        ossl_htable_ent_add(&table, &e[i], key_hash(e[i].key));
        if (!TEST_size_t_eq(ossl_htable_num(&table), i + 1)
            || !TEST_true(ossl_queue_ent_hashed(&e[i])))
            return 0;
    }

    chain_shape(table.buckets, ENT_BUCKETS, &used, &max_chain);
    if (!TEST_false(ossl_htable_is_empty(&table))
        || !TEST_size_t_le(used, ENT_BUCKETS)
        || !TEST_size_t_ge(max_chain, NENTRIES / ENT_BUCKETS))
        return 0;

    /* Every element is found under its own key, and an unknown key is not */
    for (i = 0; i < NENTRIES; i++) {
        OSSL_HTABLE_FIND(p, ent, &table, key_hash(e[i].key), p->key == e[i].key);
        if (!TEST_ptr_eq(p, &e[i]))
            return 0;
    }
    OSSL_HTABLE_FIND(p, ent, &table, key_hash(1), p->key == 1);
    if (!TEST_ptr_null(p))
        return 0;

    /* Each element sits in the bucket its hash selects, and nowhere else */
    for (b = 0; b < ENT_BUCKETS; b++)
        OSSL_HTABLE_FOREACH (p, ent, &table, b) {
            if (!TEST_uint64_t_eq(key_hash(p->key) & ossl_htable_mask(&table), b))
                return 0;
            count++;
        }
    if (!TEST_size_t_eq(count, NENTRIES))
        return 0;

    /* doall visits every element exactly once */
    count = 0;
    ossl_htable_ent_doall_arg(&table, count_visit, &count);
    if (!TEST_size_t_eq(count, NENTRIES))
        return 0;
    for (i = 0; i < NENTRIES; i++)
        if (!TEST_int_eq(e[i].visits, 1))
            return 0;

    /* Deleting half leaves the other half findable, and they can come back */
    for (i = 0; i < NENTRIES; i += 2)
        ossl_htable_ent_del(&table, &e[i]);
    if (!TEST_size_t_eq(ossl_htable_num(&table), NENTRIES / 2))
        return 0;
    for (i = 0; i < NENTRIES; i++) {
        OSSL_HTABLE_FIND(p, ent, &table, key_hash(e[i].key), p->key == e[i].key);
        if (i % 2 == 0) {
            if (!TEST_false(ossl_queue_ent_hashed(&e[i])) || !TEST_ptr_null(p))
                return 0;
        } else if (!TEST_ptr_eq(p, &e[i])) {
            return 0;
        }
    }
    for (i = 0; i < NENTRIES; i += 2)
        ossl_htable_ent_add(&table, &e[i], key_hash(e[i].key));
    if (!TEST_size_t_eq(ossl_htable_num(&table), NENTRIES))
        return 0;
    for (i = 0; i < NENTRIES; i++) {
        OSSL_HTABLE_FIND(p, ent, &table, key_hash(e[i].key), p->key == e[i].key);
        if (!TEST_ptr_eq(p, &e[i]))
            return 0;
    }

    /* doall may remove the element it is handed */
    ossl_htable_ent_doall_arg(&table, del_visit, &table);
    if (!TEST_size_t_eq(ossl_htable_num(&table), 0)
        || !TEST_true(ossl_htable_is_empty(&table)))
        return 0;
    for (i = 0; i < NENTRIES; i++)
        if (!TEST_false(ossl_queue_ent_hashed(&e[i]))
            || !TEST_int_eq(e[i].visits, 2))
            return 0;
    chain_shape(table.buckets, ENT_BUCKETS, &used, &max_chain);
    return TEST_size_t_eq(used, 0) && TEST_size_t_eq(max_chain, 0);
}

/* With a single bucket every element shares one chain, most recent first. */
static int test_single_bucket(void)
{
    OSSL_HTABLE(one)
    table;
    ENTRY e[10], *p, *pn;
    size_t i, count = 0, used, max_chain;

    ossl_htable_one_init(&table);
    init_entries(e, OSSL_NELEM(e), 1);
    if (!TEST_size_t_eq(ossl_htable_num_buckets(&table), 1)
        || !TEST_uint64_t_eq(ossl_htable_mask(&table), 0)
        || !TEST_ptr_eq(ossl_htable_bucket(&table, UINT64_MAX),
            &table.buckets[0]))
        return 0;

    for (i = 0; i < OSSL_NELEM(e); i++)
        ossl_htable_one_add(&table, &e[i], key_hash(e[i].key));
    OSSL_HTABLE_FOREACH (p, one, &table, 12345) {
        if (!TEST_size_t_lt(count, OSSL_NELEM(e))
            || !TEST_ptr_eq(p, &e[OSSL_NELEM(e) - 1 - count]))
            return 0;
        count++;
    }
    chain_shape(table.buckets, 1, &used, &max_chain);
    if (!TEST_size_t_eq(count, OSSL_NELEM(e))
        || !TEST_size_t_eq(used, 1)
        || !TEST_size_t_eq(max_chain, OSSL_NELEM(e)))
        return 0;

    /*
     * Whatever hash a search is given, it lands in the one bucket and walks
     * the chain to its key.
     */
    for (i = 0; i < OSSL_NELEM(e); i++) {
        OSSL_HTABLE_FIND(p, one, &table, (uint64_t)i * 977, p->key == e[i].key);
        if (!TEST_ptr_eq(p, &e[i]))
            return 0;
    }

    /* A deletion-safe bucket walk may remove every element */
    OSSL_HTABLE_FOREACH_DELSAFE (p, pn, one, &table, 0)
        ossl_htable_one_del(&table, p);
    return TEST_size_t_eq(ossl_htable_num(&table), 0)
        && TEST_true(ossl_htable_is_empty(&table))
        && TEST_ptr_null(ossl_htable_one_head(&table, 0));
}

/* Recently-used-cache promotion moves an element to the head of a bucket. */
static int test_ruc(void)
{
    OSSL_HTABLE(ent)
    table;
    ENTRY e[3], *p;
    size_t i;

    ossl_htable_ent_init(&table);
    init_entries(e, OSSL_NELEM(e), 1);
    for (i = 0; i < OSSL_NELEM(e); i++)
        ossl_htable_ent_add(&table, &e[i], 5);
    if (!TEST_ptr_eq(ossl_htable_ent_head(&table, 5), &e[2]))
        return 0;

    /* Promoting the tail makes it the head and keeps the count */
    ossl_htable_ent_ruc(&table, &e[0], 5);
    if (!TEST_ptr_eq(ossl_htable_ent_head(&table, 5), &e[0])
        || !TEST_ptr_eq(ossl_queue_ent_next(&e[0]), &e[2])
        || !TEST_ptr_eq(ossl_queue_ent_next(&e[2]), &e[1])
        || !TEST_ptr_null(ossl_queue_ent_next(&e[1]))
        || !TEST_size_t_eq(ossl_htable_num(&table), 3))
        return 0;

    /* Promoting under another hash moves the element to that bucket */
    ossl_htable_ent_ruc(&table, &e[1], 9);
    OSSL_HTABLE_FIND(p, ent, &table, 9, p->key == e[1].key);
    if (!TEST_ptr_eq(p, &e[1])
        || !TEST_ptr_eq(ossl_htable_ent_head(&table, 9), &e[1])
        || !TEST_ptr_null(ossl_queue_ent_next(&e[1]))
        || !TEST_ptr_eq(ossl_htable_ent_head(&table, 5), &e[0])
        || !TEST_ptr_eq(ossl_queue_ent_next(&e[0]), &e[2])
        || !TEST_ptr_null(ossl_queue_ent_next(&e[2]))
        || !TEST_size_t_eq(ossl_htable_num(&table), 3))
        return 0;
    OSSL_HTABLE_FIND(p, ent, &table, 5, p->key == e[1].key);
    return TEST_ptr_null(p);
}

/* The hash helpers spread keys over the low bits that select a bucket. */
static int test_hash_mixing(void)
{
    unsigned char used[1024];
    size_t i, n = 0, m = 0;
    int local = 0;

    /* Zero is the finaliser's fixed point; everything else moves */
    if (!TEST_uint64_t_eq(ossl_hash_u64(0), 0)
        || !TEST_uint64_t_ne(ossl_hash_u64(1), 1)
        || !TEST_uint64_t_ne(ossl_hash_u64(1), ossl_hash_u64(2))
        || !TEST_uint64_t_eq(ossl_hash_ptr(&local),
            ossl_hash_u64((uint64_t)(uintptr_t)&local)))
        return 0;

    /* Mixed sequential keys spread like random ones: about 63% of buckets */
    memset(used, 0, sizeof(used));
    for (i = 0; i < OSSL_NELEM(used); i++)
        used[ossl_hash_u64(i) & (OSSL_NELEM(used) - 1)] = 1;
    for (i = 0; i < OSSL_NELEM(used); i++)
        n += used[i];

    /* Keys with a stride of four passed through raw use a quarter of them */
    memset(used, 0, sizeof(used));
    for (i = 0; i < OSSL_NELEM(used); i++)
        used[(i << 2) & (OSSL_NELEM(used) - 1)] = 1;
    for (i = 0; i < OSSL_NELEM(used); i++)
        m += used[i];

    return TEST_size_t_ge(n, OSSL_NELEM(used) / 2)
        && TEST_size_t_eq(m, OSSL_NELEM(used) / 4);
}

/* The RCU variants, checked for their ordering and unlink semantics. */
static int test_rcu_accessors(void)
{
    OSSL_HTABLE(ent)
    table;
    ENTRY e[4], *p;
    size_t i, count = 0;

    ossl_htable_ent_init(&table);
    init_entries(e, OSSL_NELEM(e), 1);
    for (i = 0; i < OSSL_NELEM(e); i++)
        ossl_htable_ent_add_rcu(&table, &e[i], 3);

    OSSL_HTABLE_FIND_RCU(p, ent, &table, 3, p->key == 1);
    if (!TEST_size_t_eq(ossl_htable_num(&table), OSSL_NELEM(e))
        || !TEST_ptr_eq(ossl_htable_ent_head_rcu(&table, 3), &e[3])
        || !TEST_ptr_eq(p, &e[1]))
        return 0;
    OSSL_HTABLE_FOREACH_RCU (p, ent, &table, 3)
        count++;
    if (!TEST_size_t_eq(count, OSSL_NELEM(e)))
        return 0;

    /*
     * del_rcu unhashes the element but keeps its next pointer, so a reader
     * parked on it can still advance along the chain.
     */
    ossl_htable_ent_del_rcu(&table, &e[2]);
    OSSL_HTABLE_FIND_RCU(p, ent, &table, 3, p->key == 2);
    if (!TEST_ptr_null(p)
        || !TEST_size_t_eq(ossl_htable_num(&table), OSSL_NELEM(e) - 1)
        || !TEST_false(ossl_queue_ent_hashed(&e[2]))
        || !TEST_ptr_eq(ossl_queue_ent_next_rcu(&e[2]), &e[1]))
        return 0;
    count = 0;
    OSSL_HTABLE_FOREACH_RCU (p, ent, &table, 3)
        count++;
    return TEST_size_t_eq(count, OSSL_NELEM(e) - 1);
}

int setup_tests(void)
{
    ADD_TEST(test_init);
    ADD_TEST(test_add_find_del);
    ADD_TEST(test_single_bucket);
    ADD_TEST(test_ruc);
    ADD_TEST(test_hash_mixing);
    ADD_TEST(test_rcu_accessors);
    return 1;
}
