/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include "testutil.h"
#include "internal/ossl_rbtree.h"

static const char *test_data[] = {
    "alpha",
    "bravo",
    "charlie",
    "delta",
    "echo",
    "foxtrot",
    "golf",
    "hotel",
    "india",
    "juliet",
    "kilo",
    "lima",
    "mike",
    "november",
    "oscar",
    "papa",
    "quebec",
    "romeo",
    "sierra",
    "tango",
    "uniform",
    "victor",
    "whiskey",
    "x-ray",
    "yankey",
    "zulu",
};

typedef struct test_rbt {
    OSSL_RBT_ENTRY(test_rbt)
    rbt_entry;
    const char *rbt_data;
} TEST_RBT_T;

static OSSL_RBT_HEAD(ossl_rbt, test_rbt)
    rbt_head;

static TEST_RBT_T nodes_rbt[26];

static int cmp(const TEST_RBT_T *a, const TEST_RBT_T *b);

OSSL_RBT_PROTOTYPE(ossl_rbt, test_rbt, rbt_entry, cmp)

OSSL_RBT_GENERATE(ossl_rbt, test_rbt, rbt_entry, cmp);

static int cmp(const TEST_RBT_T *a_rbt, const TEST_RBT_T *b_rbt)
{
    return strcmp(a_rbt->rbt_data, b_rbt->rbt_data);
}

static int test_rbt_insert(void)
{
    unsigned int i;
    TEST_RBT_T *found_rbt, *node_rbt;

    memset(nodes_rbt, 0, sizeof(nodes_rbt));
    OSSL_RBT_INIT(ossl_rbt, &rbt_head);

    for (i = 26; i != 0; i--) {
        node_rbt = &nodes_rbt[i - 1];
        node_rbt->rbt_data = test_data[i - 1];
        found_rbt = OSSL_RBT_INSERT(ossl_rbt, &rbt_head, node_rbt);
        if (!TEST_ptr_eq(found_rbt, NULL)) {
            TEST_info("%s %p(%s) found already %p(%s) @ %un", __func__,
                (void *)node_rbt, node_rbt->rbt_data,
                (void *)found_rbt, found_rbt->rbt_data, i);
            return 0;
        }
    }

    return 1;
}

static int test_rbt_min(void)
{
    unsigned int i;
    int match;
    TEST_RBT_T *node_rbt;

    if (test_rbt_insert() == 0)
        return 0;

    node_rbt = OSSL_RBT_MIN(ossl_rbt, &rbt_head);
    if (!TEST_ptr(node_rbt)) {
        TEST_info("%s OSSL_RBT_MIN() returns NULL", __func__);
        return 0;
    }

    for (i = 0; i < 26; i++) {
        match = strcmp(node_rbt->rbt_data, test_data[i]);
        if (!TEST_int_eq(match, 0)) {
            TEST_info("%s %s != %s @ %u", __func__,
                node_rbt->rbt_data, test_data[i], i);
            return 0;
        }
        node_rbt = OSSL_RBT_NEXT(ossl_rbt, node_rbt);
    }

    if (!TEST_ptr_eq(node_rbt, NULL)) {
        TEST_info("%s OSSL_RBT_NEXT() is not NULL", __func__);
        return 0;
    }

    return 1;
}

static int test_rbt_max(void)
{
    unsigned int i;
    int match;
    TEST_RBT_T *node_rbt;

    if (test_rbt_insert() == 0)
        return 0;

    node_rbt = OSSL_RBT_MAX(ossl_rbt, &rbt_head);
    if (!TEST_ptr(node_rbt)) {
        TEST_info("%s OSSL_RBT_MIN() returns NULL", __func__);
        return 0;
    }

    for (i = 26; i > 0; i--) {
        match = strcmp(node_rbt->rbt_data, test_data[i - 1]);
        if (!TEST_int_eq(match, 0)) {
            TEST_info("%s %s != %s @ %u", __func__,
                node_rbt->rbt_data, test_data[i - 1], i);
            return 0;
        }
        node_rbt = OSSL_RBT_PREV(ossl_rbt, node_rbt);
    }

    if (!TEST_ptr_eq(node_rbt, NULL)) {
        TEST_info("%s OSSL_RBT_PREV() is not NULL", __func__);
        return 0;
    }

    return 1;
}

static int test_rbt_find_remove(void)
{
    unsigned int i;
    TEST_RBT_T *node_rbt, *removed_rbt;
    TEST_RBT_T key_rbt;

    if (test_rbt_insert() == 0)
        return 0;

    for (i = 0; i < 26; i++) {
        key_rbt.rbt_data = test_data[i];
        node_rbt = OSSL_RBT_FIND(ossl_rbt, &rbt_head, &key_rbt);
        if (!TEST_ptr(node_rbt)) {
            TEST_info("%s %s not found in tree @ %u", __func__,
                key_rbt.rbt_data, i);
            return 0;
        }
        removed_rbt = OSSL_RBT_REMOVE(ossl_rbt, &rbt_head, node_rbt);
        if (!TEST_ptr_eq(node_rbt, removed_rbt)) {
            TEST_info("%s node_rbt(%p) != removed_rbt(%p) @ %u",
                __func__, (void *)node_rbt, (void *)removed_rbt, i);
            return 0;
        }

        node_rbt = OSSL_RBT_FIND(ossl_rbt, &rbt_head, &key_rbt);
        if (!TEST_ptr_eq(node_rbt, NULL)) {
            TEST_info("%s %s(%p) still found after being removed @ %u",
                __func__, node_rbt->rbt_data, (void *)node_rbt, i);
            return 0;
        }
    }

    if (!TEST_int_ne(OSSL_RBT_EMPTY(ossl_rbt, &rbt_head), 0)) {
        TEST_info("%s rbt is not empty", __func__);
        return 0;
    }

    return 1;
}

static int test_rbt_dup_insert(void)
{
    unsigned int i;
    int match;
    TEST_RBT_T *conflict_rbt;
    TEST_RBT_T insert_rbt;

    if (test_rbt_insert() == 0)
        return 0;

    for (i = 0; i < 26; i++) {
        insert_rbt.rbt_data = test_data[i];
        conflict_rbt = OSSL_RBT_INSERT(ossl_rbt, &rbt_head, &insert_rbt);
        if (!TEST_ptr(conflict_rbt)) {
            TEST_info("%s %s not found in tree @ %u", __func__,
                insert_rbt.rbt_data, i);
            return 0;
        }
        match = strcmp(conflict_rbt->rbt_data, insert_rbt.rbt_data);
        if (!TEST_int_eq(match, 0)) {
            TEST_info("%s insert(%s) != conflict(%s) @ %u",
                __func__, insert_rbt.rbt_data, conflict_rbt->rbt_data, i);
            return 0;
        }
    }

    return 1;
}

static int test_rbt_foreach(void)
{
    unsigned int i;
    int match;
    TEST_RBT_T *walk_rbt, *save_rbt;

    if (test_rbt_insert() == 0)
        return 0;

    i = 0;
    OSSL_RBT_FOREACH(walk_rbt, ossl_rbt, &rbt_head)
    {
        match = strcmp(walk_rbt->rbt_data, test_data[i]);
        if (!TEST_int_eq(match, 0)) {
            TEST_info("%s expected: %s got: %s @ %u",
                __func__, walk_rbt->rbt_data, test_data[i], i);
            return 0;
        }
        i++;
    }

    i = 0;
    OSSL_RBT_FOREACH_SAFE(walk_rbt, ossl_rbt, &rbt_head, save_rbt)
    {
        match = strcmp(walk_rbt->rbt_data, test_data[i]);
        if (!TEST_int_eq(match, 0)) {
            TEST_info("%s expected: %s got: %s @ %u",
                __func__, walk_rbt->rbt_data, test_data[i], i);
            return 0;
        }
        OSSL_RBT_REMOVE(ossl_rbt, &rbt_head, walk_rbt);
        i++;
    }

    if (!TEST_int_ne(OSSL_RBT_EMPTY(ossl_rbt, &rbt_head), 0)) {
        TEST_info("%s rbt is not empty", __func__);
        return 0;
    }

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(test_rbt_insert);
    ADD_TEST(test_rbt_min);
    ADD_TEST(test_rbt_max);
    ADD_TEST(test_rbt_find_remove);
    ADD_TEST(test_rbt_dup_insert);
    ADD_TEST(test_rbt_foreach);

    return 1;
}
