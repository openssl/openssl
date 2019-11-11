/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdarg.h>
#include "testutil.h"
#include "internal/nelem.h"
#include "internal/property.h"
#include "../crypto/property/property_local.h"

static int add_property_names(const char *n, ...)
{
    va_list args;
    int res = 1;

    va_start(args, n);
    do {
        if (!TEST_int_ne(ossl_property_name(NULL, n, 1), 0))
            res = 0;
    } while ((n = va_arg(args, const char *)) != NULL);
    va_end(args);
    return res;
}

static int up_ref(void *p)
{
    return 1;
}

static void down_ref(void *p)
{
}

static int test_property_string(void)
{
    OSSL_METHOD_STORE *store;
    int res = 0;
    OSSL_PROPERTY_IDX i, j;

    if (TEST_ptr(store = ossl_method_store_new(NULL))
        && TEST_int_eq(ossl_property_name(NULL, "fnord", 0), 0)
        && TEST_int_ne(ossl_property_name(NULL, "fnord", 1), 0)
        && TEST_int_ne(ossl_property_name(NULL, "name", 1), 0)
        /* Property value checks */
        && TEST_int_eq(ossl_property_value(NULL, "fnord", 0), 0)
        && TEST_int_ne(i = ossl_property_value(NULL, "no", 0), 0)
        && TEST_int_ne(j = ossl_property_value(NULL, "yes", 0), 0)
        && TEST_int_ne(i, j)
        && TEST_int_eq(ossl_property_value(NULL, "yes", 1), j)
        && TEST_int_eq(ossl_property_value(NULL, "no", 1), i)
        && TEST_int_ne(i = ossl_property_value(NULL, "illuminati", 1), 0)
        && TEST_int_eq(j = ossl_property_value(NULL, "fnord", 1), i + 1)
        && TEST_int_eq(ossl_property_value(NULL, "fnord", 1), j)
        /* Check name and values are distinct */
        && TEST_int_eq(ossl_property_value(NULL, "cold", 0), 0)
        && TEST_int_ne(ossl_property_name(NULL, "fnord", 0),
                       ossl_property_value(NULL, "fnord", 0)))
        res = 1;
    ossl_method_store_free(store);
    return res;
}

static const struct {
    const char *defn;
    const char *query;
    int e;
} parser_tests[] = {
    { "", "sky=blue", -1 },
    { "", "sky!=blue", 1 },
    { "groan", "", 0 },
    { "cold=yes", "cold=yes", 1 },
    { "cold=yes", "cold", 1 },
    { "cold=yes", "cold!=no", 1 },
    { "groan", "groan=yes", 1 },
    { "groan", "groan=no", -1 },
    { "groan", "groan!=yes", -1 },
    { "cold=no", "cold", -1 },
    { "cold=no", "?cold", 0 },
    { "cold=no", "cold=no", 1 },
    { "groan", "cold", -1 },
    { "groan", "cold=no", 1 },
    { "groan", "cold!=yes", 1 },
    { "groan=blue", "groan=yellow", -1 },
    { "groan=blue", "?groan=yellow", 0 },
    { "groan=blue", "groan!=yellow", 1 },
    { "groan=blue", "?groan!=yellow", 1 },
    { "today=monday, tomorrow=3", "today!=2", 1 },
    { "today=monday, tomorrow=3", "today!='monday'", -1 },
    { "today=monday, tomorrow=3", "tomorrow=3", 1 },
    { "n=0x3", "n=3", 1 },
    { "n=0x3", "n=-3", -1 },
    { "n=0x33", "n=51", 1 },
    { "n=033", "n=27", 1 },
    { "n=0", "n=00", 1 },
    { "n=0x0", "n=0", 1 },
    { "n=0, sky=blue", "?n=0, sky=blue", 2 },
    { "n=1, sky=blue", "?n=0, sky=blue", 1 },
};

static int test_property_parse(int n)
{
    OSSL_METHOD_STORE *store;
    OSSL_PROPERTY_LIST *p = NULL, *q = NULL;
    int r = 0;

    if (TEST_ptr(store = ossl_method_store_new(NULL))
        && add_property_names("sky", "groan", "cold", "today", "tomorrow", "n",
                              NULL)
        && TEST_ptr(p = ossl_parse_property(NULL, parser_tests[n].defn))
        && TEST_ptr(q = ossl_parse_query(NULL, parser_tests[n].query))
        && TEST_int_eq(ossl_property_match_count(q, p), parser_tests[n].e))
        r = 1;
    ossl_property_free(p);
    ossl_property_free(q);
    ossl_method_store_free(store);
    return r;
}

static const struct {
    const char *q_global;
    const char *q_local;
    const char *prop;
} merge_tests[] = {
    { "", "colour=blue", "colour=blue" },
    { "colour=blue", "", "colour=blue" },
    { "colour=red", "colour=blue", "colour=blue" },
    { "clouds=pink, urn=red", "urn=blue, colour=green",
        "urn=blue, colour=green, clouds=pink" },
    { "pot=gold", "urn=blue", "pot=gold, urn=blue" },
    { "night", "day", "day=yes, night=yes" },
    { "day", "night", "day=yes, night=yes" },
    { "", "", "" },
    /*
     * The following four leave 'day' unspecified in the query, and will match
     * any definition
     */
    { "day=yes", "-day", "day=no" },
    { "day=yes", "-day", "day=yes" },
    { "day=yes", "-day", "day=arglebargle" },
    { "day=yes", "-day", "pot=sesquioxidizing" },
    { "day, night", "-night, day", "day=yes, night=no" },
    { "-day", "day=yes", "day=yes" },
};

static int test_property_merge(int n)
{
    OSSL_METHOD_STORE *store;
    OSSL_PROPERTY_LIST *q_global = NULL, *q_local = NULL;
    OSSL_PROPERTY_LIST *q_combined = NULL, *prop = NULL;
    int r = 0;

    if (TEST_ptr(store = ossl_method_store_new(NULL))
        && add_property_names("colour", "urn", "clouds", "pot", "day", "night",
                              NULL)
        && TEST_ptr(prop = ossl_parse_property(NULL, merge_tests[n].prop))
        && TEST_ptr(q_global = ossl_parse_query(NULL, merge_tests[n].q_global))
        && TEST_ptr(q_local = ossl_parse_query(NULL, merge_tests[n].q_local))
        && TEST_ptr(q_combined = ossl_property_merge(q_local, q_global))
        && TEST_int_ge(ossl_property_match_count(q_combined, prop), 0))
        r = 1;
    ossl_property_free(q_global);
    ossl_property_free(q_local);
    ossl_property_free(q_combined);
    ossl_property_free(prop);
    ossl_method_store_free(store);
    return r;
}

static int test_property_defn_cache(void)
{
    OSSL_METHOD_STORE *store;
    OSSL_PROPERTY_LIST *red, *blue;
    int r = 0;

    if (TEST_ptr(store = ossl_method_store_new(NULL))
        && add_property_names("red", "blue", NULL)
        && TEST_ptr(red = ossl_parse_property(NULL, "red"))
        && TEST_ptr(blue = ossl_parse_property(NULL, "blue"))
        && TEST_ptr_ne(red, blue)
        && TEST_true(ossl_prop_defn_set(NULL, "red", red))
        && TEST_true(ossl_prop_defn_set(NULL, "blue", blue))
        && TEST_ptr_eq(ossl_prop_defn_get(NULL, "red"), red)
        && TEST_ptr_eq(ossl_prop_defn_get(NULL, "blue"), blue))
        r = 1;
    ossl_method_store_free(store);
    return r;
}

static const struct {
    const char *defn;
    const char *query;
    int e;
} definition_tests[] = {
    { "alpha", "alpha=yes", 1 },
    { "alpha=no", "alpha", -1 },
    { "alpha=1", "alpha=1", 1 },
    { "alpha=2", "alpha=1",-1 },
    { "alpha", "omega", -1 },
    { "alpha", "?omega", 0 },
    { "alpha", "?omega=1", 0 },
    { "alpha", "?omega=no", 1 },
    { "alpha", "?omega=yes", 0 },
    { "alpha, omega", "?omega=yes", 1 },
    { "alpha, omega", "?omega=no", 0 }
};

static int test_definition_compares(int n)
{
    OSSL_METHOD_STORE *store;
    OSSL_PROPERTY_LIST *d = NULL, *q = NULL;
    int r;

    r = TEST_ptr(store = ossl_method_store_new(NULL))
        && add_property_names("alpha", "omega", NULL)
        && TEST_ptr(d = ossl_parse_property(NULL, definition_tests[n].defn))
        && TEST_ptr(q = ossl_parse_query(NULL, definition_tests[n].query))
        && TEST_int_eq(ossl_property_match_count(q, d), definition_tests[n].e);

    ossl_property_free(d);
    ossl_property_free(q);
    ossl_method_store_free(store);
    return r;
}

static int test_register_deregister(void)
{
    static const struct {
        int nid;
        const char *prop;
        char *impl;
    } impls[] = {
        { 6, "position=1", "a" },
        { 6, "position=2", "b" },
        { 6, "position=3", "c" },
        { 6, "position=4", "d" },
    };
    size_t i;
    int ret = 0;
    OSSL_METHOD_STORE *store;

    if (!TEST_ptr(store = ossl_method_store_new(NULL))
        || !add_property_names("position", NULL))
        goto err;

    for (i = 0; i < OSSL_NELEM(impls); i++)
        if (!TEST_true(ossl_method_store_add(store, NULL, impls[i].nid,
                                             impls[i].prop, impls[i].impl,
                                             &up_ref, &down_ref))) {
            TEST_note("iteration %zd", i + 1);
            goto err;
        }

    /* Deregister in a different order to registration */
    for (i = 0; i < OSSL_NELEM(impls); i++) {
        const size_t j = (1 + i * 3) % OSSL_NELEM(impls);
        int nid = impls[j].nid;
        void *impl = impls[j].impl;

        if (!TEST_true(ossl_method_store_remove(store, nid, impl))
            || !TEST_false(ossl_method_store_remove(store, nid, impl))) {
            TEST_note("iteration %zd, position %zd", i + 1, j + 1);
            goto err;
        }
    }

    if (TEST_false(ossl_method_store_remove(store, impls[0].nid, impls[0].impl)))
        ret = 1;
err:
    ossl_method_store_free(store);
    return ret;
}

static int test_property(void)
{
    static const struct {
        int nid;
        const char *prop;
        char *impl;
    } impls[] = {
        { 1, "fast=no, colour=green", "a" },
        { 1, "fast, colour=blue", "b" },
        { 1, "", "-" },
        { 9, "sky=blue, furry", "c" },
        { 3, NULL, "d" },
        { 6, "sky.colour=blue, sky=green, old.data", "e" },
    };
    static struct {
        int nid;
        const char *prop;
        char *expected;
    } queries[] = {
        { 1, "fast", "b" },
        { 1, "fast=yes", "b" },
        { 1, "fast=no, colour=green", "a" },
        { 1, "colour=blue, fast", "b" },
        { 1, "colour=blue", "b" },
        { 9, "furry", "c" },
        { 6, "sky.colour=blue", "e" },
        { 6, "old.data", "e" },
        { 9, "furry=yes, sky=blue", "c" },
        { 1, "", "a" },
        { 3, "", "d" },
    };
    OSSL_METHOD_STORE *store;
    size_t i;
    int ret = 0;
    void *result;

    if (!TEST_ptr(store = ossl_method_store_new(NULL))
        || !add_property_names("fast", "colour", "sky", "furry", NULL))
        goto err;

    for (i = 0; i < OSSL_NELEM(impls); i++)
        if (!TEST_true(ossl_method_store_add(store, NULL, impls[i].nid,
                                             impls[i].prop, impls[i].impl,
                                             &up_ref, &down_ref))) {
            TEST_note("iteration %zd", i + 1);
            goto err;
        }
    for (i = 0; i < OSSL_NELEM(queries); i++) {
        OSSL_PROPERTY_LIST *pq = NULL;

        if (!TEST_true(ossl_method_store_fetch(store, queries[i].nid,
                                               queries[i].prop, &result))
            || !TEST_str_eq((char *)result, queries[i].expected)) {
            TEST_note("iteration %zd", i + 1);
            ossl_property_free(pq);
            goto err;
        }
        ossl_property_free(pq);
    }
    ret = 1;
err:
    ossl_method_store_free(store);
    return ret;
}

static int test_query_cache_stochastic(void)
{
    const int max = 10000, tail = 10;
    OSSL_METHOD_STORE *store;
    int i, res = 0;
    char buf[50];
    void *result;
    int errors = 0;
    int v[10001];

    if (!TEST_ptr(store = ossl_method_store_new(NULL))
        || !add_property_names("n", NULL))
        goto err;

    for (i = 1; i <= max; i++) {
        v[i] = 2 * i;
        BIO_snprintf(buf, sizeof(buf), "n=%d\n", i);
        if (!TEST_true(ossl_method_store_add(store, NULL, i, buf, "abc",
                                             &up_ref, &down_ref))
                || !TEST_true(ossl_method_store_cache_set(store, i, buf, v + i,
                                                          &up_ref, &down_ref))
                || !TEST_true(ossl_method_store_cache_set(store, i, "n=1234",
                                                          "miss", &up_ref,
                                                          &down_ref))) {
            TEST_note("iteration %d", i);
            goto err;
        }
    }
    for (i = 1; i <= max; i++) {
        BIO_snprintf(buf, sizeof(buf), "n=%d\n", i);
        if (!ossl_method_store_cache_get(store, i, buf, &result)
            || result != v + i)
            errors++;
    }
    /* There is a tiny probability that this will fail when it shouldn't */
    res = TEST_int_gt(errors, tail) && TEST_int_lt(errors, max - tail);

err:
    ossl_method_store_free(store);
    return res;
}

int setup_tests(void)
{
    ADD_TEST(test_property_string);
    ADD_ALL_TESTS(test_property_parse, OSSL_NELEM(parser_tests));
    ADD_ALL_TESTS(test_property_merge, OSSL_NELEM(merge_tests));
    ADD_TEST(test_property_defn_cache);
    ADD_ALL_TESTS(test_definition_compares, OSSL_NELEM(definition_tests));
    ADD_TEST(test_register_deregister);
    ADD_TEST(test_property);
    ADD_TEST(test_query_cache_stochastic);
    return 1;
}
