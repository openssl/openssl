/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Copyright (c) 2017 Oracle and/or its affiliates.  All rights reserved.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/lhash.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "e_os.h"
#include "test_main.h"
#include "testutil.h"

/*
 * The macros below generate unused functions which error out one of the clang
 * builds.  We disable this check here.
 */
#ifdef __clang__
#pragma clang diagnostic ignored "-Wunused-function"
#endif

DEFINE_LHASH_OF(int);

static int int_tests[] = { 65537, 13, 1, 3, -5, 6, 7, 4, -10, -12, -14, 22, 9,
                           -17, 16, 17, -23, 35, 37, 173, 11 };
static const unsigned int n_int_tests = OSSL_NELEM(int_tests);
static short int_found[OSSL_NELEM(int_tests)];

static unsigned long int int_hash(const int *p)
{
    return 3 & *p;      /* To force collisions */
}

static int int_cmp(const int *p, const int *q)
{
    return *p != *q;
}

static int int_find(int n)
{
    unsigned int i;

    for (i = 0; i < n_int_tests; i++)
        if (int_tests[i] == n)
            return i;
    return -1;
}

static void int_doall(int *v)
{
    int_found[int_find(*v)]++;
}

static void int_doall_arg(int *p, short *f)
{
    f[int_find(*p)]++;
}

IMPLEMENT_LHASH_DOALL_ARG(int, short);

static int test_int_lhash(void)
{
    static struct {
        int data;
        int null;
    } dels[] = {
        { 65537,    0 },
        { 173,      0 },
        { 999,      1 },
        { 37,       0 },
        { 1,        0 },
        { 34,       1 }     
    };
    const unsigned int n_dels = OSSL_NELEM(dels);
    LHASH_OF(int) *h = lh_int_new(&int_hash, &int_cmp);
    unsigned int i;
    int testresult = 0, j, *p;

    if (h == NULL) {
        fprintf(stderr, "test lhash int allocation\n");
        goto end;
    }

    /* insert */
    for (i = 0; i < n_int_tests; i++)
        if (lh_int_insert(h, int_tests + i) != NULL) {
            fprintf(stderr, "test lhash int insert %d\n", i);
            goto end;
        }

    /* num_items */
    if (lh_int_num_items(h) != n_int_tests) {
            fprintf(stderr, "test lhash int num items\n");
            goto end;
    }

    /* retrieve */
    for (i = 0; i < n_int_tests; i++)
        if (*lh_int_retrieve(h, int_tests + i) != int_tests[i]) {
            fprintf(stderr, "test lhash int retrieve value %d\n", i);
            goto end;
        }
    for (i = 0; i < n_int_tests; i++)
        if (lh_int_retrieve(h, int_tests + i) != int_tests + i) {
            fprintf(stderr, "test lhash int retrieve address %d\n", i);
            goto end;
        }
    j = 1;
    if (lh_int_retrieve(h, &j) != int_tests + 2) {
        fprintf(stderr, "test lhash int retrieve other\n");
        goto end;
    }

    /* replace */
    j = 13;
    if ((p = lh_int_insert(h, &j)) == NULL) {
        fprintf(stderr, "test lhash int replacement insert\n");
        goto end;
    }
    if (p != int_tests + 1) {
        fprintf(stderr, "test lhash int replacement pointer\n");
        goto end;
    }
    if (lh_int_retrieve(h, int_tests + 1) != &j) {
        fprintf(stderr, "test lhash int replacement variable\n");
        goto end;
    }

    /* do_all */
    memset(int_found, 0, sizeof(int_found));
    lh_int_doall(h, &int_doall);
    for (i = 0; i < n_int_tests; i++)
        if (int_found[i] != 1) {
            fprintf(stderr, "test lhash int doall %d\n", i);
            goto end;
        }
    
    /* do_all_arg */
    memset(int_found, 0, sizeof(int_found));
    lh_int_doall_short(h, int_doall_arg, int_found);
    for (i = 0; i < n_int_tests; i++)
        if (int_found[i] != 1) {
            fprintf(stderr, "test lhash int doall arg %d\n", i);
            goto end;
        }
    
    /* delete */
    for (i = 0; i < n_dels; i++) {
        const int b = lh_int_delete(h, &dels[i].data) == NULL;
        if ((b ^ dels[i].null) != 0) {
            fprintf(stderr, "test lhash int delete %d\n", i);
            goto end;
        }
    }

    /* error */
    if (lh_int_error(h) != 0) {
        fprintf(stderr, "test lhash int error\n");
        goto end;
    }

    testresult = 1;
end:
    lh_int_free(h);
    return testresult;
}

static unsigned long int stress_hash(const int *p)
{
    return *p;
}

static int test_stress(void)
{
    LHASH_OF(int) *h = lh_int_new(&stress_hash, &int_cmp);
    const unsigned int n = 2500000;
    unsigned int i;
    int testresult = 0, *p;

    if (h == NULL) {
        fprintf(stderr, "test lhash stress allocation\n");
        goto end;
    }

    /* insert */
    for (i = 0; i < n; i++) {
        p = OPENSSL_malloc(sizeof(i));
        if (p == NULL) {
            fprintf(stderr, "test lhash stress out of memory %d\n", i);
            goto end;
        }
        *p = 3 * i + 1;
        lh_int_insert(h, p);
    }

    /* num_items */
    if (lh_int_num_items(h) != n) {
            fprintf(stderr, "test lhash stress num items\n");
            goto end;
    }

    fprintf(stderr, "hash full statistics:\n");
    OPENSSL_LH_stats((OPENSSL_LHASH *)h, stderr);
    fprintf(stderr, "\nhash full node usage:\n");
    OPENSSL_LH_node_usage_stats((OPENSSL_LHASH *)h, stderr);

    /* delete in a different order */
    for (i = 0; i < n; i++) {
        const int j = (7 * i + 4) % n * 3 + 1;

        if ((p = lh_int_delete(h, &j)) == NULL) {
            fprintf(stderr, "test lhash stress delete %d\n", i);
            goto end;
        }
        if (*p != j) {
            fprintf(stderr, "test lhash stress bad value %d\n", i);
            goto end;
        }
        OPENSSL_free(p);
    }

    fprintf(stderr, "\nhash empty statistics:\n");
    OPENSSL_LH_stats((OPENSSL_LHASH *)h, stderr);
    fprintf(stderr, "\nhash empty node usage:\n");
    OPENSSL_LH_node_usage_stats((OPENSSL_LHASH *)h, stderr);

    testresult = 1;
end:
    lh_int_free(h);
    return testresult;
}

void register_tests(void)
{
    ADD_TEST(test_int_lhash);
    ADD_TEST(test_stress);
}
