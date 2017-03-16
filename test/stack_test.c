/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ====================================================================
 * Copyright (c) 2017 Oracle and/or its affiliates.  All rights reserved.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/safestack.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "e_os.h"
#include "test_main.h"
#include "testutil.h"

/* The macros below generate unused functions which error out one of the clang
 * builds.  We disable this check here.
 */
#ifdef __clang__
#pragma clang diagnostic ignored "-Wunused-function"
#endif

typedef struct {
    int n;
    char c;
} SS;

typedef union {
    int n;
    char c;
} SU;

DEFINE_SPECIAL_STACK_OF(sint, int)
DEFINE_SPECIAL_STACK_OF_CONST(uchar, unsigned char)
DEFINE_STACK_OF(SS)
DEFINE_STACK_OF_CONST(SU)

static int int_compare(const int *const *a, const int *const *b)
{
    if (**a < **b)
        return -1;
    if (**a > **b)
        return 1;
    return 0;
}

static int test_int_stack(void)
{
    static int v[] = { 1, 2, -4, 16, 999, 1, -173, 1, 9 };
    static int notpresent = -1;
    const int n = OSSL_NELEM(v);
    static struct {
        int value;
        int unsorted;
        int sorted;
        int ex;
    } finds[] = {
        { 2,    1,  5,  5   },
        { 9,    7,  6,  6   },
        { -173, 5,  0,  0   },
        { 999,  3,  8,  8   },
        { 0,   -1, -1,  1   }
    };
    const int n_finds = OSSL_NELEM(finds);
    static struct {
        int value;
        int ex;
    } exfinds[] = {
        { 3,    5   },
        { 1000, 8   },
        { 20,   8   },
        { -999, 0   },
        { -5,   0   },
        { 8,    5   }
    };
    const int n_exfinds = OSSL_NELEM(exfinds);
    STACK_OF(sint) *s = sk_sint_new_null();
    int i;
    int testresult = 0;

    /* Check push and num */
    for (i = 0; i < n; i++) {
        if (sk_sint_num(s) != i) {
            fprintf(stderr, "test int stack size %d\n", i);
            goto end;
        }
        sk_sint_push(s, v + i);
    }
    if (sk_sint_num(s) != n) {
        fprintf(stderr, "test int stack size %d\n", n);
        goto end;
    }

    /* check the values */
    for (i = 0; i < n; i++)
        if (sk_sint_value(s, i) != v + i) {
            fprintf(stderr, "test int value %d\n", i);
            goto end;
        }

    /* find unsorted -- the pointers are compared */
    for (i = 0; i < n_finds; i++) {
        int *val = (finds[i].unsorted == -1) ? &notpresent
                                             : v + finds[i].unsorted;

        if (sk_sint_find(s, val) != finds[i].unsorted) {
            fprintf(stderr, "test int unsorted find %d\n", i);
            goto end;
        }
    }

    /* find_ex unsorted */
    for (i = 0; i < n_finds; i++) {
        int *val = (finds[i].unsorted == -1) ? &notpresent
                                             : v + finds[i].unsorted;

        if (sk_sint_find_ex(s, val) != finds[i].unsorted) {
            fprintf(stderr, "test int unsorted find_ex %d\n", i);
            goto end;
        }
    }

    /* sorting */
    if (sk_sint_is_sorted(s)) {
        fprintf(stderr, "test int unsorted\n");
        goto end;
    }
    sk_sint_set_cmp_func(s, &int_compare);
    sk_sint_sort(s);
    if (!sk_sint_is_sorted(s)) {
        fprintf(stderr, "test int sorted\n");
        goto end;
    }

    /* find sorted -- the value is matched so we don't need to locate it */
    for (i = 0; i < n_finds; i++)
        if (sk_sint_find(s, &finds[i].value) != finds[i].sorted) {
            fprintf(stderr, "test int sorted find %d\n", i);
            goto end;
        }

    /* find_ex sorted */
    for (i = 0; i < n_finds; i++)
        if (sk_sint_find_ex(s, &finds[i].value) != finds[i].ex) {
            fprintf(stderr, "test int sorted find_ex present %d\n", i);
            goto end;
        }
    for (i = 0; i < n_exfinds; i++)
        if (sk_sint_find_ex(s, &exfinds[i].value) != exfinds[i].ex) {
            fprintf(stderr, "test int sorted find_ex absent %d\n", i);
            goto end;
        }

    /* shift */
    if (sk_sint_shift(s) != v + 6) {
        fprintf(stderr, "test int shift\n");
        goto end;
    }

    testresult = 1;
end:
    sk_sint_free(s);
    return testresult;
}

static int uchar_compare(const unsigned char *const *a,
                         const unsigned char *const *b)
{
    return **a - (signed int)**b;
}

static int test_uchar_stack(void)
{
    static const unsigned char v[] = { 1, 3, 7, 5, 255, 0 };
    const int n = OSSL_NELEM(v);
    STACK_OF(uchar) *s = sk_uchar_new(&uchar_compare), *r = NULL;
    int i;
    int testresult = 0;

    /* unshift and num */
    for (i = 0; i < n; i++) {
        if (sk_uchar_num(s) != i) {
            fprintf(stderr, "test uchar stack size %d\n", i);
            goto end;
        }
        sk_uchar_unshift(s, v + i);
    }
    if (sk_uchar_num(s) != n) {
        fprintf(stderr, "test uchar stack size %d\n", n);
        goto end;
    }

    /* dup */
    r = sk_uchar_dup(s);
    if (sk_uchar_num(r) != n) {
        fprintf(stderr, "test uchar dup size %d\n", n);
        goto end;
    }
    sk_uchar_sort(r);

    /* pop */
    for (i = 0; i < n; i++) 
        if (sk_uchar_pop(s) != v + i) {
            fprintf(stderr, "test uchar pop %d\n", i);
            goto end;
        }

    /* free -- we rely on the debug malloc to detect leakage here */
    sk_uchar_free(s);
    s = NULL;

    /* dup again */
    if (sk_uchar_num(r) != n) {
        fprintf(stderr, "test uchar dup size %d\n", n);
        goto end;
    }

    /* zero */
    sk_uchar_zero(r);
    if (sk_uchar_num(r) != 0) {
        fprintf(stderr, "test uchar zero %d\n", n);
        goto end;
    }

    /* insert */
    sk_uchar_insert(r, v, 0);
    sk_uchar_insert(r, v + 2, -1);
    sk_uchar_insert(r, v + 1, 1);
    for (i = 0; i < 3; i++)
        if (sk_uchar_value(r, i) != v + i) {
            fprintf(stderr, "test uchar insert %d\n", i);
            goto end;
        }

    /* delete */
    if (sk_uchar_delete(r, 12) != NULL) {
        fprintf(stderr, "test uchar delete missing %d\n", n);
        goto end;
    }
    if (sk_uchar_delete(r, 1) != v + 1) {
        fprintf(stderr, "test uchar delete middle %d\n", n);
        goto end;
    }

    /* set */
    sk_uchar_set(r, 1, v + 1);
    for (i = 0; i < 2; i++)
        if (sk_uchar_value(r, i) != v + i) {
            fprintf(stderr, "test uchar set %d\n", i);
            goto end;
        }

    testresult = 1;
end:
    sk_uchar_free(r);
    sk_uchar_free(s);
    return testresult;
}

static SS *SS_copy(const SS *p)
{
    SS *q = OPENSSL_malloc(sizeof(*q));

    if (q != NULL)
        memcpy(q, p, sizeof(*q));
    return q;
}

static void SS_free(SS *p) {
    OPENSSL_free(p);
}

static int test_SS_stack(void)
{
    STACK_OF(SS) *s = sk_SS_new_null();
    STACK_OF(SS) *r = NULL;
    SS *v[10], *p;
    const int n = OSSL_NELEM(v);
    int i;
    int testresult = 0;

    /* allocate and push */
    for (i = 0; i < n; i++) {
        v[i] = OPENSSL_malloc(sizeof(*v[i]));

        if (v[i] == NULL) {
            fprintf(stderr, "test SS memory allocation failure\n");
            goto end;
        }
        v[i]->n = i;
        v[i]->c = 'A' + i;
        if (sk_SS_num(s) != i) {
            fprintf(stderr, "test SS stack size %d\n", i);
            goto end;
        }
        sk_SS_push(s, v[i]);
    }
    if (sk_SS_num(s) != n) {
        fprintf(stderr, "test SS size %d\n", n);
        goto end;
    }

    /* deepcopy */
    r = sk_SS_deep_copy(s, &SS_copy, &SS_free);
    if (r == NULL) {
        fprintf(stderr, "test SS deepcopy failure\n");
        goto end;
    }
    for (i = 0; i < n; i++) {
        p = sk_SS_value(r, i);
        if (p == v[i]) {
            fprintf(stderr, "test SS deepcopy non-copy %d\n", i);
            goto end;
        }
        if (p->n != v[i]->n || p->c != v[i]->c) {
            fprintf(stderr, "test SS deepcopy values %d\n", i);
            goto end;
        }
    }

    /* pop_free - we rely on the malloc debug to catch the leak */
    sk_SS_pop_free(r, &SS_free);
    r = NULL;

    /* delete_ptr */
    if ((p = sk_SS_delete_ptr(s, v[3])) == NULL) {
        fprintf(stderr, "test SS delete ptr not found\n");
        goto end;
    }
    SS_free(p);
    if (sk_SS_num(s) != n-1) {
        fprintf(stderr, "test SS delete ptr size\n");
        goto end;
    }
    for (i = 0; i < n-1; i++)
        if (sk_SS_value(s, i) != v[i<3 ? i : 1+i]) {
            fprintf(stderr, "test SS delete ptr item %d\n", i);
            goto end;
        }

    testresult = 1;
end:
    sk_SS_pop_free(r, &SS_free);
    sk_SS_pop_free(s, &SS_free);
    return testresult;
}

static int test_SU_stack(void)
{
    STACK_OF(SU) *s = sk_SU_new_null();
    SU v[10];
    const int n = OSSL_NELEM(v);
    int i;
    int testresult = 0;

    /* allocate and push */
    for (i = 0; i < n; i++) {
        if ((i & 1) == 0)
            v[i].n = i;
        else
            v[i].c = 'A' + i;
        if (sk_SU_num(s) != i) {
            fprintf(stderr, "test SU stack size %d\n", i);
            goto end;
        }
        sk_SU_push(s, v + i);
    }
    if (sk_SU_num(s) != n) {
        fprintf(stderr, "test SU size %d\n", n);
        goto end;
    }

    /* check the pointers are correct */
    for (i = 0; i < n; i++)
        if (sk_SU_value(s, i) != v + i) {
            fprintf(stderr, "test SU pointer check %d\n", i);
            goto end;
        }

    testresult = 1;
end:
    sk_SU_free(s);
    return testresult;
}

void register_tests(void)
{
    ADD_TEST(test_int_stack);
    ADD_TEST(test_uchar_stack);
    ADD_TEST(test_SS_stack);
    ADD_TEST(test_SU_stack);
}
