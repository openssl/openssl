/*
 * Copyright 2015-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/crypto.h>

#include "testutil.h"

static long saved_argl;
static void *saved_argp;
static int saved_idx;
static int gbl_result;

static void exnew(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
          int idx, long argl, void *argp)
{
    if (!TEST_int_eq(idx, saved_idx)
        || !TEST_long_eq(argl, saved_argl)
        || !TEST_ptr_eq(argp, saved_argp)
        || !TEST_ptr_null(ptr))
        gbl_result = 0;
}

static int exdup(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
          void *from_d, int idx, long argl, void *argp)
{
    if (!TEST_int_eq(idx, saved_idx)
        || !TEST_long_eq(argl, saved_argl)
        || !TEST_ptr_eq(argp, saved_argp)
        || !TEST_ptr(from_d))
        gbl_result = 0;
    return 1;
}

static void exfree(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
            int idx, long argl, void *argp)
{
    if (!TEST_int_eq(idx, saved_idx)
        || !TEST_long_eq(argl, saved_argl)
        || !TEST_ptr_eq(argp, saved_argp))
        gbl_result = 0;
}

typedef struct myobj_st {
    CRYPTO_EX_DATA ex_data;
    int id;
    int st;
} MYOBJ;

static MYOBJ *MYOBJ_new()
{
    static int count = 0;
    MYOBJ *obj = OPENSSL_malloc(sizeof(*obj));

    obj->id = ++count;
    obj->st = CRYPTO_new_ex_data(CRYPTO_EX_INDEX_APP, obj, &obj->ex_data);
    return obj;
}

static void MYOBJ_sethello(MYOBJ *obj, char *cp)
{
    obj->st = CRYPTO_set_ex_data(&obj->ex_data, saved_idx, cp);
    if (!TEST_int_eq(obj->st, 1))
        gbl_result = 0;
}

static char *MYOBJ_gethello(MYOBJ *obj)
{
    return CRYPTO_get_ex_data(&obj->ex_data, saved_idx);
}

static void MYOBJ_free(MYOBJ *obj)
{
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, obj, &obj->ex_data);
    OPENSSL_free(obj);
}

static MYOBJ *MYOBJ_dup(MYOBJ *in)
{
    MYOBJ *obj = MYOBJ_new();

    obj->st |= CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_APP, &obj->ex_data,
                                 &in->ex_data);
    return obj;
}

static int test_exdata(void)
{
    MYOBJ *t1, *t2, *t3;
    const char *cp;
    char *p;

    gbl_result = 1;

    p = strdup("hello world");
    saved_argl = 21;
    saved_argp = malloc(1);
    saved_idx = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_APP,
                                        saved_argl, saved_argp,
                                        exnew, exdup, exfree);
    t1 = MYOBJ_new();
    t2 = MYOBJ_new();
    if (!TEST_int_eq(t1->st, 1) || !TEST_int_eq(t2->st, 1))
        return 0;

    MYOBJ_sethello(t1, p);
    cp = MYOBJ_gethello(t1);
    if (!TEST_ptr_eq(cp, p))
        return 0;

    cp = MYOBJ_gethello(t2);
    if (!TEST_ptr_null(cp))
        return 0;

    t3 = MYOBJ_dup(t1);
    if (!TEST_int_eq(t3->st, 1))
        return 0;

    cp = MYOBJ_gethello(t3);
    if (!TEST_ptr_eq(cp, p))
        return 0;

    MYOBJ_free(t1);
    MYOBJ_free(t2);
    MYOBJ_free(t3);
    free(saved_argp);
    free(p);

    if (gbl_result)
      return 1;
    else
      return 0;
}

void register_tests(void)
{
    ADD_TEST(test_exdata);
}
