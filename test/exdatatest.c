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

static long saved_argl;
static void *saved_argp;
static int saved_idx;

static void exnew(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
          int idx, long argl, void *argp)
{
    OPENSSL_assert(idx == saved_idx);
    OPENSSL_assert(argl == saved_argl);
    OPENSSL_assert(argp == saved_argp);
    OPENSSL_assert(ptr == NULL);
}

static int exdup(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
          void *from_d, int idx, long argl, void *argp)
{
    OPENSSL_assert(idx == saved_idx);
    OPENSSL_assert(argl == saved_argl);
    OPENSSL_assert(argp == saved_argp);
    OPENSSL_assert(from_d != NULL);
    return 1;
}

static void exfree(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
            int idx, long argl, void *argp)
{
    OPENSSL_assert(idx == saved_idx);
    OPENSSL_assert(argl == saved_argl);
    OPENSSL_assert(argp == saved_argp);
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
    OPENSSL_assert(obj->st != 0);
    return obj;
}

static void MYOBJ_sethello(MYOBJ *obj, char *cp)
{
    obj->st = CRYPTO_set_ex_data(&obj->ex_data, saved_idx, cp);
    OPENSSL_assert(obj->st != 0);
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

    obj->st = CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_APP, &obj->ex_data,
                                 &in->ex_data);
    OPENSSL_assert(obj->st != 0);
    return obj;
}

int main()
{
    MYOBJ *t1, *t2, *t3;
    const char *cp;
    char *p;

    p = strdup("hello world");
    saved_argl = 21;
    saved_argp = malloc(1);
    saved_idx = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_APP,
                                        saved_argl, saved_argp,
                                        exnew, exdup, exfree);
    t1 = MYOBJ_new();
    t2 = MYOBJ_new();
    MYOBJ_sethello(t1, p);
    cp = MYOBJ_gethello(t1);
    OPENSSL_assert(cp == p);
    if (cp != p)
        return 1;
    cp = MYOBJ_gethello(t2);
    OPENSSL_assert(cp == NULL);
    if (cp != NULL)
        return 1;
    t3 = MYOBJ_dup(t1);
    cp = MYOBJ_gethello(t3);
    OPENSSL_assert(cp == p);
    if (cp != p)
        return 1;
    cp = MYOBJ_gethello(t2);
    MYOBJ_free(t1);
    MYOBJ_free(t2);
    MYOBJ_free(t3);
    free(saved_argp);
    free(p);
    return 0;
}
