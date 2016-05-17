/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/stack.h>
#include <openssl/objects.h>

struct stack_st {
    int num;
    char **data;
    int sorted;
    int num_alloc;
    int (*comp) (const void *, const void *);
};

#undef MIN_NODES
#define MIN_NODES       4

#include <errno.h>

int (*sk_set_cmp_func(_STACK *sk, int (*c) (const void *, const void *)))
 (const void *, const void *) {
    int (*old) (const void *, const void *) = sk->comp;

    if (sk->comp != c)
        sk->sorted = 0;
    sk->comp = c;

    return old;
}

_STACK *sk_dup(_STACK *sk)
{
    _STACK *ret;
    char **s;

    if ((ret = sk_new(sk->comp)) == NULL)
        goto err;
    s = OPENSSL_realloc((char *)ret->data,
                        (unsigned int)sizeof(char *) * sk->num_alloc);
    if (s == NULL)
        goto err;
    ret->data = s;

    ret->num = sk->num;
    memcpy(ret->data, sk->data, sizeof(char *) * sk->num);
    ret->sorted = sk->sorted;
    ret->num_alloc = sk->num_alloc;
    ret->comp = sk->comp;
    return (ret);
 err:
    sk_free(ret);
    return (NULL);
}

_STACK *sk_deep_copy(_STACK *sk, void *(*copy_func) (void *),
                     void (*free_func) (void *))
{
    _STACK *ret;
    int i;

    if ((ret = OPENSSL_malloc(sizeof(_STACK))) == NULL)
        return ret;
    ret->comp = sk->comp;
    ret->sorted = sk->sorted;
    ret->num = sk->num;
    ret->num_alloc = sk->num > MIN_NODES ? sk->num : MIN_NODES;
    ret->data = OPENSSL_malloc(sizeof(*ret->data) * ret->num_alloc);
    if (ret->data == NULL) {
        OPENSSL_free(ret);
        return NULL;
    }
    for (i = 0; i < ret->num_alloc; i++)
        ret->data[i] = NULL;

    for (i = 0; i < ret->num; ++i) {
        if (sk->data[i] == NULL)
            continue;
        if ((ret->data[i] = copy_func(sk->data[i])) == NULL) {
            while (--i >= 0)
                if (ret->data[i] != NULL)
                    free_func(ret->data[i]);
            sk_free(ret);
            return NULL;
        }
    }
    return ret;
}

_STACK *sk_new_null(void)
{
    return sk_new((int (*)(const void *, const void *))0);
}

_STACK *sk_new(int (*c) (const void *, const void *))
{
    _STACK *ret;

    if ((ret = OPENSSL_zalloc(sizeof(_STACK))) == NULL)
        goto err;
    if ((ret->data = OPENSSL_zalloc(sizeof(*ret->data) * MIN_NODES)) == NULL)
        goto err;
    ret->comp = c;
    ret->num_alloc = MIN_NODES;
    return (ret);

 err:
    OPENSSL_free(ret);
    return (NULL);
}

int sk_insert(_STACK *st, void *data, int loc)
{
    char **s;

    if (st == NULL)
        return 0;
    if (st->num_alloc <= st->num + 1) {
        s = OPENSSL_realloc((char *)st->data,
                            (unsigned int)sizeof(char *) * st->num_alloc * 2);
        if (s == NULL)
            return (0);
        st->data = s;
        st->num_alloc *= 2;
    }
    if ((loc >= (int)st->num) || (loc < 0))
        st->data[st->num] = data;
    else {
        memmove(&(st->data[loc + 1]),
                &(st->data[loc]), sizeof(char *) * (st->num - loc));
        st->data[loc] = data;
    }
    st->num++;
    st->sorted = 0;
    return (st->num);
}

void *sk_delete_ptr(_STACK *st, void *p)
{
    int i;

    for (i = 0; i < st->num; i++)
        if (st->data[i] == p)
            return (sk_delete(st, i));
    return (NULL);
}

void *sk_delete(_STACK *st, int loc)
{
    char *ret;
    int i, j;

    if (!st || (loc < 0) || (loc >= st->num))
        return NULL;

    ret = st->data[loc];
    if (loc != st->num - 1) {
        j = st->num - 1;
        for (i = loc; i < j; i++)
            st->data[i] = st->data[i + 1];
        /*
         * In theory memcpy is not safe for this memcpy( &(st->data[loc]),
         * &(st->data[loc+1]), sizeof(char *)*(st->num-loc-1));
         */
    }
    st->num--;
    return (ret);
}

static int internal_find(_STACK *st, void *data, int ret_val_options)
{
    const void *const *r;
    int i;

    if (st == NULL)
        return -1;

    if (st->comp == NULL) {
        for (i = 0; i < st->num; i++)
            if (st->data[i] == data)
                return (i);
        return (-1);
    }
    sk_sort(st);
    if (data == NULL)
        return (-1);
    r = OBJ_bsearch_ex_(&data, st->data, st->num, sizeof(void *), st->comp,
                        ret_val_options);
    if (r == NULL)
        return (-1);
    return (int)((char **)r - st->data);
}

int sk_find(_STACK *st, void *data)
{
    return internal_find(st, data, OBJ_BSEARCH_FIRST_VALUE_ON_MATCH);
}

int sk_find_ex(_STACK *st, void *data)
{
    return internal_find(st, data, OBJ_BSEARCH_VALUE_ON_NOMATCH);
}

int sk_push(_STACK *st, void *data)
{
    return (sk_insert(st, data, st->num));
}

int sk_unshift(_STACK *st, void *data)
{
    return (sk_insert(st, data, 0));
}

void *sk_shift(_STACK *st)
{
    if (st == NULL)
        return (NULL);
    if (st->num <= 0)
        return (NULL);
    return (sk_delete(st, 0));
}

void *sk_pop(_STACK *st)
{
    if (st == NULL)
        return (NULL);
    if (st->num <= 0)
        return (NULL);
    return (sk_delete(st, st->num - 1));
}

void sk_zero(_STACK *st)
{
    if (st == NULL)
        return;
    if (st->num <= 0)
        return;
    memset(st->data, 0, sizeof(*st->data) * st->num);
    st->num = 0;
}

void sk_pop_free(_STACK *st, void (*func) (void *))
{
    int i;

    if (st == NULL)
        return;
    for (i = 0; i < st->num; i++)
        if (st->data[i] != NULL)
            func(st->data[i]);
    sk_free(st);
}

void sk_free(_STACK *st)
{
    if (st == NULL)
        return;
    OPENSSL_free(st->data);
    OPENSSL_free(st);
}

int sk_num(const _STACK *st)
{
    if (st == NULL)
        return -1;
    return st->num;
}

void *sk_value(const _STACK *st, int i)
{
    if (!st || (i < 0) || (i >= st->num))
        return NULL;
    return st->data[i];
}

void *sk_set(_STACK *st, int i, void *value)
{
    if (!st || (i < 0) || (i >= st->num))
        return NULL;
    return (st->data[i] = value);
}

void sk_sort(_STACK *st)
{
    if (st && !st->sorted && st->comp != NULL) {
        int (*comp_func) (const void *, const void *);

        /*
         * same comment as in sk_find ... previously st->comp was declared as
         * a (void*,void*) callback type, but this made the population of the
         * callback pointer illogical - our callbacks compare type** with
         * type**, so we leave the casting until absolutely necessary (ie.
         * "now").
         */
        comp_func = (int (*)(const void *, const void *))(st->comp);
        qsort(st->data, st->num, sizeof(char *), comp_func);
        st->sorted = 1;
    }
}

int sk_is_sorted(const _STACK *st)
{
    if (!st)
        return 1;
    return st->sorted;
}
