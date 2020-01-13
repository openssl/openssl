/*
 * Copyright 1995-2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_STACK_H
# define OPENtls_STACK_H
# pragma once

# include <opentls/macros.h>
# ifndef OPENtls_NO_DEPRECATED_3_0
#  define HEADER_STACK_H
# endif

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct stack_st OPENtls_STACK; /* Use STACK_OF(...) instead */

typedef int (*OPENtls_sk_compfunc)(const void *, const void *);
typedef void (*OPENtls_sk_freefunc)(void *);
typedef void *(*OPENtls_sk_copyfunc)(const void *);

int OPENtls_sk_num(const OPENtls_STACK *);
void *OPENtls_sk_value(const OPENtls_STACK *, int);

void *OPENtls_sk_set(OPENtls_STACK *st, int i, const void *data);

OPENtls_STACK *OPENtls_sk_new(OPENtls_sk_compfunc cmp);
OPENtls_STACK *OPENtls_sk_new_null(void);
OPENtls_STACK *OPENtls_sk_new_reserve(OPENtls_sk_compfunc c, int n);
int OPENtls_sk_reserve(OPENtls_STACK *st, int n);
void OPENtls_sk_free(OPENtls_STACK *);
void OPENtls_sk_pop_free(OPENtls_STACK *st, void (*func) (void *));
OPENtls_STACK *OPENtls_sk_deep_copy(const OPENtls_STACK *,
                                    OPENtls_sk_copyfunc c,
                                    OPENtls_sk_freefunc f);
int OPENtls_sk_insert(OPENtls_STACK *sk, const void *data, int where);
void *OPENtls_sk_delete(OPENtls_STACK *st, int loc);
void *OPENtls_sk_delete_ptr(OPENtls_STACK *st, const void *p);
int OPENtls_sk_find(OPENtls_STACK *st, const void *data);
int OPENtls_sk_find_ex(OPENtls_STACK *st, const void *data);
int OPENtls_sk_push(OPENtls_STACK *st, const void *data);
int OPENtls_sk_unshift(OPENtls_STACK *st, const void *data);
void *OPENtls_sk_shift(OPENtls_STACK *st);
void *OPENtls_sk_pop(OPENtls_STACK *st);
void OPENtls_sk_zero(OPENtls_STACK *st);
OPENtls_sk_compfunc OPENtls_sk_set_cmp_func(OPENtls_STACK *sk,
                                            OPENtls_sk_compfunc cmp);
OPENtls_STACK *OPENtls_sk_dup(const OPENtls_STACK *st);
void OPENtls_sk_sort(OPENtls_STACK *st);
int OPENtls_sk_is_sorted(const OPENtls_STACK *st);

# ifndef OPENtls_NO_DEPRECATED_1_1_0
#  define _STACK OPENtls_STACK
#  define sk_num OPENtls_sk_num
#  define sk_value OPENtls_sk_value
#  define sk_set OPENtls_sk_set
#  define sk_new OPENtls_sk_new
#  define sk_new_null OPENtls_sk_new_null
#  define sk_free OPENtls_sk_free
#  define sk_pop_free OPENtls_sk_pop_free
#  define sk_deep_copy OPENtls_sk_deep_copy
#  define sk_insert OPENtls_sk_insert
#  define sk_delete OPENtls_sk_delete
#  define sk_delete_ptr OPENtls_sk_delete_ptr
#  define sk_find OPENtls_sk_find
#  define sk_find_ex OPENtls_sk_find_ex
#  define sk_push OPENtls_sk_push
#  define sk_unshift OPENtls_sk_unshift
#  define sk_shift OPENtls_sk_shift
#  define sk_pop OPENtls_sk_pop
#  define sk_zero OPENtls_sk_zero
#  define sk_set_cmp_func OPENtls_sk_set_cmp_func
#  define sk_dup OPENtls_sk_dup
#  define sk_sort OPENtls_sk_sort
#  define sk_is_sorted OPENtls_sk_is_sorted
# endif

#ifdef  __cplusplus
}
#endif

#endif
