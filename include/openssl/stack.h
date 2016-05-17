/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_STACK_H
# define HEADER_STACK_H

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct stack_st _STACK; /* Use STACK_OF(...) instead */

int sk_num(const _STACK *);
void *sk_value(const _STACK *, int);

void *sk_set(_STACK *, int, void *);

_STACK *sk_new(int (*cmp) (const void *, const void *));
_STACK *sk_new_null(void);
void sk_free(_STACK *);
void sk_pop_free(_STACK *st, void (*func) (void *));
_STACK *sk_deep_copy(_STACK *, void *(*)(void *), void (*)(void *));
int sk_insert(_STACK *sk, void *data, int where);
void *sk_delete(_STACK *st, int loc);
void *sk_delete_ptr(_STACK *st, void *p);
int sk_find(_STACK *st, void *data);
int sk_find_ex(_STACK *st, void *data);
int sk_push(_STACK *st, void *data);
int sk_unshift(_STACK *st, void *data);
void *sk_shift(_STACK *st);
void *sk_pop(_STACK *st);
void sk_zero(_STACK *st);
int (*sk_set_cmp_func(_STACK *sk, int (*c) (const void *, const void *)))
 (const void *, const void *);
_STACK *sk_dup(_STACK *st);
void sk_sort(_STACK *st);
int sk_is_sorted(const _STACK *st);

#ifdef  __cplusplus
}
#endif

#endif
