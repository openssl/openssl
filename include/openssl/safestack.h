/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SAFESTACK_H
# define HEADER_SAFESTACK_H

# include <openssl/stack.h>
# include <openssl/e_os2.h>

#ifdef __cplusplus
extern "C" {
#endif

# ifndef CHECKED_PTR_OF
#  define CHECKED_PTR_OF(type, p) ((void*) (1 ? p : (type*)0))
# endif

/*
 * In C++ we get problems because an explicit cast is needed from (void *) we
 * use CHECKED_STACK_OF to ensure the correct type is passed in the macros
 * below.
 */

# define CHECKED_STACK_OF(type, p) \
    ((_STACK*) (1 ? p : (STACK_OF(type)*)0))

# define CHECKED_SK_COPY_FUNC(type, p) \
    ((void *(*)(void *)) ((1 ? p : (type *(*)(const type *))0)))

# define CHECKED_SK_FREE_FUNC(type, p) \
    ((void (*)(void *)) ((1 ? p : (void (*)(type *))0)))

# define CHECKED_SK_CMP_FUNC(type, p) \
    ((int (*)(const void *, const void *)) \
        ((1 ? p : (int (*)(const type * const *, const type * const *))0)))

# define STACK_OF(type) struct stack_st_##type

# define SKM_DEFINE_STACK_OF(t1, t2, t3) \
    STACK_OF(t1); \
    static ossl_inline int sk_##t1##_num(const STACK_OF(t1) *sk) \
    { \
        return sk_num((const _STACK *)sk); \
    } \
    static ossl_inline t2 *sk_##t1##_value(const STACK_OF(t1) *sk, int idx) \
    { \
        return (t2 *)sk_value((const _STACK *)sk, idx); \
    } \
    static ossl_inline STACK_OF(t1) *sk_##t1##_new(int (*cmpf)(const t3 * const *a, const t3 * const *b)) \
    { \
        return (STACK_OF(t1) *)sk_new((int (*)(const void *a, const void *b))cmpf); \
    } \
    static ossl_inline STACK_OF(t1) *sk_##t1##_new_null(void) \
    { \
        return (STACK_OF(t1) *)sk_new_null(); \
    } \
    static ossl_inline void sk_##t1##_free(STACK_OF(t1) *sk) \
    { \
        sk_free((_STACK *)sk); \
    } \
    static ossl_inline void sk_##t1##_zero(STACK_OF(t1) *sk) \
    { \
        sk_zero((_STACK *)sk); \
    } \
    static ossl_inline t2 *sk_##t1##_delete(STACK_OF(t1) *sk, int i) \
    { \
        return (t2 *)sk_delete((_STACK *)sk, i); \
    } \
    static ossl_inline t2 *sk_##t1##_delete_ptr(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return (t2 *)sk_delete_ptr((_STACK *)sk, (void *)ptr); \
    } \
    static ossl_inline int sk_##t1##_push(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return sk_push((_STACK *)sk, (void *)ptr); \
    } \
    static ossl_inline int sk_##t1##_unshift(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return sk_unshift((_STACK *)sk, (void *)ptr); \
    } \
    static ossl_inline t2 *sk_##t1##_pop(STACK_OF(t1) *sk) \
    { \
        return (t2 *)sk_pop((_STACK *)sk); \
    } \
    static ossl_inline t2 *sk_##t1##_shift(STACK_OF(t1) *sk) \
    { \
        return (t2 *)sk_shift((_STACK *)sk); \
    } \
    static ossl_inline void sk_##t1##_pop_free(STACK_OF(t1) *sk, void (*func)(t3 *a)) \
    { \
        sk_pop_free((_STACK *)sk, (void (*)(void *))func); \
    } \
    static ossl_inline int sk_##t1##_insert(STACK_OF(t1) *sk, t2 *ptr, int idx) \
    { \
        return sk_insert((_STACK *)sk, (void *)ptr, idx); \
    } \
    static ossl_inline t2 *sk_##t1##_set(STACK_OF(t1) *sk, int idx, t2 *ptr) \
    { \
        return (t2 *)sk_set((_STACK *)sk, idx, (void *)ptr); \
    } \
    static ossl_inline int sk_##t1##_find(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return sk_find((_STACK *)sk, (void *)ptr); \
    } \
    static ossl_inline int sk_##t1##_find_ex(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return sk_find_ex((_STACK *)sk, (void *)ptr); \
    } \
    static ossl_inline void sk_##t1##_sort(STACK_OF(t1) *sk) \
    { \
        sk_sort((_STACK *)sk); \
    } \
    static ossl_inline int sk_##t1##_is_sorted(const STACK_OF(t1) *sk) \
    { \
        return sk_is_sorted((const _STACK *)sk); \
    } \
    static ossl_inline STACK_OF(t1) * sk_##t1##_dup(STACK_OF(t1) *sk) \
    { \
        return (STACK_OF(t1) *)sk_dup((_STACK *)sk); \
    } \
    static ossl_inline STACK_OF(t1) *sk_##t1##_deep_copy(STACK_OF(t1) *sk, \
                                                    t3 *(*copyfn)(const t3 *), \
                                                    void (*freefn)(t3 *)) \
    { \
        return (STACK_OF(t1) *)sk_deep_copy((_STACK *)sk, \
                                            (void * (*)(void *a))copyfn, \
                                            (void (*)(void *a))freefn); \
    } \
    static ossl_inline int (*sk_##t1##_set_cmp_func(STACK_OF(t1) *sk, int (*cmpf)(const t3 * const *a, const t3 * const *b)))(const t3 * const *, const t3 * const *) \
    { \
        return (int (*)(const t3 * const *,const t3 * const *))sk_set_cmp_func((_STACK *)sk, (int (*)(const void *a, const void *b))cmpf); \
    }

# define DEFINE_SPECIAL_STACK_OF(t1, t2) SKM_DEFINE_STACK_OF(t1, t2, t2)
# define DEFINE_STACK_OF(t) SKM_DEFINE_STACK_OF(t, t, t)
# define DEFINE_STACK_OF_CONST(t) SKM_DEFINE_STACK_OF(t, const t, t)

/*-
 * Strings are special: normally an lhash entry will point to a single
 * (somewhat) mutable object. In the case of strings:
 *
 * a) Instead of a single char, there is an array of chars, NUL-terminated.
 * b) The string may have be immutable.
 *
 * So, they need their own declarations. Especially important for
 * type-checking tools, such as Deputy.
 *
 * In practice, however, it appears to be hard to have a const
 * string. For now, I'm settling for dealing with the fact it is a
 * string at all.
 */
typedef char *OPENSSL_STRING;
typedef const char *OPENSSL_CSTRING;

/*-
 * Confusingly, LHASH_OF(STRING) deals with char ** throughout, but
 * STACK_OF(STRING) is really more like STACK_OF(char), only, as mentioned
 * above, instead of a single char each entry is a NUL-terminated array of
 * chars. So, we have to implement STRING specially for STACK_OF. This is
 * dealt with in the autogenerated macros below.
 */
DEFINE_SPECIAL_STACK_OF(OPENSSL_STRING, char)

/*
 * Similarly, we sometimes use a block of characters, NOT nul-terminated.
 * These should also be distinguished from "normal" stacks.
 */
typedef void *OPENSSL_BLOCK;
DEFINE_SPECIAL_STACK_OF(OPENSSL_BLOCK, void)

# ifdef  __cplusplus
}
# endif
#endif
