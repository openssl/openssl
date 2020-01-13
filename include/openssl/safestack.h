/*
 * Copyright 1999-2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_SAFESTACK_H
# define OPENtls_SAFESTACK_H
# pragma once

# include <opentls/macros.h>
# ifndef OPENtls_NO_DEPRECATED_3_0
#  define HEADER_SAFESTACK_H
# endif

# include <opentls/stack.h>
# include <opentls/e_os2.h>

#ifdef __cplusplus
extern "C" {
#endif

# define STACK_OF(type) struct stack_st_##type

# define SKM_DEFINE_STACK_OF(t1, t2, t3) \
    STACK_OF(t1); \
    typedef int (*sk_##t1##_compfunc)(const t3 * const *a, const t3 *const *b); \
    typedef void (*sk_##t1##_freefunc)(t3 *a); \
    typedef t3 * (*sk_##t1##_copyfunc)(const t3 *a); \
    static otls_unused otls_inline int sk_##t1##_num(const STACK_OF(t1) *sk) \
    { \
        return OPENtls_sk_num((const OPENtls_STACK *)sk); \
    } \
    static otls_unused otls_inline t2 *sk_##t1##_value(const STACK_OF(t1) *sk, int idx) \
    { \
        return (t2 *)OPENtls_sk_value((const OPENtls_STACK *)sk, idx); \
    } \
    static otls_unused otls_inline STACK_OF(t1) *sk_##t1##_new(sk_##t1##_compfunc compare) \
    { \
        return (STACK_OF(t1) *)OPENtls_sk_new((OPENtls_sk_compfunc)compare); \
    } \
    static otls_unused otls_inline STACK_OF(t1) *sk_##t1##_new_null(void) \
    { \
        return (STACK_OF(t1) *)OPENtls_sk_new_null(); \
    } \
    static otls_unused otls_inline STACK_OF(t1) *sk_##t1##_new_reserve(sk_##t1##_compfunc compare, int n) \
    { \
        return (STACK_OF(t1) *)OPENtls_sk_new_reserve((OPENtls_sk_compfunc)compare, n); \
    } \
    static otls_unused otls_inline int sk_##t1##_reserve(STACK_OF(t1) *sk, int n) \
    { \
        return OPENtls_sk_reserve((OPENtls_STACK *)sk, n); \
    } \
    static otls_unused otls_inline void sk_##t1##_free(STACK_OF(t1) *sk) \
    { \
        OPENtls_sk_free((OPENtls_STACK *)sk); \
    } \
    static otls_unused otls_inline void sk_##t1##_zero(STACK_OF(t1) *sk) \
    { \
        OPENtls_sk_zero((OPENtls_STACK *)sk); \
    } \
    static otls_unused otls_inline t2 *sk_##t1##_delete(STACK_OF(t1) *sk, int i) \
    { \
        return (t2 *)OPENtls_sk_delete((OPENtls_STACK *)sk, i); \
    } \
    static otls_unused otls_inline t2 *sk_##t1##_delete_ptr(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return (t2 *)OPENtls_sk_delete_ptr((OPENtls_STACK *)sk, \
                                           (const void *)ptr); \
    } \
    static otls_unused otls_inline int sk_##t1##_push(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return OPENtls_sk_push((OPENtls_STACK *)sk, (const void *)ptr); \
    } \
    static otls_unused otls_inline int sk_##t1##_unshift(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return OPENtls_sk_unshift((OPENtls_STACK *)sk, (const void *)ptr); \
    } \
    static otls_unused otls_inline t2 *sk_##t1##_pop(STACK_OF(t1) *sk) \
    { \
        return (t2 *)OPENtls_sk_pop((OPENtls_STACK *)sk); \
    } \
    static otls_unused otls_inline t2 *sk_##t1##_shift(STACK_OF(t1) *sk) \
    { \
        return (t2 *)OPENtls_sk_shift((OPENtls_STACK *)sk); \
    } \
    static otls_unused otls_inline void sk_##t1##_pop_free(STACK_OF(t1) *sk, sk_##t1##_freefunc freefunc) \
    { \
        OPENtls_sk_pop_free((OPENtls_STACK *)sk, (OPENtls_sk_freefunc)freefunc); \
    } \
    static otls_unused otls_inline int sk_##t1##_insert(STACK_OF(t1) *sk, t2 *ptr, int idx) \
    { \
        return OPENtls_sk_insert((OPENtls_STACK *)sk, (const void *)ptr, idx); \
    } \
    static otls_unused otls_inline t2 *sk_##t1##_set(STACK_OF(t1) *sk, int idx, t2 *ptr) \
    { \
        return (t2 *)OPENtls_sk_set((OPENtls_STACK *)sk, idx, (const void *)ptr); \
    } \
    static otls_unused otls_inline int sk_##t1##_find(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return OPENtls_sk_find((OPENtls_STACK *)sk, (const void *)ptr); \
    } \
    static otls_unused otls_inline int sk_##t1##_find_ex(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return OPENtls_sk_find_ex((OPENtls_STACK *)sk, (const void *)ptr); \
    } \
    static otls_unused otls_inline void sk_##t1##_sort(STACK_OF(t1) *sk) \
    { \
        OPENtls_sk_sort((OPENtls_STACK *)sk); \
    } \
    static otls_unused otls_inline int sk_##t1##_is_sorted(const STACK_OF(t1) *sk) \
    { \
        return OPENtls_sk_is_sorted((const OPENtls_STACK *)sk); \
    } \
    static otls_unused otls_inline STACK_OF(t1) * sk_##t1##_dup(const STACK_OF(t1) *sk) \
    { \
        return (STACK_OF(t1) *)OPENtls_sk_dup((const OPENtls_STACK *)sk); \
    } \
    static otls_unused otls_inline STACK_OF(t1) *sk_##t1##_deep_copy(const STACK_OF(t1) *sk, \
                                                    sk_##t1##_copyfunc copyfunc, \
                                                    sk_##t1##_freefunc freefunc) \
    { \
        return (STACK_OF(t1) *)OPENtls_sk_deep_copy((const OPENtls_STACK *)sk, \
                                            (OPENtls_sk_copyfunc)copyfunc, \
                                            (OPENtls_sk_freefunc)freefunc); \
    } \
    static otls_unused otls_inline sk_##t1##_compfunc sk_##t1##_set_cmp_func(STACK_OF(t1) *sk, sk_##t1##_compfunc compare) \
    { \
        return (sk_##t1##_compfunc)OPENtls_sk_set_cmp_func((OPENtls_STACK *)sk, (OPENtls_sk_compfunc)compare); \
    }

# define DEFINE_SPECIAL_STACK_OF(t1, t2) SKM_DEFINE_STACK_OF(t1, t2, t2)
# define DEFINE_STACK_OF(t) SKM_DEFINE_STACK_OF(t, t, t)
# define DEFINE_SPECIAL_STACK_OF_CONST(t1, t2) \
            SKM_DEFINE_STACK_OF(t1, const t2, t2)
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
typedef char *OPENtls_STRING;
typedef const char *OPENtls_CSTRING;

/*-
 * Confusingly, LHASH_OF(STRING) deals with char ** throughout, but
 * STACK_OF(STRING) is really more like STACK_OF(char), only, as mentioned
 * above, instead of a single char each entry is a NUL-terminated array of
 * chars. So, we have to implement STRING specially for STACK_OF. This is
 * dealt with in the autogenerated macros below.
 */
DEFINE_SPECIAL_STACK_OF(OPENtls_STRING, char)
DEFINE_SPECIAL_STACK_OF_CONST(OPENtls_CSTRING, char)

/*
 * Similarly, we sometimes use a block of characters, NOT nul-terminated.
 * These should also be distinguished from "normal" stacks.
 */
typedef void *OPENtls_BLOCK;
DEFINE_SPECIAL_STACK_OF(OPENtls_BLOCK, void)

/*
 * If called without higher optimization (min. -xO3) the Oracle Developer
 * Studio compiler generates code for the defined (static inline) functions
 * above.
 * This would later lead to the linker complaining about missing symbols when
 * this header file is included but the resulting object is not linked against
 * the Crypto library (opentls#6912).
 */
# ifdef __SUNPRO_C
#  pragma weak OPENtls_sk_num
#  pragma weak OPENtls_sk_value
#  pragma weak OPENtls_sk_new
#  pragma weak OPENtls_sk_new_null
#  pragma weak OPENtls_sk_new_reserve
#  pragma weak OPENtls_sk_reserve
#  pragma weak OPENtls_sk_free
#  pragma weak OPENtls_sk_zero
#  pragma weak OPENtls_sk_delete
#  pragma weak OPENtls_sk_delete_ptr
#  pragma weak OPENtls_sk_push
#  pragma weak OPENtls_sk_unshift
#  pragma weak OPENtls_sk_pop
#  pragma weak OPENtls_sk_shift
#  pragma weak OPENtls_sk_pop_free
#  pragma weak OPENtls_sk_insert
#  pragma weak OPENtls_sk_set
#  pragma weak OPENtls_sk_find
#  pragma weak OPENtls_sk_find_ex
#  pragma weak OPENtls_sk_sort
#  pragma weak OPENtls_sk_is_sorted
#  pragma weak OPENtls_sk_dup
#  pragma weak OPENtls_sk_deep_copy
#  pragma weak OPENtls_sk_set_cmp_func
# endif /* __SUNPRO_C */

# ifdef  __cplusplus
}
# endif
#endif
