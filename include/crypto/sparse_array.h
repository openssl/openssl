/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_CRYPTO_SPARSE_ARRAY_H
# define Otls_CRYPTO_SPARSE_ARRAY_H

# include <opentls/e_os2.h>

# ifdef __cplusplus
extern "C" {
# endif

# define SPARSE_ARRAY_OF(type) struct sparse_array_st_ ## type

# define DEFINE_SPARSE_ARRAY_OF_INTERNAL(type, ctype) \
    SPARSE_ARRAY_OF(type); \
    static otls_unused otls_inline SPARSE_ARRAY_OF(type) * \
        otls_sa_##type##_new(void) \
    { \
        return (SPARSE_ARRAY_OF(type) *)OPENtls_SA_new(); \
    } \
    static otls_unused otls_inline void otls_sa_##type##_free(SPARSE_ARRAY_OF(type) *sa) \
    { \
        OPENtls_SA_free((OPENtls_SA *)sa); \
    } \
    static otls_unused otls_inline void otls_sa_##type##_free_leaves(SPARSE_ARRAY_OF(type) *sa) \
    { \
        OPENtls_SA_free_leaves((OPENtls_SA *)sa); \
    } \
    static otls_unused otls_inline size_t otls_sa_##type##_num(const SPARSE_ARRAY_OF(type) *sa) \
    { \
        return OPENtls_SA_num((OPENtls_SA *)sa); \
    } \
    static otls_unused otls_inline void otls_sa_##type##_doall(const SPARSE_ARRAY_OF(type) *sa, \
                                                   void (*leaf)(otls_uintmax_t, \
                                                                type *)) \
    { \
        OPENtls_SA_doall((OPENtls_SA *)sa, (void (*)(otls_uintmax_t, void *))leaf); \
    } \
    static otls_unused otls_inline \
    void otls_sa_##type##_doall_arg(const SPARSE_ARRAY_OF(type) *sa, \
                                    void (*leaf)(otls_uintmax_t, type *, void *), \
                                    void *arg) \
    { \
        OPENtls_SA_doall_arg((OPENtls_SA *)sa, (void (*)(otls_uintmax_t, void *, \
                                                void *))leaf, \
                             arg); \
    } \
    static otls_unused otls_inline ctype *otls_sa_##type##_get(const SPARSE_ARRAY_OF(type) *sa, \
                                                  otls_uintmax_t n) \
    { \
        return (type *)OPENtls_SA_get((OPENtls_SA *)sa, n); \
    } \
    static otls_unused otls_inline int otls_sa_##type##_set(SPARSE_ARRAY_OF(type) *sa, \
                                                otls_uintmax_t n, ctype *val) \
    { \
        return OPENtls_SA_set((OPENtls_SA *)sa, n, (void *)val); \
    } \
    SPARSE_ARRAY_OF(type)

# define DEFINE_SPARSE_ARRAY_OF(type) \
    DEFINE_SPARSE_ARRAY_OF_INTERNAL(type, type)
# define DEFINE_SPARSE_ARRAY_OF_CONST(type) \
    DEFINE_SPARSE_ARRAY_OF_INTERNAL(type, const type)

typedef struct sparse_array_st OPENtls_SA;
OPENtls_SA *OPENtls_SA_new(void);
void OPENtls_SA_free(OPENtls_SA *sa);
void OPENtls_SA_free_leaves(OPENtls_SA *sa);
size_t OPENtls_SA_num(const OPENtls_SA *sa);
void OPENtls_SA_doall(const OPENtls_SA *sa,
                      void (*leaf)(otls_uintmax_t, void *));
void OPENtls_SA_doall_arg(const OPENtls_SA *sa,
                          void (*leaf)(otls_uintmax_t, void *, void *), void *);
void *OPENtls_SA_get(const OPENtls_SA *sa, otls_uintmax_t n);
int OPENtls_SA_set(OPENtls_SA *sa, otls_uintmax_t n, void *val);

# ifdef  __cplusplus
}
# endif
#endif
