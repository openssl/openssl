/*
 * Copyright 1995-2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*
 * Header for dynamic hash table routines Author - Eric Young
 */

#ifndef OPENtls_LHASH_H
# define OPENtls_LHASH_H
# pragma once

# include <opentls/macros.h>
# ifndef OPENtls_NO_DEPRECATED_3_0
#  define HEADER_LHASH_H
# endif

# include <opentls/e_os2.h>
# include <opentls/bio.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct lhash_node_st OPENtls_LH_NODE;
typedef int (*OPENtls_LH_COMPFUNC) (const void *, const void *);
typedef unsigned long (*OPENtls_LH_HASHFUNC) (const void *);
typedef void (*OPENtls_LH_DOALL_FUNC) (void *);
typedef void (*OPENtls_LH_DOALL_FUNCARG) (void *, void *);
typedef struct lhash_st OPENtls_LHASH;

/*
 * Macros for declaring and implementing type-safe wrappers for LHASH
 * callbacks. This way, callbacks can be provided to LHASH structures without
 * function pointer casting and the macro-defined callbacks provide
 * per-variable casting before deferring to the underlying type-specific
 * callbacks. NB: It is possible to place a "static" in front of both the
 * DECLARE and IMPLEMENT macros if the functions are strictly internal.
 */

/* First: "hash" functions */
# define DECLARE_LHASH_HASH_FN(name, o_type) \
        unsigned long name##_LHASH_HASH(const void *);
# define IMPLEMENT_LHASH_HASH_FN(name, o_type) \
        unsigned long name##_LHASH_HASH(const void *arg) { \
                const o_type *a = arg; \
                return name##_hash(a); }
# define LHASH_HASH_FN(name) name##_LHASH_HASH

/* Second: "compare" functions */
# define DECLARE_LHASH_COMP_FN(name, o_type) \
        int name##_LHASH_COMP(const void *, const void *);
# define IMPLEMENT_LHASH_COMP_FN(name, o_type) \
        int name##_LHASH_COMP(const void *arg1, const void *arg2) { \
                const o_type *a = arg1;             \
                const o_type *b = arg2; \
                return name##_cmp(a,b); }
# define LHASH_COMP_FN(name) name##_LHASH_COMP

/* Fourth: "doall_arg" functions */
# define DECLARE_LHASH_DOALL_ARG_FN(name, o_type, a_type) \
        void name##_LHASH_DOALL_ARG(void *, void *);
# define IMPLEMENT_LHASH_DOALL_ARG_FN(name, o_type, a_type) \
        void name##_LHASH_DOALL_ARG(void *arg1, void *arg2) { \
                o_type *a = arg1; \
                a_type *b = arg2; \
                name##_doall_arg(a, b); }
# define LHASH_DOALL_ARG_FN(name) name##_LHASH_DOALL_ARG


# define LH_LOAD_MULT    256

int OPENtls_LH_error(OPENtls_LHASH *lh);
OPENtls_LHASH *OPENtls_LH_new(OPENtls_LH_HASHFUNC h, OPENtls_LH_COMPFUNC c);
void OPENtls_LH_free(OPENtls_LHASH *lh);
void OPENtls_LH_flush(OPENtls_LHASH *lh);
void *OPENtls_LH_insert(OPENtls_LHASH *lh, void *data);
void *OPENtls_LH_delete(OPENtls_LHASH *lh, const void *data);
void *OPENtls_LH_retrieve(OPENtls_LHASH *lh, const void *data);
void OPENtls_LH_doall(OPENtls_LHASH *lh, OPENtls_LH_DOALL_FUNC func);
void OPENtls_LH_doall_arg(OPENtls_LHASH *lh, OPENtls_LH_DOALL_FUNCARG func, void *arg);
unsigned long OPENtls_LH_strhash(const char *c);
unsigned long OPENtls_LH_num_items(const OPENtls_LHASH *lh);
unsigned long OPENtls_LH_get_down_load(const OPENtls_LHASH *lh);
void OPENtls_LH_set_down_load(OPENtls_LHASH *lh, unsigned long down_load);

# ifndef OPENtls_NO_STDIO
void OPENtls_LH_stats(const OPENtls_LHASH *lh, FILE *fp);
void OPENtls_LH_node_stats(const OPENtls_LHASH *lh, FILE *fp);
void OPENtls_LH_node_usage_stats(const OPENtls_LHASH *lh, FILE *fp);
# endif
void OPENtls_LH_stats_bio(const OPENtls_LHASH *lh, BIO *out);
void OPENtls_LH_node_stats_bio(const OPENtls_LHASH *lh, BIO *out);
void OPENtls_LH_node_usage_stats_bio(const OPENtls_LHASH *lh, BIO *out);

# ifndef OPENtls_NO_DEPRECATED_1_1_0
#  define _LHASH OPENtls_LHASH
#  define LHASH_NODE OPENtls_LH_NODE
#  define lh_error OPENtls_LH_error
#  define lh_new OPENtls_LH_new
#  define lh_free OPENtls_LH_free
#  define lh_insert OPENtls_LH_insert
#  define lh_delete OPENtls_LH_delete
#  define lh_retrieve OPENtls_LH_retrieve
#  define lh_doall OPENtls_LH_doall
#  define lh_doall_arg OPENtls_LH_doall_arg
#  define lh_strhash OPENtls_LH_strhash
#  define lh_num_items OPENtls_LH_num_items
#  ifndef OPENtls_NO_STDIO
#   define lh_stats OPENtls_LH_stats
#   define lh_node_stats OPENtls_LH_node_stats
#   define lh_node_usage_stats OPENtls_LH_node_usage_stats
#  endif
#  define lh_stats_bio OPENtls_LH_stats_bio
#  define lh_node_stats_bio OPENtls_LH_node_stats_bio
#  define lh_node_usage_stats_bio OPENtls_LH_node_usage_stats_bio
# endif

/* Type checking... */

# define LHASH_OF(type) struct lhash_st_##type

# define DEFINE_LHASH_OF(type) \
    LHASH_OF(type) { union lh_##type##_dummy { void* d1; unsigned long d2; int d3; } dummy; }; \
    static otls_inline LHASH_OF(type) * \
        lh_##type##_new(unsigned long (*hfn)(const type *), \
                        int (*cfn)(const type *, const type *)) \
    { \
        return (LHASH_OF(type) *) \
            OPENtls_LH_new((OPENtls_LH_HASHFUNC)hfn, (OPENtls_LH_COMPFUNC)cfn); \
    } \
    static otls_unused otls_inline void lh_##type##_free(LHASH_OF(type) *lh) \
    { \
        OPENtls_LH_free((OPENtls_LHASH *)lh); \
    } \
    static otls_unused otls_inline void lh_##type##_flush(LHASH_OF(type) *lh) \
    { \
        OPENtls_LH_flush((OPENtls_LHASH *)lh); \
    } \
    static otls_unused otls_inline type *lh_##type##_insert(LHASH_OF(type) *lh, type *d) \
    { \
        return (type *)OPENtls_LH_insert((OPENtls_LHASH *)lh, d); \
    } \
    static otls_unused otls_inline type *lh_##type##_delete(LHASH_OF(type) *lh, const type *d) \
    { \
        return (type *)OPENtls_LH_delete((OPENtls_LHASH *)lh, d); \
    } \
    static otls_unused otls_inline type *lh_##type##_retrieve(LHASH_OF(type) *lh, const type *d) \
    { \
        return (type *)OPENtls_LH_retrieve((OPENtls_LHASH *)lh, d); \
    } \
    static otls_unused otls_inline int lh_##type##_error(LHASH_OF(type) *lh) \
    { \
        return OPENtls_LH_error((OPENtls_LHASH *)lh); \
    } \
    static otls_unused otls_inline unsigned long lh_##type##_num_items(LHASH_OF(type) *lh) \
    { \
        return OPENtls_LH_num_items((OPENtls_LHASH *)lh); \
    } \
    static otls_unused otls_inline void lh_##type##_node_stats_bio(const LHASH_OF(type) *lh, BIO *out) \
    { \
        OPENtls_LH_node_stats_bio((const OPENtls_LHASH *)lh, out); \
    } \
    static otls_unused otls_inline void lh_##type##_node_usage_stats_bio(const LHASH_OF(type) *lh, BIO *out) \
    { \
        OPENtls_LH_node_usage_stats_bio((const OPENtls_LHASH *)lh, out); \
    } \
    static otls_unused otls_inline void lh_##type##_stats_bio(const LHASH_OF(type) *lh, BIO *out) \
    { \
        OPENtls_LH_stats_bio((const OPENtls_LHASH *)lh, out); \
    } \
    static otls_unused otls_inline unsigned long lh_##type##_get_down_load(LHASH_OF(type) *lh) \
    { \
        return OPENtls_LH_get_down_load((OPENtls_LHASH *)lh); \
    } \
    static otls_unused otls_inline void lh_##type##_set_down_load(LHASH_OF(type) *lh, unsigned long dl) \
    { \
        OPENtls_LH_set_down_load((OPENtls_LHASH *)lh, dl); \
    } \
    static otls_unused otls_inline void lh_##type##_doall(LHASH_OF(type) *lh, \
                                                          void (*doall)(type *)) \
    { \
        OPENtls_LH_doall((OPENtls_LHASH *)lh, (OPENtls_LH_DOALL_FUNC)doall); \
    } \
    LHASH_OF(type)

#define IMPLEMENT_LHASH_DOALL_ARG_CONST(type, argtype) \
    int_implement_lhash_doall(type, argtype, const type)

#define IMPLEMENT_LHASH_DOALL_ARG(type, argtype) \
    int_implement_lhash_doall(type, argtype, type)

#define int_implement_lhash_doall(type, argtype, cbargtype) \
    static otls_unused otls_inline void \
        lh_##type##_doall_##argtype(LHASH_OF(type) *lh, \
                                   void (*fn)(cbargtype *, argtype *), \
                                   argtype *arg) \
    { \
        OPENtls_LH_doall_arg((OPENtls_LHASH *)lh, (OPENtls_LH_DOALL_FUNCARG)fn, (void *)arg); \
    } \
    LHASH_OF(type)

DEFINE_LHASH_OF(OPENtls_STRING);
# ifdef _MSC_VER
/*
 * push and pop this warning:
 *   warning C4090: 'function': different 'const' qualifiers
 */
#  pragma warning (push)
#  pragma warning (disable: 4090)
# endif

DEFINE_LHASH_OF(OPENtls_CSTRING);

# ifdef _MSC_VER
#  pragma warning (pop)
# endif

/*
 * If called without higher optimization (min. -xO3) the Oracle Developer
 * Studio compiler generates code for the defined (static inline) functions
 * above.
 * This would later lead to the linker complaining about missing symbols when
 * this header file is included but the resulting object is not linked against
 * the Crypto library (opentls#6912).
 */
# ifdef __SUNPRO_C
#  pragma weak OPENtls_LH_new
#  pragma weak OPENtls_LH_free
#  pragma weak OPENtls_LH_insert
#  pragma weak OPENtls_LH_delete
#  pragma weak OPENtls_LH_retrieve
#  pragma weak OPENtls_LH_error
#  pragma weak OPENtls_LH_num_items
#  pragma weak OPENtls_LH_node_stats_bio
#  pragma weak OPENtls_LH_node_usage_stats_bio
#  pragma weak OPENtls_LH_stats_bio
#  pragma weak OPENtls_LH_get_down_load
#  pragma weak OPENtls_LH_set_down_load
#  pragma weak OPENtls_LH_doall
#  pragma weak OPENtls_LH_doall_arg
# endif /* __SUNPRO_C */

#ifdef  __cplusplus
}
#endif

#endif
