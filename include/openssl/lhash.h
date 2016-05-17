/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Header for dynamic hash table routines Author - Eric Young
 */

#ifndef HEADER_LHASH_H
# define HEADER_LHASH_H

# include <openssl/e_os2.h>
# include <openssl/bio.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct lhash_node_st {
    void *data;
    struct lhash_node_st *next;
    unsigned long hash;
} LHASH_NODE;

typedef int (*LHASH_COMP_FN_TYPE) (const void *, const void *);
typedef unsigned long (*LHASH_HASH_FN_TYPE) (const void *);
typedef void (*LHASH_DOALL_FN_TYPE) (void *);
typedef void (*LHASH_DOALL_ARG_FN_TYPE) (void *, void *);

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

typedef struct lhash_st {
    LHASH_NODE **b;
    LHASH_COMP_FN_TYPE comp;
    LHASH_HASH_FN_TYPE hash;
    unsigned int num_nodes;
    unsigned int num_alloc_nodes;
    unsigned int p;
    unsigned int pmax;
    unsigned long up_load;      /* load times 256 */
    unsigned long down_load;    /* load times 256 */
    unsigned long num_items;
    unsigned long num_expands;
    unsigned long num_expand_reallocs;
    unsigned long num_contracts;
    unsigned long num_contract_reallocs;
    unsigned long num_hash_calls;
    unsigned long num_comp_calls;
    unsigned long num_insert;
    unsigned long num_replace;
    unsigned long num_delete;
    unsigned long num_no_delete;
    unsigned long num_retrieve;
    unsigned long num_retrieve_miss;
    unsigned long num_hash_comps;
    int error;
} _LHASH;                       /* Do not use _LHASH directly, use LHASH_OF
                                 * and friends */

# define LH_LOAD_MULT    256

/*
 * Indicates a malloc() error in the last call, this is only bad in
 * lh_insert().
 */
int lh_error(_LHASH *lh);

_LHASH *lh_new(LHASH_HASH_FN_TYPE h, LHASH_COMP_FN_TYPE c);
void lh_free(_LHASH *lh);
void *lh_insert(_LHASH *lh, void *data);
void *lh_delete(_LHASH *lh, const void *data);
void *lh_retrieve(_LHASH *lh, const void *data);
void lh_doall(_LHASH *lh, LHASH_DOALL_FN_TYPE func);
void lh_doall_arg(_LHASH *lh, LHASH_DOALL_ARG_FN_TYPE func, void *arg);
unsigned long lh_strhash(const char *c);
unsigned long lh_num_items(const _LHASH *lh);
unsigned long lh_get_down_load(const _LHASH *lh);
void lh_set_down_load(_LHASH *lh, unsigned long down_load);

# ifndef OPENSSL_NO_STDIO
void lh_stats(const _LHASH *lh, FILE *fp);
void lh_node_stats(const _LHASH *lh, FILE *fp);
void lh_node_usage_stats(const _LHASH *lh, FILE *fp);
# endif
void lh_stats_bio(const _LHASH *lh, BIO *out);
void lh_node_stats_bio(const _LHASH *lh, BIO *out);
void lh_node_usage_stats_bio(const _LHASH *lh, BIO *out);

/* Type checking... */

# define LHASH_OF(type) struct lhash_st_##type

# define DEFINE_LHASH_OF(type) \
    LHASH_OF(type) { union lh_##type##_dummy { void* d1; unsigned long d2; int d3; } dummy; }; \
    static ossl_inline LHASH_OF(type) * \
        lh_##type##_new(unsigned long (*hfn)(const type *), \
                        int (*cfn)(const type *, const type *)) \
    { \
        return (LHASH_OF(type) *) \
            lh_new((LHASH_HASH_FN_TYPE) hfn, (LHASH_COMP_FN_TYPE)cfn); \
    } \
    static ossl_inline void lh_##type##_free(LHASH_OF(type) *lh) \
    { \
        lh_free((_LHASH *)lh); \
    } \
    static ossl_inline type *lh_##type##_insert(LHASH_OF(type) *lh, type *d) \
    { \
        return (type *)lh_insert((_LHASH *)lh, d); \
    } \
    static ossl_inline type *lh_##type##_delete(LHASH_OF(type) *lh, const type *d) \
    { \
        return (type *)lh_delete((_LHASH *)lh, d); \
    } \
    static ossl_inline type *lh_##type##_retrieve(LHASH_OF(type) *lh, const type *d) \
    { \
        return (type *)lh_retrieve((_LHASH *)lh, d); \
    } \
    static ossl_inline int lh_##type##_error(LHASH_OF(type) *lh) \
    { \
        return lh_error((_LHASH *)lh); \
    } \
    static ossl_inline unsigned long lh_##type##_num_items(LHASH_OF(type) *lh) \
    { \
        return lh_num_items((_LHASH *)lh); \
    } \
    static ossl_inline void lh_##type##_node_stats_bio(const LHASH_OF(type) *lh, BIO *out) \
    { \
        lh_node_stats_bio((_LHASH *)lh, out); \
    } \
    static ossl_inline void lh_##type##_node_usage_stats_bio(const LHASH_OF(type) *lh, BIO *out) \
    { \
        lh_node_usage_stats_bio((_LHASH *)lh, out); \
    } \
    static ossl_inline void lh_##type##_stats_bio(const LHASH_OF(type) *lh, BIO *out) \
    { \
        lh_stats_bio((_LHASH *)lh, out); \
    } \
    static ossl_inline unsigned long lh_##type##_get_down_load(LHASH_OF(type) *lh) \
    { \
        return lh_get_down_load((_LHASH *)lh); \
    } \
    static ossl_inline void lh_##type##_set_down_load(LHASH_OF(type) *lh, unsigned long dl) \
    { \
        lh_set_down_load((_LHASH *)lh, dl); \
    } \
    static ossl_inline void lh_##type##_doall(LHASH_OF(type) *lh, \
                                         void (*doall)(type *)) \
    { \
        lh_doall((_LHASH *)lh, (LHASH_DOALL_FN_TYPE)doall); \
    } \
    LHASH_OF(type)

#define IMPLEMENT_LHASH_DOALL_ARG_CONST(type, argtype) \
    int_implement_lhash_doall(type, argtype, const type)

#define IMPLEMENT_LHASH_DOALL_ARG(type, argtype) \
    int_implement_lhash_doall(type, argtype, type)

#define int_implement_lhash_doall(type, argtype, cbargtype) \
    static ossl_inline void \
        lh_##type##_doall_##argtype(LHASH_OF(type) *lh, \
                                   void (*fn)(cbargtype *, argtype *), \
                                   argtype *arg) \
    { \
        lh_doall_arg((_LHASH *)lh, (LHASH_DOALL_ARG_FN_TYPE)fn, (void *)arg); \
    } \
    LHASH_OF(type)

# define CHECKED_LHASH_OF(type,lh) \
  ((_LHASH *)CHECKED_PTR_OF(LHASH_OF(type),lh))

/* Define wrapper functions. */
# define LHM_lh_doall_arg(type, lh, fn, arg_type, arg) \
  lh_doall_arg(CHECKED_LHASH_OF(type, lh), fn, CHECKED_PTR_OF(arg_type, arg))

DEFINE_LHASH_OF(OPENSSL_STRING);
DEFINE_LHASH_OF(OPENSSL_CSTRING);

#ifdef  __cplusplus
}
#endif

#endif
