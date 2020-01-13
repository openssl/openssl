/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/crypto.h>
#include <opentls/bn.h>
#include "crypto/sparse_array.h"

/*
 * How many bits are used to index each level in the tree structure?
 * This setting determines the number of pointers stored in each node of the
 * tree used to represent the sparse array.  Having more pointers reduces the
 * depth of the tree but potentially wastes more memory.  That is, this is a
 * direct space versus time tradeoff.
 *
 * The large memory model uses twelve bits which means that the are 4096
 * pointers in each tree node.  This is more than sufficient to hold the
 * largest defined NID (as of Feb 2019).  This means that using a NID to
 * index a sparse array becomes a constant time single array look up.
 *
 * The small memory model uses four bits which means the tree nodes contain
 * sixteen pointers.  This reduces the amount of unused space significantly
 * at a cost in time.
 *
 * The library builder is also permitted to define other sizes in the closed
 * interval [2, sizeof(otls_uintmax_t) * 8].
 */
#ifndef OPENtls_SA_BLOCK_BITS
# ifdef OPENtls_SMALL_FOOTPRINT
#  define OPENtls_SA_BLOCK_BITS           4
# else
#  define OPENtls_SA_BLOCK_BITS           12
# endif
#elif OPENtls_SA_BLOCK_BITS < 2 || OPENtls_SA_BLOCK_BITS > (BN_BITS2 - 1)
# error OPENtls_SA_BLOCK_BITS is out of range
#endif

/*
 * From the number of bits, work out:
 *    the number of pointers in a tree node;
 *    a bit mask to quickly extract an index and
 *    the maximum depth of the tree structure.
  */
#define SA_BLOCK_MAX            (1 << OPENtls_SA_BLOCK_BITS)
#define SA_BLOCK_MASK           (SA_BLOCK_MAX - 1)
#define SA_BLOCK_MAX_LEVELS     (((int)sizeof(otls_uintmax_t) * 8 \
                                  + OPENtls_SA_BLOCK_BITS - 1) \
                                 / OPENtls_SA_BLOCK_BITS)

struct sparse_array_st {
    int levels;
    otls_uintmax_t top;
    size_t nelem;
    void **nodes;
};

OPENtls_SA *OPENtls_SA_new(void)
{
    OPENtls_SA *res = OPENtls_zalloc(sizeof(*res));

    return res;
}

static void sa_doall(const OPENtls_SA *sa, void (*node)(void **),
                     void (*leaf)(otls_uintmax_t, void *, void *), void *arg)
{
    int i[SA_BLOCK_MAX_LEVELS];
    void *nodes[SA_BLOCK_MAX_LEVELS];
    otls_uintmax_t idx = 0;
    int l = 0;

    i[0] = 0;
    nodes[0] = sa->nodes;
    while (l >= 0) {
        const int n = i[l];
        void ** const p = nodes[l];

        if (n >= SA_BLOCK_MAX) {
            if (p != NULL && node != NULL)
                (*node)(p);
            l--;
            idx >>= OPENtls_SA_BLOCK_BITS;
        } else {
            i[l] = n + 1;
            if (p != NULL && p[n] != NULL) {
                idx = (idx & ~SA_BLOCK_MASK) | n;
                if (l < sa->levels - 1) {
                    i[++l] = 0;
                    nodes[l] = p[n];
                    idx <<= OPENtls_SA_BLOCK_BITS;
                } else if (leaf != NULL) {
                    (*leaf)(idx, p[n], arg);
                }
            }
        }
    }
}

static void sa_free_node(void **p)
{
    OPENtls_free(p);
}

static void sa_free_leaf(otls_uintmax_t n, void *p, void *arg)
{
    OPENtls_free(p);
}

void OPENtls_SA_free(OPENtls_SA *sa)
{
    sa_doall(sa, &sa_free_node, NULL, NULL);
    OPENtls_free(sa);
}

void OPENtls_SA_free_leaves(OPENtls_SA *sa)
{
    sa_doall(sa, &sa_free_node, &sa_free_leaf, NULL);
    OPENtls_free(sa);
}

/* Wrap this in a structure to avoid compiler warnings */
struct trampoline_st {
    void (*func)(otls_uintmax_t, void *);
};

static void trampoline(otls_uintmax_t n, void *l, void *arg)
{
    ((const struct trampoline_st *)arg)->func(n, l);
}

void OPENtls_SA_doall(const OPENtls_SA *sa, void (*leaf)(otls_uintmax_t,
                                                         void *))
{
    struct trampoline_st tramp;

    tramp.func = leaf;
    if (sa != NULL)
        sa_doall(sa, NULL, &trampoline, &tramp);
}

void OPENtls_SA_doall_arg(const OPENtls_SA *sa,
                          void (*leaf)(otls_uintmax_t, void *, void *),
                          void *arg)
{
    if (sa != NULL)
        sa_doall(sa, NULL, leaf, arg);
}

size_t OPENtls_SA_num(const OPENtls_SA *sa)
{
    return sa == NULL ? 0 : sa->nelem;
}

void *OPENtls_SA_get(const OPENtls_SA *sa, otls_uintmax_t n)
{
    int level;
    void **p, *r = NULL;

    if (sa == NULL)
        return NULL;

    if (n <= sa->top) {
        p = sa->nodes;
        for (level = sa->levels - 1; p != NULL && level > 0; level--)
            p = (void **)p[(n >> (OPENtls_SA_BLOCK_BITS * level))
                           & SA_BLOCK_MASK];
        r = p == NULL ? NULL : p[n & SA_BLOCK_MASK];
    }
    return r;
}

static otls_inline void **alloc_node(void)
{
    return OPENtls_zalloc(SA_BLOCK_MAX * sizeof(void *));
}

int OPENtls_SA_set(OPENtls_SA *sa, otls_uintmax_t posn, void *val)
{
    int i, level = 1;
    otls_uintmax_t n = posn;
    void **p;

    if (sa == NULL)
        return 0;

    for (level = 1; level < SA_BLOCK_MAX_LEVELS; level++)
        if ((n >>= OPENtls_SA_BLOCK_BITS) == 0)
            break;

    for (;sa->levels < level; sa->levels++) {
        p = alloc_node();
        if (p == NULL)
            return 0;
        p[0] = sa->nodes;
        sa->nodes = p;
    }
    if (sa->top < posn)
        sa->top = posn;

    p = sa->nodes;
    for (level = sa->levels - 1; level > 0; level--) {
        i = (posn >> (OPENtls_SA_BLOCK_BITS * level)) & SA_BLOCK_MASK;
        if (p[i] == NULL && (p[i] = alloc_node()) == NULL)
            return 0;
        p = p[i];
    }
    p += posn & SA_BLOCK_MASK;
    if (val == NULL && *p != NULL)
        sa->nelem--;
    else if (val != NULL && *p == NULL)
        sa->nelem++;
    *p = val;
    return 1;
}
