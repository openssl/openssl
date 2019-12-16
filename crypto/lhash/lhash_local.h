/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/crypto.h>

#include "internal/tsan_assist.h"

/*
 * Testing shows that only some of these fields need TSAN safety.
 */
typedef struct lhash_stats_st {
    TSAN_QUALIFIER unsigned long retrieve;
    TSAN_QUALIFIER unsigned long retrieve_miss;
    TSAN_QUALIFIER unsigned long hash_comps;
    TSAN_QUALIFIER unsigned long hash_calls;
    TSAN_QUALIFIER unsigned long comp_calls;
    unsigned long expand_reallocs;
    unsigned long contracts;
    unsigned long contract_reallocs;
    unsigned long insert;
    unsigned long replace;
    unsigned long expands;
    unsigned long deletes;
    unsigned long no_delete;
} LHASH_STATS;

struct lhash_node_st {
    void *data;
    struct lhash_node_st *next;
    unsigned long hash;
};

struct lhash_st {
    OPENSSL_LH_NODE **b;
    OPENSSL_LH_COMPFUNC comp;
    OPENSSL_LH_HASHFUNC hash;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    LHASH_STATS num;
#endif
    unsigned int num_nodes;
    unsigned int num_alloc_nodes;
    unsigned int p;
    unsigned int pmax;
    unsigned long down_load;    /* load times 256 */
    unsigned long num_items;
    int error;
};
