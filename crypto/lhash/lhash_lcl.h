/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/crypto.h>

struct lhash_node_st {
    void *data;
    struct lhash_node_st *next;
    unsigned long hash;
};

struct lhash_stats_st {
    unsigned long expands;
    unsigned long expand_reallocs;
    unsigned long contracts;
    unsigned long contract_reallocs;
    unsigned long hash_calls;
    unsigned long comp_calls;
    unsigned long insert;
    unsigned long replace;
    unsigned long delete;
    unsigned long no_delete;
    unsigned long retrieve;
    unsigned long retrieve_miss;
    unsigned long hash_comps;
};

struct lhash_st {
    OPENSSL_LH_NODE **b;
    OPENSSL_LH_COMPFUNC comp;
    OPENSSL_LH_HASHFUNC hash;
    unsigned int num_nodes;
    unsigned int num_alloc_nodes;
    unsigned long num_items;
    unsigned int p;
    unsigned int pmax;
    unsigned long up_load;      /* load times 256 */
    unsigned long down_load;    /* load times 256 */
    unsigned long flags;
    int error;
    struct lhash_stats_st stats;
};
