/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/*
 * If you wish to build this outside of OpenSSL, remove the following lines
 * and things should work as expected
 */
#include "internal/cryptlib.h"

#include <openssl/bio.h>
#include <openssl/lhash.h>
#include "lhash_lcl.h"

# ifndef OPENSSL_NO_STDIO
void OPENSSL_LH_stats(const OPENSSL_LHASH *lh, FILE *fp)
{
    BIO *bp;

    bp = BIO_new(BIO_s_file());
    if (bp == NULL)
        return;
    BIO_set_fp(bp, fp, BIO_NOCLOSE);
    OPENSSL_LH_stats_bio(lh, bp);
    BIO_free(bp);
}

void OPENSSL_LH_node_stats(const OPENSSL_LHASH *lh, FILE *fp)
{
    BIO *bp;

    bp = BIO_new(BIO_s_file());
    if (bp == NULL)
        return;
    BIO_set_fp(bp, fp, BIO_NOCLOSE);
    OPENSSL_LH_node_stats_bio(lh, bp);
    BIO_free(bp);
}

void OPENSSL_LH_node_usage_stats(const OPENSSL_LHASH *lh, FILE *fp)
{
    BIO *bp;

    bp = BIO_new(BIO_s_file());
    if (bp == NULL)
        return;
    BIO_set_fp(bp, fp, BIO_NOCLOSE);
    OPENSSL_LH_node_usage_stats_bio(lh, bp);
    BIO_free(bp);
}

# endif

void OPENSSL_LH_stats_bio(const OPENSSL_LHASH *lh, BIO *out)
{
    BIO_printf(out, "items             = %lu\n", lh->num_items);
    BIO_printf(out, "nodes             = %u\n",  lh->num_nodes);
    BIO_printf(out, "alloc_nodes       = %u\n",  lh->num_alloc_nodes);
    BIO_printf(out, "expands           = %lu\n", lh->stats.expands);
    BIO_printf(out, "expand_reallocs   = %lu\n", lh->stats.expand_reallocs);
    BIO_printf(out, "contracts         = %lu\n", lh->stats.contracts);
    BIO_printf(out, "contract_reallocs = %lu\n", lh->stats.contract_reallocs);
    BIO_printf(out, "hash_calls        = %lu\n", lh->stats.hash_calls);
    BIO_printf(out, "comp_calls        = %lu\n", lh->stats.comp_calls);
    BIO_printf(out, "insert            = %lu\n", lh->stats.insert);
    BIO_printf(out, "replace           = %lu\n", lh->stats.replace);
    BIO_printf(out, "delete            = %lu\n", lh->stats.delete);
    BIO_printf(out, "no_delete         = %lu\n", lh->stats.no_delete);
    BIO_printf(out, "retrieve          = %lu\n", lh->stats.retrieve);
    BIO_printf(out, "retrieve_miss     = %lu\n", lh->stats.retrieve_miss);
    BIO_printf(out, "hash_comps        = %lu\n", lh->stats.hash_comps);
}

void OPENSSL_LH_node_stats_bio(const OPENSSL_LHASH *lh, BIO *out)
{
    OPENSSL_LH_NODE *n;
    unsigned int i, num;

    for (i = 0; i < lh->num_nodes; i++) {
        for (n = lh->b[i], num = 0; n != NULL; n = n->next)
            num++;
        BIO_printf(out, "node %6u -> %3u\n", i, num);
    }
}

void OPENSSL_LH_node_usage_stats_bio(const OPENSSL_LHASH *lh, BIO *out)
{
    OPENSSL_LH_NODE *n;
    unsigned long num;
    unsigned int i;
    unsigned long total = 0, n_used = 0;

    for (i = 0; i < lh->num_nodes; i++) {
        for (n = lh->b[i], num = 0; n != NULL; n = n->next)
            num++;
        if (num != 0) {
            n_used++;
            total += num;
        }
    }
    BIO_printf(out, "%lu nodes used out of %u\n", n_used, lh->num_nodes);
    BIO_printf(out, "%lu items\n", total);
    if (n_used == 0)
        return;
    BIO_printf(out, "load %d.%02d  actual load %d.%02d\n",
               (int)(total / lh->num_nodes),
               (int)((total % lh->num_nodes) * 100 / lh->num_nodes),
               (int)(total / n_used), (int)((total % n_used) * 100 / n_used));
}
