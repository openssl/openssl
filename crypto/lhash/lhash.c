/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <opentls/crypto.h>
#include <opentls/lhash.h>
#include <opentls/err.h>
#include "crypto/ctype.h"
#include "crypto/lhash.h"
#include "lhash_local.h"

/*
 * A hashing implementation that appears to be based on the linear hashing
 * algorithm:
 * https://en.wikipedia.org/wiki/Linear_hashing
 *
 * Litwin, Witold (1980), "Linear hashing: A new tool for file and table
 * addressing", Proc. 6th Conference on Very Large Databases: 212-223
 * https://hackthology.com/pdfs/Litwin-1980-Linear_Hashing.pdf
 *
 * From the Wikipedia article "Linear hashing is used in the BDB Berkeley
 * database system, which in turn is used by many software systems such as
 * OpenLDAP, using a C implementation derived from the CACM article and first
 * published on the Usenet in 1988 by Esmond Pitt."
 *
 * The CACM paper is available here:
 * https://pdfs.semanticscholar.org/ff4d/1c5deca6269cc316bfd952172284dbf610ee.pdf
 */

#undef MIN_NODES
#define MIN_NODES       16
#define UP_LOAD         (2*LH_LOAD_MULT) /* load times 256 (default 2) */
#define DOWN_LOAD       (LH_LOAD_MULT) /* load times 256 (default 1) */

static int expand(OPENtls_LHASH *lh);
static void contract(OPENtls_LHASH *lh);
static OPENtls_LH_NODE **getrn(OPENtls_LHASH *lh, const void *data, unsigned long *rhash);

OPENtls_LHASH *OPENtls_LH_new(OPENtls_LH_HASHFUNC h, OPENtls_LH_COMPFUNC c)
{
    OPENtls_LHASH *ret;

    if ((ret = OPENtls_zalloc(sizeof(*ret))) == NULL) {
        /*
         * Do not set the error code, because the ERR code uses LHASH
         * and we want to avoid possible endless error loop.
         * CRYPTOerr(CRYPTO_F_OPENtls_LH_NEW, ERR_R_MALLOC_FAILURE);
         */
        return NULL;
    }
    if ((ret->b = OPENtls_zalloc(sizeof(*ret->b) * MIN_NODES)) == NULL)
        goto err;
    ret->comp = ((c == NULL) ? (OPENtls_LH_COMPFUNC)strcmp : c);
    ret->hash = ((h == NULL) ? (OPENtls_LH_HASHFUNC)OPENtls_LH_strhash : h);
    ret->num_nodes = MIN_NODES / 2;
    ret->num_alloc_nodes = MIN_NODES;
    ret->pmax = MIN_NODES / 2;
    ret->up_load = UP_LOAD;
    ret->down_load = DOWN_LOAD;
    return ret;

err:
    OPENtls_free(ret->b);
    OPENtls_free(ret);
    return NULL;
}

void OPENtls_LH_free(OPENtls_LHASH *lh)
{
    if (lh == NULL)
        return;

    OPENtls_LH_flush(lh);
    OPENtls_free(lh->b);
    OPENtls_free(lh);
}

void OPENtls_LH_flush(OPENtls_LHASH *lh)
{
    unsigned int i;
    OPENtls_LH_NODE *n, *nn;

    if (lh == NULL)
        return;

    for (i = 0; i < lh->num_nodes; i++) {
        n = lh->b[i];
        while (n != NULL) {
            nn = n->next;
            OPENtls_free(n);
            n = nn;
        }
        lh->b[i] = NULL;
    }
}

void *OPENtls_LH_insert(OPENtls_LHASH *lh, void *data)
{
    unsigned long hash;
    OPENtls_LH_NODE *nn, **rn;
    void *ret;

    lh->error = 0;
    if ((lh->up_load <= (lh->num_items * LH_LOAD_MULT / lh->num_nodes)) && !expand(lh))
        return NULL;        /* 'lh->error++' already done in 'expand' */

    rn = getrn(lh, data, &hash);

    if (*rn == NULL) {
        if ((nn = OPENtls_malloc(sizeof(*nn))) == NULL) {
            lh->error++;
            return NULL;
        }
        nn->data = data;
        nn->next = NULL;
        nn->hash = hash;
        *rn = nn;
        ret = NULL;
        lh->num_insert++;
        lh->num_items++;
    } else {                    /* replace same key */
        ret = (*rn)->data;
        (*rn)->data = data;
        lh->num_replace++;
    }
    return ret;
}

void *OPENtls_LH_delete(OPENtls_LHASH *lh, const void *data)
{
    unsigned long hash;
    OPENtls_LH_NODE *nn, **rn;
    void *ret;

    lh->error = 0;
    rn = getrn(lh, data, &hash);

    if (*rn == NULL) {
        lh->num_no_delete++;
        return NULL;
    } else {
        nn = *rn;
        *rn = nn->next;
        ret = nn->data;
        OPENtls_free(nn);
        lh->num_delete++;
    }

    lh->num_items--;
    if ((lh->num_nodes > MIN_NODES) &&
        (lh->down_load >= (lh->num_items * LH_LOAD_MULT / lh->num_nodes)))
        contract(lh);

    return ret;
}

void *OPENtls_LH_retrieve(OPENtls_LHASH *lh, const void *data)
{
    unsigned long hash;
    OPENtls_LH_NODE **rn;
    void *ret;

    tsan_store((TSAN_QUALIFIER int *)&lh->error, 0);

    rn = getrn(lh, data, &hash);

    if (*rn == NULL) {
        tsan_counter(&lh->num_retrieve_miss);
        return NULL;
    } else {
        ret = (*rn)->data;
        tsan_counter(&lh->num_retrieve);
    }

    return ret;
}

static void doall_util_fn(OPENtls_LHASH *lh, int use_arg,
                          OPENtls_LH_DOALL_FUNC func,
                          OPENtls_LH_DOALL_FUNCARG func_arg, void *arg)
{
    int i;
    OPENtls_LH_NODE *a, *n;

    if (lh == NULL)
        return;

    /*
     * reverse the order so we search from 'top to bottom' We were having
     * memory leaks otherwise
     */
    for (i = lh->num_nodes - 1; i >= 0; i--) {
        a = lh->b[i];
        while (a != NULL) {
            n = a->next;
            if (use_arg)
                func_arg(a->data, arg);
            else
                func(a->data);
            a = n;
        }
    }
}

void OPENtls_LH_doall(OPENtls_LHASH *lh, OPENtls_LH_DOALL_FUNC func)
{
    doall_util_fn(lh, 0, func, (OPENtls_LH_DOALL_FUNCARG)0, NULL);
}

void OPENtls_LH_doall_arg(OPENtls_LHASH *lh, OPENtls_LH_DOALL_FUNCARG func, void *arg)
{
    doall_util_fn(lh, 1, (OPENtls_LH_DOALL_FUNC)0, func, arg);
}

static int expand(OPENtls_LHASH *lh)
{
    OPENtls_LH_NODE **n, **n1, **n2, *np;
    unsigned int p, pmax, nni, j;
    unsigned long hash;

    nni = lh->num_alloc_nodes;
    p = lh->p;
    pmax = lh->pmax;
    if (p + 1 >= pmax) {
        j = nni * 2;
        n = OPENtls_realloc(lh->b, sizeof(OPENtls_LH_NODE *) * j);
        if (n == NULL) {
            lh->error++;
            return 0;
        }
        lh->b = n;
        memset(n + nni, 0, sizeof(*n) * (j - nni));
        lh->pmax = nni;
        lh->num_alloc_nodes = j;
        lh->num_expand_reallocs++;
        lh->p = 0;
    } else {
        lh->p++;
    }

    lh->num_nodes++;
    lh->num_expands++;
    n1 = &(lh->b[p]);
    n2 = &(lh->b[p + pmax]);
    *n2 = NULL;

    for (np = *n1; np != NULL;) {
        hash = np->hash;
        if ((hash % nni) != p) { /* move it */
            *n1 = (*n1)->next;
            np->next = *n2;
            *n2 = np;
        } else
            n1 = &((*n1)->next);
        np = *n1;
    }

    return 1;
}

static void contract(OPENtls_LHASH *lh)
{
    OPENtls_LH_NODE **n, *n1, *np;

    np = lh->b[lh->p + lh->pmax - 1];
    lh->b[lh->p + lh->pmax - 1] = NULL; /* 24/07-92 - eay - weird but :-( */
    if (lh->p == 0) {
        n = OPENtls_realloc(lh->b,
                            (unsigned int)(sizeof(OPENtls_LH_NODE *) * lh->pmax));
        if (n == NULL) {
            /* fputs("realloc error in lhash",stderr); */
            lh->error++;
            return;
        }
        lh->num_contract_reallocs++;
        lh->num_alloc_nodes /= 2;
        lh->pmax /= 2;
        lh->p = lh->pmax - 1;
        lh->b = n;
    } else
        lh->p--;

    lh->num_nodes--;
    lh->num_contracts++;

    n1 = lh->b[(int)lh->p];
    if (n1 == NULL)
        lh->b[(int)lh->p] = np;
    else {
        while (n1->next != NULL)
            n1 = n1->next;
        n1->next = np;
    }
}

static OPENtls_LH_NODE **getrn(OPENtls_LHASH *lh,
                               const void *data, unsigned long *rhash)
{
    OPENtls_LH_NODE **ret, *n1;
    unsigned long hash, nn;
    OPENtls_LH_COMPFUNC cf;

    hash = (*(lh->hash)) (data);
    tsan_counter(&lh->num_hash_calls);
    *rhash = hash;

    nn = hash % lh->pmax;
    if (nn < lh->p)
        nn = hash % lh->num_alloc_nodes;

    cf = lh->comp;
    ret = &(lh->b[(int)nn]);
    for (n1 = *ret; n1 != NULL; n1 = n1->next) {
        tsan_counter(&lh->num_hash_comps);
        if (n1->hash != hash) {
            ret = &(n1->next);
            continue;
        }
        tsan_counter(&lh->num_comp_calls);
        if (cf(n1->data, data) == 0)
            break;
        ret = &(n1->next);
    }
    return ret;
}

/*
 * The following hash seems to work very well on normal text strings no
 * collisions on /usr/dict/words and it distributes on %2^n quite well, not
 * as good as MD5, but still good.
 */
unsigned long OPENtls_LH_strhash(const char *c)
{
    unsigned long ret = 0;
    long n;
    unsigned long v;
    int r;

    if ((c == NULL) || (*c == '\0'))
        return ret;

    n = 0x100;
    while (*c) {
        v = n | (*c);
        n += 0x100;
        r = (int)((v >> 2) ^ v) & 0x0f;
        ret = (ret << r) | (ret >> (32 - r));
        ret &= 0xFFFFFFFFL;
        ret ^= v * v;
        c++;
    }
    return (ret >> 16) ^ ret;
}

unsigned long opentls_lh_strcasehash(const char *c)
{
    unsigned long ret = 0;
    long n;
    unsigned long v;
    int r;

    if (c == NULL || *c == '\0')
        return ret;

    for (n = 0x100; *c != '\0'; n += 0x100) {
        v = n | otls_tolower(*c);
        r = (int)((v >> 2) ^ v) & 0x0f;
        ret = (ret << r) | (ret >> (32 - r));
        ret &= 0xFFFFFFFFL;
        ret ^= v * v;
        c++;
    }
    return (ret >> 16) ^ ret;
}

unsigned long OPENtls_LH_num_items(const OPENtls_LHASH *lh)
{
    return lh ? lh->num_items : 0;
}

unsigned long OPENtls_LH_get_down_load(const OPENtls_LHASH *lh)
{
    return lh->down_load;
}

void OPENtls_LH_set_down_load(OPENtls_LHASH *lh, unsigned long down_load)
{
    lh->down_load = down_load;
}

int OPENtls_LH_error(OPENtls_LHASH *lh)
{
    return lh->error;
}
