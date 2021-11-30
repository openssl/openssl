/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "crypto/param_trie.h"

/* We need the run once to initialise the alphabet lookup table */
#define ALLOW_RUN_ONCE_IN_FIPS
#include "internal/thread_once.h"

typedef unsigned char NODE_IDX;
#define NO_IDX  255

#ifndef OPENSSL_SMALL_FOOTPRINT
static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789-_";
# define ALPHABET_SIZE (OSSL_NELEM(alphabet) - 1)
# define TRIE_NODES  200

struct ossl_ptrie_s {
    NODE_IDX end;                   /* First unused node in the TRIE */
    struct {
        OSSL_PTRIE_PARAM_IDX paramidx;         /* Index into passed params */
        NODE_IDX children[ALPHABET_SIZE];
    } trie[TRIE_NODES];
};

static unsigned char alphabet_map[256];

static void init_alphabet_table(void)
{
    unsigned int i;

    memset(alphabet_map, 255, sizeof(alphabet_map));
    for (i = 0; i < ALPHABET_SIZE; i++)
        alphabet_map[(unsigned char)alphabet[i]] = i;
}

static CRYPTO_ONCE ptrie_init = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(do_ptrie_init)
{
    init_alphabet_table();
    return 1;
}
#endif /* OPENSSL_SMALL_FOOTPRINT */

OSSL_PTRIE *ossl_ptrie_new(const OSSL_PARAM *params)
{
#ifndef OPENSSL_SMALL_FOOTPRINT
    OSSL_PTRIE *pt = NULL;
    OSSL_PTRIE_PARAM_IDX i;
    unsigned char ch;
    NODE_IDX idx;
    const char *key;

    if (params == NULL)
        goto fail;
    pt = OPENSSL_zalloc(sizeof(*pt));
    pt->end = 1;
    for (i = 0; i < TRIE_NODES; i++)
        pt->trie[i].paramidx = NO_IDX;

    if (!RUN_ONCE(&ptrie_init, do_ptrie_init))
        goto fail;

    for (i = 0; params[i].key != NULL; i++) {
        idx = 0;
        for (key = params[i].key; *key != '\0'; key++) {
            ch = alphabet_map[(unsigned char)*key];
            if (ch == 255) {
                ERR_raise_data(ERR_LIB_CRYPTO, CRYPTO_R_BAD_CHARACTER,
                               "`%c' is not valid in parameter keys", *key);
                goto fail;
            }
            if (pt->trie[idx].children[ch] == 0) {
                if (pt->end >= TRIE_NODES) {
                    ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_MANY_RECORDS);
                    goto fail;
                }
                pt->trie[idx].children[ch] = pt->end++;
            }
            idx = pt->trie[idx].children[ch];
        }
        if (pt->trie[idx].paramidx != NO_IDX) {
            ERR_raise_data(ERR_LIB_CRYPTO, CRYPTO_R_DUPLICATE_PARAMETER,
                           "duplicate param `%s'", params[i].key);
            goto fail;
        }
        pt->trie[idx].paramidx = i;
    }
    return pt;

 fail:
    /* Failed to create the param TRIE, fall back to normal locate calls */
    OPENSSL_free(pt);
#endif /* OPENSSL_SMALL_FOOTPRINT */
    return NULL;
}

void ossl_ptrie_free(OSSL_PTRIE *pt)
{
    OPENSSL_free(pt);
}

#ifndef OPENSSL_SMALL_FOOTPRINT
static int ptrie_search(const OSSL_PTRIE *pt, const char *key)
{
    NODE_IDX idx;
    unsigned char ch;

    for (idx = 0; *key != '\0';) {
        if ((ch = alphabet_map[(unsigned char)*key++]) == 0xff)
            return NO_IDX;
        idx = pt->trie[idx].children[ch];
        if (idx == 0)
            return NO_IDX;
    }
    return pt->trie[idx].paramidx == NO_IDX ? NO_IDX : idx;
}
#endif /* OPENSSL_SMALL_FOOTPRINT */

int ossl_ptrie_scan(const OSSL_PTRIE *pt, const OSSL_PARAM *params,
                    size_t n, OSSL_PTRIE_PARAM_IDX *indicies)
{
#ifdef OPENSSL_SMALL_FOOTPRINT
    return params != NULL;
#else
    OSSL_PTRIE_PARAM_IDX i;
    NODE_IDX idx;

    if (params == NULL)
        return 0;
    if (pt == NULL || n == 0 || indicies == NULL)
        return 1;
    memset(indicies, NO_IDX, n * sizeof(unsigned char));
    for (i = 0; params[i].key != NULL && (size_t)i < n; i++)
        if ((idx = ptrie_search(pt, params[i].key)) != NO_IDX)
            indicies[pt->trie[idx].paramidx] = i;
    return 1;
#endif
}

OSSL_PARAM *ossl_ptrie_locate(int idx, OSSL_PARAM *params,
                              OSSL_PTRIE_PARAM_IDX *indicies, const char *key)
{
#ifndef OPENSSL_SMALL_FOOTPRINT
    if (params == NULL)
        return NULL;
    
    if (indicies != NULL && idx >= 0)
        return indicies[idx] != NO_IDX ? params + indicies[idx] : NULL;
#endif /* OPENSSL_SMALL_FOOTPRINT */
    return OSSL_PARAM_locate(params, key);
}

const OSSL_PARAM *ossl_ptrie_locate_const(int idx, const OSSL_PARAM *params,
                                          OSSL_PTRIE_PARAM_IDX *indicies,
                                          const char *key)
{
    return ossl_ptrie_locate(idx, (OSSL_PARAM *)params, indicies, key);
}
