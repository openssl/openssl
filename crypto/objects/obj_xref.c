/*
 * Copyright 2006-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/objects.h>
#include "obj_xref.h"
#include "internal/nelem.h"
#include "internal/thread_once.h"
#include "internal/lockless.h"
#include <openssl/err.h>

static LLL *sig_app_list = NULL;

static int sig_cmp(const nid_triple *a, const nid_triple *b)
{
    return a->sign_id - b->sign_id;
}

static int sig_list_cmp(void *a, void *b, void *arg, int restart)
{
    nid_triple *at = (nid_triple *)a;
    nid_triple *bt = (nid_triple *)b;
    int *located_pkey_id = (int *)arg;
    int ret = at->sign_id - bt->sign_id;

    if (ret == 0)
        *located_pkey_id = at->pkey_id;    
    return ret;
}

static int sig_app_list_find_by_nid(void *a, void *b, void *arg, int restart)
{
    nid_triple *at = (nid_triple *)a;
    nid_triple *key = (nid_triple *)arg;
    int ret = at->sign_id - key->sign_id;

    if (ret == 0) {
        key->hash_id = at->hash_id;
        key->pkey_id = at->pkey_id;
    }
    return ret;
}

static int sig_app_list_find_by_algs(void *a, void *b, void *arg, int restart)
{
    int ret;
    nid_triple *at = (nid_triple *)a;
    nid_triple *key = (nid_triple *)arg;

    ret = at->hash_id - key->hash_id;
    if ((ret != 0) && (at->hash_id != NID_undef))
        return -1;
    ret = at->pkey_id - key->pkey_id;
    if (ret == 0) {
        key->sign_id = at->sign_id;
        return 0;
    }
    return -1;
}

static void sig_list_free(void *d)
{
    /*
     * Free this nid_triple
     */
    OPENSSL_free(d);
    return;
}

DECLARE_OBJ_BSEARCH_CMP_FN(nid_triple, nid_triple, sig);
IMPLEMENT_OBJ_BSEARCH_CMP_FN(nid_triple, nid_triple, sig);

DECLARE_OBJ_BSEARCH_CMP_FN(const nid_triple *, const nid_triple *, sigx);

static int sigx_cmp(const nid_triple *const *a, const nid_triple *const *b)
{
    int ret;

    ret = (*a)->hash_id - (*b)->hash_id;
    /* The "b" side of the comparison carries the algorithms already
     * registered. A NID_undef for 'hash_id' there means that the
     * signature algorithm doesn't need a digest to operate OK. In
     * such case, any hash_id/digest algorithm on the test side (a),
     * incl. NID_undef, is acceptable. signature algorithm NID
     * (pkey_id) must match in any case.
     */
    if ((ret != 0) && ((*b)->hash_id != NID_undef))
        return ret;
    return (*a)->pkey_id - (*b)->pkey_id;
}

IMPLEMENT_OBJ_BSEARCH_CMP_FN(const nid_triple *, const nid_triple *, sigx);

static CRYPTO_ONCE sig_init = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(o_sig_init)
{
    sig_app_list = LLL_new(sig_list_cmp, sig_list_free, 0);
    return sig_app_list != NULL;
}

static ossl_inline int obj_sig_init(void)
{
    return RUN_ONCE(&sig_init, o_sig_init);
}

static int ossl_obj_find_sigid_algs(int signid, int *pdig_nid, int *ppkey_nid,
                                    int lock)
{
    nid_triple tmp;
    const nid_triple *rv;
    if (signid == NID_undef)
        return 0;

    tmp.sign_id = signid;
    tmp.hash_id = -1;
    tmp.pkey_id = -1;
    rv = OBJ_bsearch_sig(&tmp, sigoid_srt, OSSL_NELEM(sigoid_srt));
    if (rv == NULL) {
        if (!obj_sig_init())
            return 0;
        if (!LLL_iterate(sig_app_list, sig_app_list_find_by_nid, &tmp))
            return 0;
        if (tmp.hash_id == -1)
            return 0;
        if (pdig_nid != NULL)
            *pdig_nid = tmp.hash_id;
        if (ppkey_nid != NULL)
            *ppkey_nid = tmp.pkey_id;
     } else {
        if (pdig_nid != NULL)
            *pdig_nid = rv->hash_id;
        if (ppkey_nid != NULL)
            *ppkey_nid = rv->pkey_id;
    }
    return 1;
}

int OBJ_find_sigid_algs(int signid, int *pdig_nid, int *ppkey_nid)
{
    return ossl_obj_find_sigid_algs(signid, pdig_nid, ppkey_nid, 1);
}

int OBJ_find_sigid_by_algs(int *psignid, int dig_nid, int pkey_nid)
{
    nid_triple tmp;
    const nid_triple **rv;
    const nid_triple *t = &tmp;
    /* permitting searches for sig algs without digest: */
    if (pkey_nid == NID_undef)
        return 0;

    tmp.hash_id = dig_nid;
    tmp.pkey_id = pkey_nid;

    rv = OBJ_bsearch_sigx(&t, sigoid_srt_xref, OSSL_NELEM(sigoid_srt_xref));
    if (rv == NULL) {
        if (!obj_sig_init())
            return 0;
        tmp.sign_id = -1;
        if (!LLL_iterate(sig_app_list, sig_app_list_find_by_algs, &tmp))
            return 0;
        if (tmp.sign_id == -1)
            return 0;
        if (psignid != NULL)
            *psignid = tmp.sign_id;
    } else {
        if (psignid != NULL)
            *psignid = (*rv)->sign_id;
    }
    return 1;
}

int OBJ_add_sigid(int signid, int dig_id, int pkey_id)
{
    nid_triple *ntr;
    int ret = 0;
    int located_pkey_id = -1;

    if (signid == NID_undef || pkey_id == NID_undef)
        return 0;

    if (!obj_sig_init())
        return 0;

    if ((ntr = OPENSSL_malloc(sizeof(*ntr))) == NULL)
        return 0;
    ntr->sign_id = signid;
    ntr->hash_id = dig_id;
    ntr->pkey_id = pkey_id;

    /*
     * Better might be to find where to insert the element and insert it there.
     * This would avoid the sorting steps below.
     */
    if (!LLL_insert(sig_app_list, ntr, &located_pkey_id)) {
        /*
         * We failed the insert, which may be because we already have this entry in the 
         * list.  If we do, its not a failure, return the pkey_id of the found entry
         */
        if (located_pkey_id != -1)
            ret = located_pkey_id;
        goto err;
    }

    ntr = NULL;
    ret = 1;
 err:
    OPENSSL_free(ntr);
    return ret;
}

void OBJ_sigid_free(void)
{
    LLL_free(sig_app_list);
    sig_app_list = NULL;
}
