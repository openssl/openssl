/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "internal/nelem.h"
#include "crypto/evp.h"
#include "crypto/asn1.h"
#include "internal/provider.h"
#include "evp_local.h"

static OSSL_PARAM *paramdefs_to_params(const OSSL_PARAM *paramdefs)
{
    size_t cnt;
    const OSSL_PARAM *p;
    OSSL_PARAM *params = NULL, *q;

    for (cnt = 1, p = paramdefs; p->key != NULL; p++, cnt++)
        continue;

    params = OPENSSL_zalloc(cnt * sizeof(*params));
    if (params == NULL)
        return NULL;

    for (p = paramdefs, q = params; ; p++, q++) {
        *q = *p;
        if (p->key == NULL)
            break;

        q->data = NULL;          /* In case the provider used it */
        q->return_size = 0;
    }

    return params;
}

static OSSL_PARAM *reduce_params(OSSL_PARAM *params)
{
    OSSL_PARAM *curr, *next;
    size_t cnt;

    for (cnt = 0, curr = next = params; next->key != NULL; next++) {
        if (next->return_size == 0)
            continue;
        if (curr != next)
            *curr = *next;
        curr++;
        cnt++;
    }
    *curr = *next;               /* Terminating record */
    cnt++;

    curr = OPENSSL_realloc(params, cnt * sizeof(*params));
    if (curr == NULL)
        return params;
    return curr;
}

typedef union align_block_un {
    OSSL_UNION_ALIGN;
} ALIGN_BLOCK;

#define ALIGN_SIZE  sizeof(ALIGN_BLOCK)

static void *allocate_params_space(OSSL_PARAM *params)
{
    unsigned char *data = NULL;
    size_t space;
    OSSL_PARAM *p;

    for (space = 0, p = params; p->key != NULL; p++)
        space += ((p->return_size + ALIGN_SIZE - 1) / ALIGN_SIZE) * ALIGN_SIZE;

    if (space == 0)
        return NULL;

    data = OPENSSL_zalloc(space);
    if (data == NULL)
        return NULL;

    for (space = 0, p = params; p->key != NULL; p++) {
        p->data = data + space;
        space += ((p->return_size + ALIGN_SIZE - 1) / ALIGN_SIZE) * ALIGN_SIZE;
    }

    return data;
}

void *evp_keymgmt_export_to_provider(EVP_PKEY *pk, EVP_KEYMGMT *keymgmt,
                                     int want_domainparams)
{
    void *provdata = NULL;
    size_t i, j;

    /*
     * If there is an underlying legacy key and it has changed, invalidate
     * the cache of provider keys.
     */
    if (pk->pkey.ptr != NULL) {
        /*
         * If there is no dirty counter, this key can't be used with
         * providers.
         */
        if (pk->ameth->dirty_cnt == NULL)
            return NULL;

        if (pk->ameth->dirty_cnt(pk) != pk->dirty_cnt_copy)
            evp_keymgmt_clear_pkey_cache(pk);
    }

    /*
     * See if we have exported to this provider already.
     * If we have, return immediately.
     */
    for (i = 0;
         i < OSSL_NELEM(pk->pkeys) && pk->pkeys[i].keymgmt != NULL;
         i++) {
        if (keymgmt == pk->pkeys[i].keymgmt
            && want_domainparams == pk->pkeys[i].domainparams)
            return pk->pkeys[i].provdata;
    }

    if (pk->pkey.ptr != NULL) {
        /* There is a legacy key, try to export that one to the provider */

        /* If the legacy key doesn't have an export function, give up */
        if (pk->ameth->export_to == NULL)
            return NULL;

        /* Otherwise, simply use it. */
        provdata = pk->ameth->export_to(pk, keymgmt, want_domainparams);

        /* Synchronize the dirty count, but only if we exported successfully */
        if (provdata != NULL)
            pk->dirty_cnt_copy = pk->ameth->dirty_cnt(pk);

    } else {
        /*
         * Here, there is no legacy key, so we look at the already cached
         * provider keys, and import from the first that supports it
         * (i.e. use its export function), and export the imported data to
         * the new provider.
         */

        void *(*importfn)(void *provctx, const OSSL_PARAM params[]) =
            want_domainparams ? keymgmt->importdomparams : keymgmt->importkey;

        /*
         * If the given keymgmt doesn't have an import function, give up
         */
        if (importfn == NULL)
            return NULL;

        for (j = 0; j < i && pk->pkeys[j].keymgmt != NULL; j++) {
            if (pk->pkeys[j].keymgmt->exportkey != NULL) {
                const OSSL_PARAM *paramdefs = NULL;
                OSSL_PARAM *params = NULL;
                void *data = NULL;
                void *provctx =
                    ossl_provider_ctx(EVP_KEYMGMT_provider(keymgmt));
                int (*exportfn)(void *provctx, OSSL_PARAM params[]) = NULL;

                if (pk->pkeys[j].domainparams != want_domainparams)
                    continue;

                exportfn = want_domainparams
                    ? pk->pkeys[j].keymgmt->exportdomparams
                    : pk->pkeys[j].keymgmt->exportkey;

                paramdefs = pk->pkeys[j].keymgmt->exportkey_types();
                /*
                 * All params have 'data' set to NULL.  In that case,
                 * the exportkey call should just fill in 'return_size'
                 * in all applicable params.
                 */
                params = paramdefs_to_params(paramdefs);
                /* Get 'return_size' filled */
                exportfn(pk->pkeys[j].provdata, params);

                /*
                 * Reduce the params by removing any entry that got return
                 * size zero, then allocate space and assign 'data' to point
                 * into the data block
                 */
                params = reduce_params(params);
                if ((data = allocate_params_space(params)) == NULL)
                    goto cont;

                /*
                 * Call the exportkey function a second time, to get
                 * the data filled.
                 * If something goes wrong, go to the next cached key.
                 */
                if (!exportfn(pk->pkeys[j].provdata, params))
                    goto cont;

                /*
                 * We should have all the data at this point, so import
                 * into the new provider and hope to get a key back.
                 */
                provdata = importfn(provctx, params);

             cont:
                OPENSSL_free(params);
                OPENSSL_free(data);

                if (provdata != NULL)
                    break;
            }
        }
    }

    /*
     * TODO(3.0) Right now, we assume we have ample space.  We will
     * have to think about a cache aging scheme, though, if |i| indexes
     * outside the array.
     */
    j = ossl_assert(i < OSSL_NELEM(pk->pkeys));

    if (provdata != NULL) {
        EVP_KEYMGMT_up_ref(keymgmt);
        pk->pkeys[i].keymgmt = keymgmt;
        pk->pkeys[i].provdata = provdata;
        pk->pkeys[i].domainparams = want_domainparams;
    }

    return provdata;
}

void evp_keymgmt_clear_pkey_cache(EVP_PKEY *pk)
{
    size_t i;

    if (pk != NULL) {
        for (i = 0;
             i < OSSL_NELEM(pk->pkeys) && pk->pkeys[i].keymgmt != NULL;
             i++) {
            EVP_KEYMGMT *keymgmt = pk->pkeys[i].keymgmt;
            void *provdata = pk->pkeys[i].provdata;

            pk->pkeys[i].keymgmt = NULL;
            pk->pkeys[i].provdata = NULL;
            if (pk->pkeys[i].domainparams)
                keymgmt->freedomparams(provdata);
            else
                keymgmt->freekey(provdata);
            EVP_KEYMGMT_free(keymgmt);
        }
    }
}

void *evp_keymgmt_fromdata(EVP_PKEY *target, EVP_KEYMGMT *keymgmt,
                           const OSSL_PARAM params[], int domainparams)
{
    void *provctx = ossl_provider_ctx(EVP_KEYMGMT_provider(keymgmt));
    void *provdata = domainparams
        ? keymgmt->importdomparams(provctx, params)
        : keymgmt->importkey(provctx, params);

    evp_keymgmt_clear_pkey_cache(target);
    if (provdata != NULL) {
        EVP_KEYMGMT_up_ref(keymgmt);
        target->pkeys[0].keymgmt = keymgmt;
        target->pkeys[0].provdata = provdata;
        target->pkeys[0].domainparams = domainparams;
    }

    return provdata;
}

/* internal functions */
/* TODO(3.0) decide if these should be public or internal */
void *evp_keymgmt_importdomparams(const EVP_KEYMGMT *keymgmt,
                                  const OSSL_PARAM params[])
{
    void *provctx = ossl_provider_ctx(EVP_KEYMGMT_provider(keymgmt));

    return keymgmt->importdomparams(provctx, params);
}

void *evp_keymgmt_gendomparams(const EVP_KEYMGMT *keymgmt,
                               const OSSL_PARAM params[])
{
    void *provctx = ossl_provider_ctx(EVP_KEYMGMT_provider(keymgmt));

    return keymgmt->gendomparams(provctx, params);
}

void evp_keymgmt_freedomparams(const EVP_KEYMGMT *keymgmt,
                               void *provdomparams)
{
    keymgmt->freedomparams(provdomparams);
}

int evp_keymgmt_exportdomparams(const EVP_KEYMGMT *keymgmt,
                                void *provdomparams, OSSL_PARAM params[])
{
    return keymgmt->exportdomparams(provdomparams, params);
}

const OSSL_PARAM *evp_keymgmt_importdomparam_types(const EVP_KEYMGMT *keymgmt)
{
    return keymgmt->importdomparam_types();
}

const OSSL_PARAM *evp_keymgmt_exportdomparam_types(const EVP_KEYMGMT *keymgmt)
{
    return keymgmt->exportdomparam_types();
}


void *evp_keymgmt_importkey(const EVP_KEYMGMT *keymgmt,
                            const OSSL_PARAM params[])
{
    void *provctx = ossl_provider_ctx(EVP_KEYMGMT_provider(keymgmt));

    return keymgmt->importkey(provctx, params);
}

void *evp_keymgmt_genkey(const EVP_KEYMGMT *keymgmt, void *domparams,
                         const OSSL_PARAM params[])
{
    void *provctx = ossl_provider_ctx(EVP_KEYMGMT_provider(keymgmt));

    return keymgmt->genkey(provctx, domparams, params);
}

void *evp_keymgmt_loadkey(const EVP_KEYMGMT *keymgmt,
                          void *id, size_t idlen)
{
    void *provctx = ossl_provider_ctx(EVP_KEYMGMT_provider(keymgmt));

    return keymgmt->loadkey(provctx, id, idlen);
}

void evp_keymgmt_freekey(const EVP_KEYMGMT *keymgmt, void *provkey)
{
    keymgmt->freekey(provkey);
}

int evp_keymgmt_exportkey(const EVP_KEYMGMT *keymgmt, void *provkey,
                          OSSL_PARAM params[])
{
    return keymgmt->exportkey(provkey, params);
}

const OSSL_PARAM *evp_keymgmt_importkey_types(const EVP_KEYMGMT *keymgmt)
{
    return keymgmt->importkey_types();
}

const OSSL_PARAM *evp_keymgmt_exportkey_types(const EVP_KEYMGMT *keymgmt)
{
    return keymgmt->exportkey_types();
}
