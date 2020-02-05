/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include "internal/cryptlib.h"
#include "internal/nelem.h"
#include "crypto/evp.h"
#include "crypto/asn1.h"
#include "internal/core.h"
#include "internal/provider.h"
#include "evp_local.h"

struct import_data_st {
    EVP_KEYMGMT *keymgmt;
    void *keydata;

    int selection;
};

static int try_import(const OSSL_PARAM params[], void *arg)
{
    struct import_data_st *data = arg;

    return evp_keymgmt_import(data->keymgmt, data->keydata, data->selection,
                              params);
}

void *evp_keymgmt_util_export_to_provider(EVP_PKEY *pk, EVP_KEYMGMT *keymgmt)
{
    void *keydata = NULL;
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
            evp_keymgmt_util_clear_pkey_cache(pk);
    }

    /*
     * See if we have exported to this provider already.
     * If we have, return immediately.
     */
    for (i = 0;
         i < OSSL_NELEM(pk->pkeys) && pk->pkeys[i].keymgmt != NULL;
         i++) {
        if (keymgmt == pk->pkeys[i].keymgmt)
            return pk->pkeys[i].keydata;
    }

    if ((keydata = evp_keymgmt_newdata(keymgmt)) == NULL)
        return NULL;

    if (pk->pkey.ptr != NULL) {
        /* There is a legacy key, try to export that one to the provider */

        /*
         * If the legacy key doesn't have an export function or the export
         * function fails, give up
         */
        if (pk->ameth->export_to == NULL
            || !pk->ameth->export_to(pk, keydata, keymgmt)) {
            evp_keymgmt_freedata(keymgmt, keydata);
            return NULL;
        }

        /* Synchronize the dirty count */
        pk->dirty_cnt_copy = pk->ameth->dirty_cnt(pk);
    } else {
        /*
         * Here, there is no legacy key, so we look at the already cached
         * provider keys, and import from the first that supports it
         * (i.e. use its export function), and export the imported data to
         * the new provider.
         */

        /* Setup for the export callback */
        struct import_data_st import_data;

        import_data.keydata = keydata;
        import_data.keymgmt = keymgmt;
        import_data.selection = OSSL_KEYMGMT_SELECT_ALL;

        for (j = 0; j < i && pk->pkeys[j].keymgmt != NULL; j++) {
            EVP_KEYMGMT *exp_keymgmt = pk->pkeys[i].keymgmt;
            void *exp_keydata = pk->pkeys[i].keydata;

            /*
             * TODO(3.0) consider an evp_keymgmt_export() return value that
             * indicates that the method is unsupported.
             */
            if (exp_keymgmt->export == NULL)
                continue;

            /*
             * The export function calls the callback (try_import), which
             * does the import for us.  If successful, we're done.
             */
            if (evp_keymgmt_export(exp_keymgmt, exp_keydata,
                                   OSSL_KEYMGMT_SELECT_ALL,
                                   &try_import, &import_data))
                break;

            /* If there was an error, bail out */
            evp_keymgmt_freedata(keymgmt, keydata);
            return NULL;
        }
    }

    /*
     * TODO(3.0) Right now, we assume we have ample space.  We will
     * have to think about a cache aging scheme, though, if |i| indexes
     * outside the array.
     */
    if (!ossl_assert(i < OSSL_NELEM(pk->pkeys)))
        return NULL;

    evp_keymgmt_util_cache_pkey(pk, i, keymgmt, keydata);

    return keydata;
}

static void int_clear_pkey_cache(EVP_PKEY *pk,
                                 void (*freefn)(EVP_KEYMGMT *keymgmt,
                                                void *keydata,
                                                void *freefnarg),
                                 void *freefnarg)
{
    size_t i;

    if (pk != NULL) {
        for (i = 0;
             i < OSSL_NELEM(pk->pkeys) && pk->pkeys[i].keymgmt != NULL;
             i++) {
            EVP_KEYMGMT *keymgmt = pk->pkeys[i].keymgmt;
            void *keydata = pk->pkeys[i].keydata;

            pk->pkeys[i].keymgmt = NULL;
            pk->pkeys[i].keydata = NULL;
            freefn(keymgmt, keydata, freefnarg);
        }

        pk->cache.size = 0;
        pk->cache.bits = 0;
        pk->cache.security_bits = 0;
    }
}

static void free_keydata(EVP_KEYMGMT *keymgmt, void *keydata, void *unused)
{
    evp_keymgmt_freedata(keymgmt, keydata);
    EVP_KEYMGMT_free(keymgmt);
}

void evp_keymgmt_util_clear_pkey_cache(EVP_PKEY *pk)
{
    int_clear_pkey_cache(pk, free_keydata, NULL);
}

void evp_keymgmt_util_cache_pkey(EVP_PKEY *pk, size_t index,
                                 EVP_KEYMGMT *keymgmt, void *keydata)
{
    if (keydata != NULL) {
        EVP_KEYMGMT_up_ref(keymgmt);
        pk->pkeys[index].keydata = keydata;
        pk->pkeys[index].keymgmt = keymgmt;

        /*
         * Cache information about the key object.  Only needed for the
         * "original" provider side key.
         *
         * This services functions like EVP_PKEY_size, EVP_PKEY_bits, etc
         */
        if (index == 0) {
            int bits = 0;
            int security_bits = 0;
            int size = 0;
            OSSL_PARAM params[4];

            params[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_BITS, &bits);
            params[1] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_SECURITY_BITS,
                                                 &security_bits);
            params[2] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_MAX_SIZE,
                                                 &size);
            params[3] = OSSL_PARAM_construct_end();
            if (evp_keymgmt_get_params(keymgmt, keydata, params)) {
                pk->cache.size = size;
                pk->cache.bits = bits;
                pk->cache.security_bits = security_bits;
            }
        }
    }
}

void *evp_keymgmt_util_fromdata(EVP_PKEY *target, EVP_KEYMGMT *keymgmt,
                                int selection, const OSSL_PARAM params[])
{
    void *keydata = evp_keymgmt_newdata(keymgmt);

    if (keydata != NULL) {
        if (!evp_keymgmt_import(keymgmt, keydata, selection, params)) {
            evp_keymgmt_freedata(keymgmt, keydata);
            return NULL;
        }


        evp_keymgmt_util_clear_pkey_cache(target);
        evp_keymgmt_util_cache_pkey(target, 0, keymgmt, keydata);
    }

    return keydata;
}

int evp_keymgmt_util_has(EVP_PKEY *pk, int selection)
{
    size_t i, end = OSSL_NELEM(pk->pkeys);

    for (i = 0; i < end && pk->pkeys[i].keymgmt != NULL; i++) {
        const EVP_KEYMGMT *keymgmt = pk->pkeys[i].keymgmt;
        void *keydata = pk->pkeys[i].keydata;

        if (keymgmt->has != NULL)
            return evp_keymgmt_has(keymgmt, keydata, selection);
    }
    /*
     * TODO(3.0) investigate whether the lack of any |has| function should
     * mean that the key has the components indicated by |selection| (i.e.
     * they are assumed to be the empty set) or not.
     * TODO(3.0) Investigate if we should return a value that indicates that
     * this function is unsupported, leaving it to the caller to decide what
     * to do.
     *
     * We currently assume that if there is no |has| function, the components
     * indicated by |selection| are present, because that's how
     * EVP_PKEY_missing_parameters() behaves for legacy EVP_PKEYs.
     */
    return 1;
}

/*
 * Specialized function to find matching keymgmt in two EVP_PKEYs, given
 * the return value from a |finder| function.  This function assumes that
 * if there isn't a perfect match, the caller will have to export one of
 * the keys to the other key's importing keymgmt, so it looks for that
 * too.
 *
 * No return value.  The success is determined by the values assigned to
 * the pointer references.
 */
static void find_keymgmt(EVP_KEYMGMT **keymgmt1, EVP_KEYMGMT **keymgmt2,
                         void **keydata1, void **keydata2,
                         EVP_PKEY *pk1, EVP_PKEY *pk2,
                         int (*finder)(EVP_KEYMGMT *keymgmt))
{
    EVP_KEYMGMT *tmp_keymgmt1 = NULL, *tmp_keymgmt2 = NULL;
    void *tmp_keydata1 = NULL, *tmp_keydata2 = NULL;
    size_t i1, i2, end = OSSL_NELEM(pk1->pkeys);

    /*
     * Find cache elements that share the same keymgmt, which must also have
     * function determined by |finder|.  This search is obviously O(n^2), but
     * since the cache is fairly small, we assume that it's still cheaper
     * than a export + import.
     */
    for (i1 = 0; i1 < end && pk1->pkeys[i1].keymgmt != NULL; i1++) {
        if (finder(pk1->pkeys[i1].keymgmt)) {
            tmp_keymgmt1 = pk1->pkeys[i1].keymgmt;
            tmp_keydata1 = pk1->pkeys[i1].keydata;
        }

        for (i2 = 0; i2 < end && pk2->pkeys[i2].keymgmt != NULL; i2++) {
            if (finder(pk2->pkeys[i2].keymgmt)) {
                tmp_keymgmt2 = pk2->pkeys[i2].keymgmt;
                tmp_keydata2 = pk2->pkeys[i2].keydata;
            }

            if (tmp_keymgmt1 != NULL && tmp_keymgmt1 == tmp_keymgmt2)
                /* We found the perfect match.  Get out! */
                goto bigbreak;

            /*
             * This isn't the perfect match, so the keymgmt we found for pk2
             * must also be able to import.
             */
            if (pk2->pkeys[i2].keymgmt->import == NULL) {
                tmp_keymgmt2 = NULL;
                tmp_keydata2 = NULL;
            }
        }

        /*
         * We haven't found the perfect match yet, so the keymgmt we found
         * for pk1 must also be able to import.
         */
        if (pk1->pkeys[i1].keymgmt->import == NULL) {
            tmp_keymgmt1 = NULL;
            tmp_keydata1 = NULL;
        }
    }
 bigbreak:

    *keymgmt1 = tmp_keymgmt1;
    *keymgmt2 = tmp_keymgmt2;
    *keydata1 = tmp_keydata1;
    *keydata2 = tmp_keydata2;
}

/*
 * Specialized function that, given two EVP_PKEYs and two keymgmts, tries
 * to export them to each other's keymgmt, so they end up having keydata
 * in the same provider.
 *
 * No return value.  The success is determined by the values assigned to
 * the pointer references.
 */
static void prepare_binary_op(EVP_KEYMGMT **keymgmt1, EVP_KEYMGMT **keymgmt2,
                              void **keydata1, void **keydata2,
                              EVP_PKEY *pk1, EVP_PKEY *pk2)
{
    EVP_KEYMGMT *tmp_keymgmt1 = *keymgmt1, *tmp_keymgmt2 = *keymgmt2;
    void *tmp_keydata1 = *keydata1, *tmp_keydata2 = *keydata2;
    void *tmp_keydata;

    tmp_keydata = evp_keymgmt_util_export_to_provider(pk1, tmp_keymgmt2);

    if (tmp_keydata != NULL) {
        tmp_keymgmt1 = tmp_keymgmt2;
        tmp_keydata1 = tmp_keydata;
    } else {
        tmp_keydata = evp_keymgmt_util_export_to_provider(pk2, tmp_keymgmt1);

        if (tmp_keydata != NULL) {
            tmp_keymgmt2 = tmp_keymgmt1;
            tmp_keydata2 = tmp_keydata;
        }
    }

    *keymgmt1 = tmp_keymgmt1;
    *keymgmt2 = tmp_keymgmt2;
    *keydata1 = tmp_keydata1;
    *keydata2 = tmp_keydata2;
}


static int match_type(EVP_KEYMGMT *keymgmt1, EVP_KEYMGMT *keymgmt2)
{
    /* Unconstify the provider, because evp_first_name() demands it */
    OSSL_PROVIDER *prov2 = (OSSL_PROVIDER *)EVP_KEYMGMT_provider(keymgmt2);
    const char *name2 = evp_first_name(prov2, EVP_KEYMGMT_number(keymgmt2));

    return EVP_KEYMGMT_is_a(keymgmt1, name2);
}

/*
 * evp_keymgmt_util_match() adheres to the return values that EVP_PKEY_cmp()
 * and EVP_PKEY_cmp_parameters() return, i.e.:
 *
 *  1   same key
 *  0   not same key
 * -1   not same key type
 * -2   unsupported operation
 */
static int implements_match(EVP_KEYMGMT *keymgmt)
{
    return keymgmt->match != NULL;
}

int evp_keymgmt_util_match(EVP_PKEY *pk1, EVP_PKEY *pk2, int selection)
{
    EVP_KEYMGMT *impmatch_keymgmt1 = NULL, *impmatch_keymgmt2 = NULL;
    void *keydata1 = NULL, *keydata2 = NULL;

    find_keymgmt(&impmatch_keymgmt1, &impmatch_keymgmt2, &keydata1, &keydata2,
                 pk1, pk2, &implements_match);

    /* If we found no suitable keymgmt for either key, support is missing */
    if (impmatch_keymgmt1 == NULL && impmatch_keymgmt2 == NULL)
        return -2;

    /*
     * If we don't have matching keymgmt implementations, we check that they
     * handle the same key type.
     * We trust that aliases are properly registered.
     */
    if (impmatch_keymgmt1 != impmatch_keymgmt2) {
        if (impmatch_keymgmt1 == NULL
            || impmatch_keymgmt2 == NULL
            || !match_type(impmatch_keymgmt1, impmatch_keymgmt2)) {
            ERR_raise(ERR_LIB_EVP, EVP_R_DIFFERENT_KEY_TYPES);
            return -1;           /* Not the same type */
        }
    }

    /*
     * If the two keymgmt aren't the same, try to prepare any of the two
     * EVP_PKEYs so they end up matching.
     */
    if (impmatch_keymgmt1 != impmatch_keymgmt2)
        prepare_binary_op(&impmatch_keymgmt1, &impmatch_keymgmt2,
                          &keydata1, &keydata2, pk1, pk2);

    /* If we still don't have matching keymgmt implementations, we give up */
    if (impmatch_keymgmt1 != impmatch_keymgmt2)
        return -2;

    return evp_keymgmt_match(impmatch_keymgmt1, keydata1, keydata2, selection);
}

static int implements_copy_and_export(EVP_KEYMGMT *keymgmt)
{
    return keymgmt->copy != NULL
        && (keymgmt->import == NULL || keymgmt->export != NULL);
}

static void free_keydata_for_copy(EVP_KEYMGMT *keymgmt, void *keydata,
                                  void *orig_keydata)
{
    if (keydata != orig_keydata) {
        evp_keymgmt_freedata(keymgmt, keydata);
        EVP_KEYMGMT_free(keymgmt);
    }
}

int evp_keymgmt_util_copy(EVP_PKEY *to, EVP_PKEY *from, int selection)
{
    EVP_KEYMGMT *impcopy_keymgmt_to = NULL, *impcopy_keymgmt_from = NULL;
    void *keydata_to = NULL, *keydata_from = NULL;

    /*
     * Find suitable keymgmt.  We insist that the one we find must not
     * only implement |copy|, but must also implement |export| if it
     * implements |import|.  This should ensure that anything we happen to
     * import into can be exported as well, since we're going to replace
     * the |to| pkey cache entirely.
     */
    find_keymgmt(&impcopy_keymgmt_to, &impcopy_keymgmt_from,
                 &keydata_to, &keydata_from,
                 to, from, &implements_copy_and_export);

    /*
     * If we didn't find any fitting keymgmt for pk2 (even for importing), or
     * the types don't match, we give up.
     */
    if (impcopy_keymgmt_to == NULL
        || !match_type(impcopy_keymgmt_to, impcopy_keymgmt_from)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DIFFERENT_KEY_TYPES);
        return 0;
    }

    /*
     * If the two keymgmt aren't the same, try to prepare any of the two
     * EVP_PKEYs so they end up matching.
     */
    if (impcopy_keymgmt_to != impcopy_keymgmt_from)
        prepare_binary_op(&impcopy_keymgmt_to, &impcopy_keymgmt_from,
                          &keydata_to, &keydata_from, to, from);

    /* If we still don't have matching keymgmt implementations, we give up */
    if (impcopy_keymgmt_to != impcopy_keymgmt_from)
        return 0;

    if (!evp_keymgmt_copy(impcopy_keymgmt_to, keydata_to, keydata_from,
                          selection))
        return 0;

    int_clear_pkey_cache(to, free_keydata_for_copy, keydata_to);
    evp_keymgmt_util_cache_pkey(to, 0, impcopy_keymgmt_to, keydata_to);
    return 1;
}
