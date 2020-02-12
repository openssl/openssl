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

/*
 * match_type() checks if two EVP_KEYMGMT are matching key types.  This
 * function assumes that the caller has made all the necessary NULL checks.
 */
static int match_type(const EVP_KEYMGMT *keymgmt1, const EVP_KEYMGMT *keymgmt2)
{
    const OSSL_PROVIDER *prov2 = EVP_KEYMGMT_provider(keymgmt2);
    const char *name2 = evp_first_name(prov2, EVP_KEYMGMT_number(keymgmt2));

    return EVP_KEYMGMT_is_a(keymgmt1, name2);
}

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
    struct import_data_st import_data;
    size_t i, j;

    /* Export to where? */
    if (keymgmt == NULL)
        return NULL;

    /* If we have an unassigned key, give up */
    if (pk->pkeys[0].keymgmt == NULL)
        return NULL;

    /*
     * See if we have exported to this provider already.
     * If we have, return immediately.
     */
    i = evp_keymgmt_util_find_pkey_cache_index(pk, keymgmt);

    /* If we're already exported to the given keymgmt, no more to do */
    if (keymgmt == pk->pkeys[i].keymgmt)
        return pk->pkeys[i].keydata;

    /*
     * Make sure that the type of the keymgmt to export to matches the type
     * of already cached keymgmt
     */
    if (!ossl_assert(match_type(pk->pkeys[0].keymgmt, keymgmt)))
        return NULL;

    /* Create space to import data into */
    if ((keydata = evp_keymgmt_newdata(keymgmt)) == NULL)
        return NULL;

    /*
     * We look at the already cached provider keys, and import from the
     * first that supports it (i.e. use its export function), and export
     * the imported data to the new provider.
     */

    /* Setup for the export callback */
    import_data.keydata = keydata;
    import_data.keymgmt = keymgmt;
    import_data.selection = OSSL_KEYMGMT_SELECT_ALL;

    for (j = 0; j < i && pk->pkeys[j].keymgmt != NULL; j++) {
        EVP_KEYMGMT *exp_keymgmt = pk->pkeys[j].keymgmt;
        void *exp_keydata = pk->pkeys[j].keydata;

        /*
         * TODO(3.0) consider an evp_keymgmt_export() return value that
         * indicates that the method is unsupported.
         */
        if (exp_keymgmt->export == NULL)
            continue;

        /*
         * The export function calls the callback (try_import), which does
         * the import for us.  If successful, we're done.
         */
        if (evp_keymgmt_export(exp_keymgmt, exp_keydata,
                               OSSL_KEYMGMT_SELECT_ALL,
                               &try_import, &import_data))
            break;

        /* If there was an error, bail out */
        evp_keymgmt_freedata(keymgmt, keydata);
        return NULL;
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

void evp_keymgmt_util_clear_pkey_cache(EVP_PKEY *pk)
{
    size_t i, end = OSSL_NELEM(pk->pkeys);

    if (pk != NULL) {
        for (i = 0; i < end && pk->pkeys[i].keymgmt != NULL; i++) {
            EVP_KEYMGMT *keymgmt = pk->pkeys[i].keymgmt;
            void *keydata = pk->pkeys[i].keydata;

            pk->pkeys[i].keymgmt = NULL;
            pk->pkeys[i].keydata = NULL;
            evp_keymgmt_freedata(keymgmt, keydata);
            EVP_KEYMGMT_free(keymgmt);
        }

        pk->cache.size = 0;
        pk->cache.bits = 0;
        pk->cache.security_bits = 0;
    }
}

size_t evp_keymgmt_util_find_pkey_cache_index(EVP_PKEY *pk,
                                              EVP_KEYMGMT *keymgmt)
{
    size_t i, end = OSSL_NELEM(pk->pkeys);

    for (i = 0; i < end && pk->pkeys[i].keymgmt != NULL; i++) {
        if (keymgmt == pk->pkeys[i].keymgmt)
            break;
    }

    return i;
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
