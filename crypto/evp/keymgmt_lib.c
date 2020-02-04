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

void evp_keymgmt_util_clear_pkey_cache(EVP_PKEY *pk)
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
            evp_keymgmt_freedata(keymgmt, keydata);
            EVP_KEYMGMT_free(keymgmt);
        }

        pk->cache.size = 0;
        pk->cache.bits = 0;
        pk->cache.security_bits = 0;
    }
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
