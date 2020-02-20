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
    size_t i = 0;

    /* Export to where? */
    if (keymgmt == NULL)
        return NULL;

    /* If we have an unassigned key, give up */
    if (pk->keymgmt == NULL)
        return NULL;

    /* If |keymgmt| matches the "origin" |keymgmt|, no more to do */
    if (pk->keymgmt == keymgmt)
        return pk->keydata;

    /* If this key is already exported to |keymgmt|, no more to do */
    i = evp_keymgmt_util_find_operation_cache_index(pk, keymgmt);
    if (i < OSSL_NELEM(pk->operation_cache)
        && pk->operation_cache[i].keymgmt != NULL)
        return pk->operation_cache[i].keydata;

    /* If the "origin" |keymgmt| doesn't support exporting, give up */
    /*
     * TODO(3.0) consider an evp_keymgmt_export() return value that indicates
     * that the method is unsupported.
     */
    if (pk->keymgmt->export == NULL)
        return NULL;

    /* Check that we have found an empty slot in the export cache */
    /*
     * TODO(3.0) Right now, we assume we have ample space.  We will have to
     * think about a cache aging scheme, though, if |i| indexes outside the
     * array.
     */
    if (!ossl_assert(i < OSSL_NELEM(pk->operation_cache)))
        return NULL;

    /*
     * Make sure that the type of the keymgmt to export to matches the type
     * of the "origin"
     */
    if (!ossl_assert(match_type(pk->keymgmt, keymgmt)))
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

    /*
     * The export function calls the callback (try_import), which does the
     * import for us.  If successful, we're done.
     */
    if (!evp_keymgmt_export(pk->keymgmt, pk->keydata, OSSL_KEYMGMT_SELECT_ALL,
                            &try_import, &import_data)) {
        /* If there was an error, bail out */
        evp_keymgmt_freedata(keymgmt, keydata);
        return NULL;
    }

    /* Add the new export to the operation cache */
    if (!evp_keymgmt_util_cache_keydata(pk, i, keymgmt, keydata)) {
        evp_keymgmt_freedata(keymgmt, keydata);
        return NULL;
    }

    return keydata;
}

void evp_keymgmt_util_clear_operation_cache(EVP_PKEY *pk)
{
    size_t i, end = OSSL_NELEM(pk->operation_cache);

    if (pk != NULL) {
        for (i = 0; i < end && pk->operation_cache[i].keymgmt != NULL; i++) {
            EVP_KEYMGMT *keymgmt = pk->operation_cache[i].keymgmt;
            void *keydata = pk->operation_cache[i].keydata;

            pk->operation_cache[i].keymgmt = NULL;
            pk->operation_cache[i].keydata = NULL;
            evp_keymgmt_freedata(keymgmt, keydata);
            EVP_KEYMGMT_free(keymgmt);
        }
    }
}

size_t evp_keymgmt_util_find_operation_cache_index(EVP_PKEY *pk,
                                                   EVP_KEYMGMT *keymgmt)
{
    size_t i, end = OSSL_NELEM(pk->operation_cache);

    for (i = 0; i < end && pk->operation_cache[i].keymgmt != NULL; i++) {
        if (keymgmt == pk->operation_cache[i].keymgmt)
            break;
    }

    return i;
}

int evp_keymgmt_util_cache_keydata(EVP_PKEY *pk, size_t index,
                                   EVP_KEYMGMT *keymgmt, void *keydata)
{
    if (keydata != NULL) {
        if (!EVP_KEYMGMT_up_ref(keymgmt))
            return 0;
        pk->operation_cache[index].keydata = keydata;
        pk->operation_cache[index].keymgmt = keymgmt;
    }
    return 1;
}

void evp_keymgmt_util_cache_keyinfo(EVP_PKEY *pk)
{
    /*
     * Cache information about the provider "origin" key.
     *
     * This services functions like EVP_PKEY_size, EVP_PKEY_bits, etc
     */
    if (pk->keymgmt != NULL) {
        int bits = 0;
        int security_bits = 0;
        int size = 0;
        OSSL_PARAM params[4];

        params[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_BITS, &bits);
        params[1] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_SECURITY_BITS,
                                             &security_bits);
        params[2] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_MAX_SIZE, &size);
        params[3] = OSSL_PARAM_construct_end();
        if (evp_keymgmt_get_params(pk->keymgmt, pk->keydata, params)) {
            pk->cache.size = size;
            pk->cache.bits = bits;
            pk->cache.security_bits = security_bits;
        }
    }
}

void *evp_keymgmt_util_fromdata(EVP_PKEY *target, EVP_KEYMGMT *keymgmt,
                                int selection, const OSSL_PARAM params[])
{
    void *keydata = evp_keymgmt_newdata(keymgmt);

    if (keydata != NULL) {
        if (!evp_keymgmt_import(keymgmt, keydata, selection, params)
            || !EVP_KEYMGMT_up_ref(keymgmt)) {
            evp_keymgmt_freedata(keymgmt, keydata);
            return NULL;
        }

        evp_keymgmt_util_clear_operation_cache(target);
        target->keymgmt = keymgmt;
        target->keydata = keydata;
        evp_keymgmt_util_cache_keyinfo(target);
    }

    return keydata;
}
