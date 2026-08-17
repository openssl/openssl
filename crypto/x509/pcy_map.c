/*
 * Copyright 2004-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "crypto/x509.h"

#include "pcy_local.h"

/*
 * Set policy mapping entries in cache. Note: this modifies the passed
 * POLICY_MAPPINGS structure
 */

int ossl_policy_cache_set_mapping(X509_POLICY_CACHE *cache,
    POLICY_MAPPINGS *maps)
{
    POLICY_MAPPING *map;
    X509_POLICY_DATA *data;
    int i;
    int ret = 0;

    if (sk_POLICY_MAPPING_num(maps) == 0) {
        cache->invalid = 1;
        goto done;
    }
    for (i = 0; i < sk_POLICY_MAPPING_num(maps); i++) {
        map = sk_POLICY_MAPPING_value(maps, i);
        /* Reject if map to or from anyPolicy */
        if ((OBJ_obj2nid(map->subjectDomainPolicy) == NID_any_policy)
            || (OBJ_obj2nid(map->issuerDomainPolicy) == NID_any_policy)) {
            cache->invalid = 1;
            goto done;
        }

        /* Attempt to find matching policy data */
        data = ossl_policy_cache_find_data(cache, map->issuerDomainPolicy);
        /* If we don't have anyPolicy can't map */
        if (data == NULL && !cache->anyPolicy)
            continue;

        /* Create a NODE from anyPolicy */
        if (data == NULL) {
            data = ossl_policy_data_new(NULL, map->issuerDomainPolicy,
                cache->anyPolicy->flags
                    & POLICY_DATA_FLAG_CRITICAL);
            if (data == NULL)
                goto err;
            data->qualifier_set = cache->anyPolicy->qualifier_set;
            data->flags |= POLICY_DATA_FLAG_MAPPED_ANY;
            data->flags |= POLICY_DATA_FLAG_SHARED_QUALIFIERS;
            if (!sk_X509_POLICY_DATA_push(cache->data, data)) {
                ossl_policy_data_free(data);
                goto err;
            }
        } else
            data->flags |= POLICY_DATA_FLAG_MAPPED;
        if (!sk_ASN1_OBJECT_push(data->expected_policy_set,
                map->subjectDomainPolicy))
            goto err;
        map->subjectDomainPolicy = NULL;
    }

done:
    ret = 1;

err:
    sk_POLICY_MAPPING_pop_free(maps, POLICY_MAPPING_free);
    return ret;
}
