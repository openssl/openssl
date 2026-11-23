/*
 * Copyright 2004-2026 The OpenSSL Project Authors. All Rights Reserved.
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

/* Sort the set for binary search and drop duplicates in linear time */
static void policy_set_sort_unique(STACK_OF(ASN1_OBJECT) *set)
{
    ASN1_OBJECT *oid;
    int i, num, unique = 1;

    sk_ASN1_OBJECT_sort(set);
    num = sk_ASN1_OBJECT_num(set);
    for (i = 1; i < num; i++) {
        oid = sk_ASN1_OBJECT_value(set, i);
        if (OBJ_cmp(sk_ASN1_OBJECT_value(set, unique - 1), oid) == 0)
            ASN1_OBJECT_free(oid);
        else if (unique++ != i)
            (void)sk_ASN1_OBJECT_set(set, unique - 1, oid);
    }
    while (sk_ASN1_OBJECT_num(set) > unique)
        (void)sk_ASN1_OBJECT_pop(set);
    /* Setting entries cleared the sorted flag that the lookup relies on */
    sk_ASN1_OBJECT_sort(set);
}

/*
 * Set policy mapping entries in cache. Note: this modifies the passed
 * POLICY_MAPPINGS structure
 */

int ossl_policy_cache_set_mapping(X509 *x, POLICY_MAPPINGS *maps)
{
    POLICY_MAPPING *map;
    X509_POLICY_DATA *data;
    X509_POLICY_CACHE *cache = x->policy_cache;
    int i;
    int ret = 0;
    if (sk_POLICY_MAPPING_num(maps) == 0) {
        ret = -1;
        goto bad_mapping;
    }
    for (i = 0; i < sk_POLICY_MAPPING_num(maps); i++) {
        map = sk_POLICY_MAPPING_value(maps, i);
        /* Reject if map to or from anyPolicy */
        if ((OBJ_obj2nid(map->subjectDomainPolicy) == NID_any_policy)
            || (OBJ_obj2nid(map->issuerDomainPolicy) == NID_any_policy)) {
            ret = -1;
            goto bad_mapping;
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
                goto bad_mapping;
            data->qualifier_set = cache->anyPolicy->qualifier_set;
            /*
             * map->issuerDomainPolicy = NULL;
             */
            data->flags |= POLICY_DATA_FLAG_MAPPED_ANY;
            data->flags |= POLICY_DATA_FLAG_SHARED_QUALIFIERS;
            if (!sk_X509_POLICY_DATA_push(cache->data, data)) {
                ossl_policy_data_free(data);
                goto bad_mapping;
            }
        } else
            data->flags |= POLICY_DATA_FLAG_MAPPED;
        if (!sk_ASN1_OBJECT_push(data->expected_policy_set,
                map->subjectDomainPolicy))
            goto bad_mapping;
        map->subjectDomainPolicy = NULL;
    }

    for (i = 0; i < sk_X509_POLICY_DATA_num(cache->data); i++) {
        data = sk_X509_POLICY_DATA_value(cache->data, i);
        policy_set_sort_unique(data->expected_policy_set);
    }

    ret = 1;
bad_mapping:
    sk_POLICY_MAPPING_pop_free(maps, POLICY_MAPPING_free);
    return ret;
}
