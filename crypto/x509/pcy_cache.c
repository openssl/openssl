/*
 * Copyright 2004-2023 The OpenSSL Project Authors. All Rights Reserved.
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

static int policy_data_cmp(const X509_POLICY_DATA *const *a,
    const X509_POLICY_DATA *const *b);
static int policy_cache_set_int(long *out, ASN1_INTEGER *value);

/**
 * @brief Populate a policy cache from the CertificatePolicies extension.
 *
 * Adds one policy data entry per policy, rejecting duplicate policy OIDs.  The
 * passed CERTIFICATEPOLICIES structure is consumed (freed) by this call.
 *
 * @param cache the policy cache to populate
 * @param policies the decoded CertificatePolicies extension, consumed here
 * @param crit non-zero if the extension is marked critical
 * @returns 1 on success, 0 on a fatal error such as a memory allocation
 *          failure.  Invalid policies, e.g. duplicate OIDs, are not fatal:
 *          cache->invalid is set and 1 is returned.
 */
static int policy_cache_create(X509_POLICY_CACHE *cache,
    CERTIFICATEPOLICIES *policies, int crit)
{
    int i, num;
    int ret = 0;
    X509_POLICY_DATA *data = NULL;
    POLICYINFO *policy;

    if ((num = sk_POLICYINFO_num(policies)) <= 0)
        goto done;
    cache->data = sk_X509_POLICY_DATA_new(policy_data_cmp);
    if (cache->data == NULL) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB);
        goto err;
    }
    for (i = 0; i < num; i++) {
        policy = sk_POLICYINFO_value(policies, i);
        data = ossl_policy_data_new(policy, NULL, crit);
        if (data == NULL) {
            ERR_raise(ERR_LIB_X509V3, ERR_R_X509_LIB);
            goto err;
        }
        /*
         * Duplicate policy OIDs are illegal: flag the cache invalid and stop.
         */
        if (OBJ_obj2nid(data->valid_policy) == NID_any_policy) {
            if (cache->anyPolicy != NULL) {
                cache->invalid = 1;
                goto done;
            }
            cache->anyPolicy = data;
        } else if (sk_X509_POLICY_DATA_find(cache->data, data) >= 0) {
            cache->invalid = 1;
            goto done;
        } else if (!sk_X509_POLICY_DATA_push(cache->data, data)) {
            ERR_raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB);
            goto err;
        }
        data = NULL;
    }
    /* Sort so we can find more quickly */
    sk_X509_POLICY_DATA_sort(cache->data);

done:
    ret = 1;

err:
    ossl_policy_data_free(data);
    sk_POLICYINFO_pop_free(policies, POLICYINFO_free);
    if (ret == 0) {
        sk_X509_POLICY_DATA_pop_free(cache->data, ossl_policy_data_free);
        cache->data = NULL;
    }
    return ret;
}

X509_POLICY_CACHE *ossl_policy_cache_new(const X509 *x)
{
    X509_POLICY_CACHE *cache;
    X509_POLICY_CACHE *ret = NULL;
    ASN1_INTEGER *ext_any = NULL;
    POLICY_CONSTRAINTS *ext_pcons = NULL;
    CERTIFICATEPOLICIES *ext_cpols = NULL;
    POLICY_MAPPINGS *ext_pmaps = NULL;
    int i;

    cache = OPENSSL_malloc(sizeof(*cache));
    if (cache == NULL)
        return NULL;
    cache->anyPolicy = NULL;
    cache->data = NULL;
    cache->any_skip = -1;
    cache->explicit_skip = -1;
    cache->map_skip = -1;
    cache->invalid = 0;

    /*
     * Handle requireExplicitPolicy *first*. Need to process this even if we
     * don't have any policies.
     */
    ext_pcons = X509_get_ext_d2i(x, NID_policy_constraints, &i, NULL);

    if (!ext_pcons) {
        if (i != -1) {
            cache->invalid = 1;
            goto done;
        }
    } else {
        if (!ext_pcons->requireExplicitPolicy
            && !ext_pcons->inhibitPolicyMapping) {
            cache->invalid = 1;
            goto done;
        }
        if (!policy_cache_set_int(&cache->explicit_skip,
                ext_pcons->requireExplicitPolicy)) {
            cache->invalid = 1;
            goto done;
        }
        if (!policy_cache_set_int(&cache->map_skip,
                ext_pcons->inhibitPolicyMapping)) {
            cache->invalid = 1;
            goto done;
        }
    }

    /* Process CertificatePolicies */

    ext_cpols = X509_get_ext_d2i(x, NID_certificate_policies, &i, NULL);
    /*
     * If no CertificatePolicies extension or problem decoding then there is
     * no point continuing because the valid policies will be NULL.
     */
    if (!ext_cpols) {
        /* If not absent some problem with extension */
        if (i != -1)
            cache->invalid = 1;
        goto done;
    }

    /* NB: ext_cpols freed by policy_cache_create */
    if (!policy_cache_create(cache, ext_cpols, i))
        goto err;

    ext_pmaps = X509_get_ext_d2i(x, NID_policy_mappings, &i, NULL);

    if (!ext_pmaps) {
        /* If not absent some problem with extension */
        if (i != -1) {
            cache->invalid = 1;
            goto done;
        }
    } else if (!ossl_policy_cache_set_mapping(cache, ext_pmaps)) {
        goto err;
    }

    ext_any = X509_get_ext_d2i(x, NID_inhibit_any_policy, &i, NULL);

    if (!ext_any) {
        if (i != -1)
            cache->invalid = 1;
    } else if (!policy_cache_set_int(&cache->any_skip, ext_any)) {
        cache->invalid = 1;
    }

done:
    ret = cache;
    cache = NULL;

err:
    ossl_policy_cache_free(cache);
    POLICY_CONSTRAINTS_free(ext_pcons);
    ASN1_INTEGER_free(ext_any);
    return ret;
}

void ossl_policy_cache_free(X509_POLICY_CACHE *cache)
{
    if (!cache)
        return;
    ossl_policy_data_free(cache->anyPolicy);
    sk_X509_POLICY_DATA_pop_free(cache->data, ossl_policy_data_free);
    OPENSSL_free(cache);
}

X509_POLICY_DATA *ossl_policy_cache_find_data(const X509_POLICY_CACHE *cache,
    const ASN1_OBJECT *id)
{
    int idx;
    X509_POLICY_DATA tmp;
    tmp.valid_policy = (ASN1_OBJECT *)id;
    idx = sk_X509_POLICY_DATA_find(cache->data, &tmp);
    return sk_X509_POLICY_DATA_value(cache->data, idx);
}

static int policy_data_cmp(const X509_POLICY_DATA *const *a,
    const X509_POLICY_DATA *const *b)
{
    return OBJ_cmp((*a)->valid_policy, (*b)->valid_policy);
}

static int policy_cache_set_int(long *out, ASN1_INTEGER *value)
{
    if (value == NULL)
        return 1;
    if (value->type == V_ASN1_NEG_INTEGER)
        return 0;
    *out = ASN1_INTEGER_get(value);
    return 1;
}
