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
 * @param inval set to 1 if the policies are invalid, e.g. duplicate OIDs
 * @returns 1 on success, 0 if no policies were cached, -1 if they are invalid
 */
static int policy_cache_create(X509_POLICY_CACHE *cache,
    CERTIFICATEPOLICIES *policies, int crit, int *inval)
{
    int i, num, ret = 0;
    X509_POLICY_DATA *data = NULL;
    POLICYINFO *policy;

    if ((num = sk_POLICYINFO_num(policies)) <= 0)
        goto bad_policy;
    cache->data = sk_X509_POLICY_DATA_new(policy_data_cmp);
    if (cache->data == NULL) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB);
        goto just_cleanup;
    }
    for (i = 0; i < num; i++) {
        policy = sk_POLICYINFO_value(policies, i);
        data = ossl_policy_data_new(policy, NULL, crit);
        if (data == NULL) {
            ERR_raise(ERR_LIB_X509V3, ERR_R_X509_LIB);
            goto just_cleanup;
        }
        /*
         * Duplicate policy OIDs are illegal: reject if matches found.
         */
        if (OBJ_obj2nid(data->valid_policy) == NID_any_policy) {
            if (cache->anyPolicy) {
                ret = -1;
                goto bad_policy;
            }
            cache->anyPolicy = data;
        } else if (sk_X509_POLICY_DATA_find(cache->data, data) >= 0) {
            ret = -1;
            goto bad_policy;
        } else if (!sk_X509_POLICY_DATA_push(cache->data, data)) {
            ERR_raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB);
            goto bad_policy;
        }
        data = NULL;
    }
    /* Sort so we can find more quickly */
    sk_X509_POLICY_DATA_sort(cache->data);
    ret = 1;

bad_policy:
    if (ret == -1)
        *inval = 1;
    ossl_policy_data_free(data);
just_cleanup:
    sk_POLICYINFO_pop_free(policies, POLICYINFO_free);
    if (ret <= 0) {
        sk_X509_POLICY_DATA_pop_free(cache->data, ossl_policy_data_free);
        cache->data = NULL;
    }
    return ret;
}

X509_POLICY_CACHE *ossl_policy_cache_new(const X509 *x, int *inval)
{
    X509_POLICY_CACHE *cache;
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

    /*
     * Handle requireExplicitPolicy *first*. Need to process this even if we
     * don't have any policies.
     */
    ext_pcons = X509_get_ext_d2i(x, NID_policy_constraints, &i, NULL);

    if (!ext_pcons) {
        if (i != -1)
            goto bad_cache;
    } else {
        if (!ext_pcons->requireExplicitPolicy
            && !ext_pcons->inhibitPolicyMapping)
            goto bad_cache;
        if (!policy_cache_set_int(&cache->explicit_skip,
                ext_pcons->requireExplicitPolicy))
            goto bad_cache;
        if (!policy_cache_set_int(&cache->map_skip,
                ext_pcons->inhibitPolicyMapping))
            goto bad_cache;
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
            goto bad_cache;
        POLICY_CONSTRAINTS_free(ext_pcons);
        return cache;
    }

    /* NB: ext_cpols freed by policy_cache_create */
    if (policy_cache_create(cache, ext_cpols, i, inval) <= 0) {
        POLICY_CONSTRAINTS_free(ext_pcons);
        return cache;
    }

    ext_pmaps = X509_get_ext_d2i(x, NID_policy_mappings, &i, NULL);

    if (!ext_pmaps) {
        /* If not absent some problem with extension */
        if (i != -1)
            goto bad_cache;
    } else {
        if (ossl_policy_cache_set_mapping(cache, ext_pmaps) <= 0)
            goto bad_cache;
    }

    ext_any = X509_get_ext_d2i(x, NID_inhibit_any_policy, &i, NULL);

    if (!ext_any) {
        if (i != -1)
            goto bad_cache;
    } else if (!policy_cache_set_int(&cache->any_skip, ext_any))
        goto bad_cache;
    goto just_cleanup;

bad_cache:
    *inval = 1;

just_cleanup:
    POLICY_CONSTRAINTS_free(ext_pcons);
    ASN1_INTEGER_free(ext_any);
    return cache;
}

void ossl_policy_cache_free(X509_POLICY_CACHE *cache)
{
    if (!cache)
        return;
    ossl_policy_data_free(cache->anyPolicy);
    sk_X509_POLICY_DATA_pop_free(cache->data, ossl_policy_data_free);
    OPENSSL_free(cache);
}

const X509_POLICY_CACHE *ossl_policy_cache_set(X509 *x)
{
    /*
     * The policy cache is built once, when the certificate is finalized by
     * ossl_x509v3_cache_extensions().  A NULL here means the certificate was
     * never finalized (EXFLAG_SET is clear), which is a caller error: policy
     * checking must only run on finalized certificates.
     */
    if ((x->ex_flags & EXFLAG_SET) == 0)
        return NULL;

    return x->policy_cache;
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
