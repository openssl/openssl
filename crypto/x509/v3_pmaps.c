/*
 * Copyright 2003-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include "ext_dat.h"

static void *v2i_POLICY_MAPPINGS(const X509V3_EXT_METHOD *method,
    X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval);
static STACK_OF(CONF_VALUE) *i2v_POLICY_MAPPINGS(const X509V3_EXT_METHOD
                                                     *method,
    void *pmps, STACK_OF(CONF_VALUE) *extlist);

const X509V3_EXT_METHOD ossl_v3_policy_mappings = {
    NID_policy_mappings, 0,
    ASN1_ITEM_ref(POLICY_MAPPINGS),
    0, 0, 0, 0,
    0, 0,
    i2v_POLICY_MAPPINGS,
    v2i_POLICY_MAPPINGS,
    0, 0,
    NULL
};

ASN1_SEQUENCE(POLICY_MAPPING) = {
    ASN1_SIMPLE(POLICY_MAPPING, issuerDomainPolicy, ASN1_OBJECT),
    ASN1_SIMPLE(POLICY_MAPPING, subjectDomainPolicy, ASN1_OBJECT)
} ASN1_SEQUENCE_END(POLICY_MAPPING)

ASN1_ITEM_TEMPLATE(POLICY_MAPPINGS) = ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, POLICY_MAPPINGS,
    POLICY_MAPPING)
ASN1_ITEM_TEMPLATE_END(POLICY_MAPPINGS)

IMPLEMENT_ASN1_ALLOC_FUNCTIONS(POLICY_MAPPING)

static STACK_OF(CONF_VALUE) *i2v_POLICY_MAPPINGS(const X509V3_EXT_METHOD
                                                     *method,
    void *a, STACK_OF(CONF_VALUE) *ext_list)
{
    POLICY_MAPPINGS *pmaps = a;
    POLICY_MAPPING *pmap;
    int i;
    char obj_tmp1[80];
    char obj_tmp2[80];

    for (i = 0; i < sk_POLICY_MAPPING_num(pmaps); i++) {
        pmap = sk_POLICY_MAPPING_value(pmaps, i);
        i2t_ASN1_OBJECT(obj_tmp1, 80, pmap->issuerDomainPolicy);
        i2t_ASN1_OBJECT(obj_tmp2, 80, pmap->subjectDomainPolicy);
        X509V3_add_value(obj_tmp1, obj_tmp2, &ext_list);
    }
    return ext_list;
}

static void *v2i_POLICY_MAPPINGS(const X509V3_EXT_METHOD *method,
    X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
    POLICY_MAPPING *pmap = NULL;
    ASN1_OBJECT *obj1 = NULL, *obj2 = NULL;
    CONF_VALUE *val;
    POLICY_MAPPINGS *pmaps;
    const int num = sk_CONF_VALUE_num(nval);
    int i;

    if ((pmaps = sk_POLICY_MAPPING_new_reserve(NULL, num)) == NULL) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB);
        return NULL;
    }

    for (i = 0; i < num; i++) {
        const char *issuer_oid, *subject_oid;
        char *colon, *name_copy = NULL;

        val = sk_CONF_VALUE_value(nval, i);
        if (!val->name) {
            ERR_raise_data(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER,
                "missing name");
            goto err;
        }

        /*
         * Support two config syntaxes for policyMappings:
         *
         * 1. Standard (inline or section with unique keys):
         *       issuerDomainPolicy = subjectDomainPolicy
         *    Here val->name is the issuer OID and val->value is subject OID.
         *
         * 2. Alternative (section with duplicate issuer policies):
         *       issuerDomainPolicy:subjectDomainPolicy = <anything>
         *    Here val->name contains "issuerOID:subjectOID" and val->value
         *    is ignored. This form avoids the config parser deduplicating
         *    entries that share the same issuer OID key.
         *
         * The alternative form is needed because the OpenSSL config file
         * parser uses a hash table keyed by (section, name) and silently
         * discards earlier entries when duplicate keys appear in a section.
         * Encoding both OIDs in the key avoids this limitation.
         */
        colon = strchr(val->name, ':');
        if (colon != NULL) {
            /* Alternative syntax: name is "issuerOID:subjectOID" */
            name_copy = OPENSSL_strdup(val->name);
            if (name_copy == NULL) {
                ERR_raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB);
                goto err;
            }
            /* Split at the colon */
            name_copy[colon - val->name] = '\0';
            issuer_oid = name_copy;
            subject_oid = name_copy + (colon - val->name) + 1;
            if (*issuer_oid == '\0' || *subject_oid == '\0') {
                ERR_raise_data(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER,
                    "%s", val->name);
                OPENSSL_free(name_copy);
                goto err;
            }
        } else {
            /* Standard syntax: name is issuer OID, value is subject OID */
            if (!val->value) {
                ERR_raise_data(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER,
                    "%s", val->name);
                goto err;
            }
            issuer_oid = val->name;
            subject_oid = val->value;
            name_copy = NULL;
        }

        obj1 = OBJ_txt2obj(issuer_oid, 0);
        obj2 = OBJ_txt2obj(subject_oid, 0);
        OPENSSL_free(name_copy);
        name_copy = NULL;
        if (!obj1 || !obj2) {
            ERR_raise_data(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER,
                "%s", val->name);
            goto err;
        }
        pmap = POLICY_MAPPING_new();
        if (pmap == NULL) {
            ERR_raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB);
            goto err;
        }
        pmap->issuerDomainPolicy = obj1;
        pmap->subjectDomainPolicy = obj2;
        obj1 = obj2 = NULL;
        sk_POLICY_MAPPING_push(pmaps, pmap); /* no failure as it was reserved */
    }
    return pmaps;
err:
    ASN1_OBJECT_free(obj1);
    ASN1_OBJECT_free(obj2);
    sk_POLICY_MAPPING_pop_free(pmaps, POLICY_MAPPING_free);
    return NULL;
}

