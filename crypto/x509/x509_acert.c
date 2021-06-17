/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <crypto/ctype.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "x509_acert.h"

/*
 * OpenSSL ASN.1 template translation of RFC 5755 4.1.
 */

ASN1_SEQUENCE(OBJECT_DIGEST_INFO) = {
    ASN1_SIMPLE(OBJECT_DIGEST_INFO, digestedObjectType, ASN1_ENUMERATED),
    ASN1_OPT(OBJECT_DIGEST_INFO, otherObjectTypeID, ASN1_OBJECT),
    ASN1_SIMPLE(OBJECT_DIGEST_INFO, digestAlgorithm, X509_ALGOR),
    ASN1_SIMPLE(OBJECT_DIGEST_INFO, objectDigest, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(OBJECT_DIGEST_INFO)

ASN1_SEQUENCE(ISSUER_SERIAL) = {
    ASN1_SEQUENCE_OF(ISSUER_SERIAL, issuer, GENERAL_NAME),
    ASN1_EMBED(ISSUER_SERIAL, serial, ASN1_INTEGER),
    ASN1_OPT(ISSUER_SERIAL, issuerUID, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(ISSUER_SERIAL)

ASN1_SEQUENCE(ACERT_ISSUER_V2FORM) = {
    ASN1_SEQUENCE_OF_OPT(ACERT_ISSUER_V2FORM, issuerName, GENERAL_NAME),
    ASN1_IMP_OPT(ACERT_ISSUER_V2FORM, baseCertificateId, ISSUER_SERIAL, 0),
    ASN1_IMP_OPT(ACERT_ISSUER_V2FORM, objectDigestInfo, OBJECT_DIGEST_INFO, 1),
} ASN1_SEQUENCE_END(ACERT_ISSUER_V2FORM)

ASN1_CHOICE(ACERT_ISSUER) = {
    ASN1_SEQUENCE_OF(ACERT_ISSUER, u.v1Form, GENERAL_NAME),
    ASN1_IMP(ACERT_ISSUER, u.v2Form, ACERT_ISSUER_V2FORM, 0),
} ASN1_CHOICE_END(ACERT_ISSUER)

ASN1_SEQUENCE(HOLDER) = {
    ASN1_IMP_OPT(HOLDER, baseCertificateID, ISSUER_SERIAL, 0),
    ASN1_IMP_SEQUENCE_OF_OPT(HOLDER, entityName, GENERAL_NAME, 1),
    ASN1_IMP_OPT(HOLDER, objectDigestInfo, OBJECT_DIGEST_INFO, 2),
} ASN1_SEQUENCE_END(HOLDER)

ASN1_SEQUENCE(X509_ACERT_INFO) = {
    ASN1_EMBED(X509_ACERT_INFO, version, ASN1_INTEGER),
    ASN1_EMBED(X509_ACERT_INFO, holder, HOLDER),
    ASN1_EMBED(X509_ACERT_INFO, issuer, ACERT_ISSUER),
    ASN1_EMBED(X509_ACERT_INFO, signature, X509_ALGOR),
    ASN1_EMBED(X509_ACERT_INFO, serialNumber, ASN1_INTEGER),
    ASN1_EMBED(X509_ACERT_INFO, validityPeriod, X509_VAL),
    ASN1_SEQUENCE_OF(X509_ACERT_INFO, attributes, X509_ATTRIBUTE),
    ASN1_OPT(X509_ACERT_INFO, issuerUID, ASN1_BIT_STRING),
    ASN1_SEQUENCE_OF_OPT(X509_ACERT_INFO, extensions, X509_EXTENSION),
} ASN1_SEQUENCE_END(X509_ACERT_INFO)

ASN1_SEQUENCE(X509_ACERT) = {
    ASN1_SIMPLE(X509_ACERT, acinfo, X509_ACERT_INFO),
    ASN1_EMBED(X509_ACERT, sig_alg, X509_ALGOR),
    ASN1_EMBED(X509_ACERT, signature, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(X509_ACERT)

IMPLEMENT_ASN1_FUNCTIONS(X509_ACERT)
IMPLEMENT_ASN1_FUNCTIONS(X509_ACERT_INFO)
IMPLEMENT_ASN1_FUNCTIONS(ISSUER_SERIAL)
IMPLEMENT_ASN1_FUNCTIONS(OBJECT_DIGEST_INFO)
IMPLEMENT_ASN1_FUNCTIONS(ACERT_ISSUER_V2FORM)

static X509_NAME *get_dirName(const GENERAL_NAMES *names)
{
    GENERAL_NAME *dirName;

    if (sk_GENERAL_NAME_num(names) != 1)
        return NULL;

    dirName = sk_GENERAL_NAME_value(names, 0);
    if (dirName->type != GEN_DIRNAME)
        return NULL;

    return dirName->d.directoryName;
}

void OBJECT_DIGEST_INFO_get0_digest(OBJECT_DIGEST_INFO *o,
                                    ASN1_ENUMERATED **digestedObjectType,
                                    X509_ALGOR **digestAlgorithm,
                                    ASN1_BIT_STRING **digest)
{
    if (digestedObjectType != NULL)
        *digestedObjectType = o->digestedObjectType;
    if (digestAlgorithm != NULL)
        *digestAlgorithm = o->digestAlgorithm;
    if (digest != NULL)
        *digest = o->objectDigest;
}

X509_NAME *ISSUER_SERIAL_get0_issuer(ISSUER_SERIAL *isss)
{
    return get_dirName(isss->issuer);
}

ASN1_INTEGER *ISSUER_SERIAL_get0_serial(ISSUER_SERIAL *isss)
{
    return &isss->serial;
}

ASN1_BIT_STRING *ISSUER_SERIAL_get0_issuerUID(ISSUER_SERIAL *isss)
{
    return isss->issuerUID;
}

long X509_ACERT_get_version(const X509_ACERT *x)
{
    return ASN1_INTEGER_get(&x->acinfo->version);
}

void X509_ACERT_get0_signature(const X509_ACERT *x,
                               const ASN1_BIT_STRING **psig,
                               const X509_ALGOR **palg)
{
    if (psig != NULL)
        *psig = &x->signature;
    if (palg != NULL)
        *palg = &x->sig_alg;
}

const GENERAL_NAMES *X509_ACERT_get0_holder_entityName(const X509_ACERT *x)
{
    return x->acinfo->holder.entityName;
}

ISSUER_SERIAL *X509_ACERT_get0_holder_baseCertId(const X509_ACERT *x)
{
    return x->acinfo->holder.baseCertificateID;
}

OBJECT_DIGEST_INFO *X509_ACERT_get0_holder_digest(const X509_ACERT *x)
{
    return x->acinfo->holder.objectDigestInfo;
}

const X509_NAME *X509_ACERT_get0_issuerName(const X509_ACERT *x)
{
    return get_dirName(x->acinfo->issuer.u.v2Form->issuerName);
}

ASN1_BIT_STRING *X509_ACERT_get0_issuerUID(X509_ACERT *x)
{
    return x->acinfo->issuerUID;
}

X509_ALGOR *X509_ACERT_get0_info_signature(const X509_ACERT *x)
{
    return &x->acinfo->signature;
}

ASN1_INTEGER *X509_ACERT_get0_serialNumber(X509_ACERT *x)
{
    return &x->acinfo->serialNumber;
}

const ASN1_GENERALIZEDTIME *X509_ACERT_get0_notBefore(const X509_ACERT *x)
{
    ASN1_GENERALIZEDTIME *gentime = x->acinfo->validityPeriod.notBefore;

    if (gentime->type != V_ASN1_GENERALIZEDTIME)
        return 0;
    return gentime;
}

const ASN1_GENERALIZEDTIME *X509_ACERT_get0_notAfter(const X509_ACERT *x)
{
    ASN1_GENERALIZEDTIME *gentime = x->acinfo->validityPeriod.notAfter;

    if (gentime->type != V_ASN1_GENERALIZEDTIME)
        return 0;
    return gentime;
}

/* Attribute management functions */

int X509_ACERT_get_attr_count(const X509_ACERT *x)
{
    return X509at_get_attr_count(x->acinfo->attributes);
}

int X509_ACERT_get_attr_by_NID(const X509_ACERT *x, int nid, int lastpos)
{
    return X509at_get_attr_by_NID(x->acinfo->attributes, nid, lastpos);
}

int X509_ACERT_get_attr_by_OBJ(const X509_ACERT *x, const ASN1_OBJECT *obj,
                               int lastpos)
{
    return X509at_get_attr_by_OBJ(x->acinfo->attributes, obj, lastpos);
}

X509_ATTRIBUTE *X509_ACERT_get_attr(const X509_ACERT *x, int loc)
{
    return X509at_get_attr(x->acinfo->attributes, loc);
}

X509_ATTRIBUTE *X509_ACERT_delete_attr(X509_ACERT *x, int loc)
{
    return X509at_delete_attr(x->acinfo->attributes, loc);
}

const STACK_OF(X509_EXTENSION) *X509_ACERT_get0_extensions(const X509_ACERT *x)
{
    return x->acinfo->extensions;
}

int X509_ACERT_add1_ext_i2d(X509_ACERT *x, int nid, void *value, int crit,
                            unsigned long flag)
{
    return X509V3_add1_i2d(&x->acinfo->extensions, nid, value, crit, flag);
}

int X509_ACERT_add1_attr(X509_ACERT *x, X509_ATTRIBUTE *attr)
{
    STACK_OF(X509_ATTRIBUTE) **attrs = &x->acinfo->attributes;

    return (X509at_add1_attr(attrs, attr) != NULL);
}

int X509_ACERT_add1_attr_by_OBJ(X509_ACERT *x, const ASN1_OBJECT *obj,
                                int type, const void *bytes, int len)
{
    STACK_OF(X509_ATTRIBUTE) **attrs = &x->acinfo->attributes;

    return (X509at_add1_attr_by_OBJ(attrs, obj, type, bytes, len) != NULL);
}

int X509_ACERT_add1_attr_by_NID(X509_ACERT *x, int nid, int type,
                                const void *bytes, int len)
{
    STACK_OF(X509_ATTRIBUTE) **attrs = &x->acinfo->attributes;

    return (X509at_add1_attr_by_NID(attrs, nid, type, bytes, len) != NULL);
}

int X509_ACERT_add1_attr_by_txt(X509_ACERT *x, const char *attrname, int type,
                                const unsigned char *bytes, int len)
{
    STACK_OF(X509_ATTRIBUTE) **attrs = &x->acinfo->attributes;

    return (X509at_add1_attr_by_txt(attrs, attrname, type, bytes, len) != NULL);
}

static int check_asn1_attribute(const char **value)
{
    const char *p = *value;

    if (strncmp(p, "ASN1:", 5) != 0)
        return 0;

    p += 5;
    while (ossl_isspace(*p))
        p++;

    *value = p;
    return 1;
}

int X509_ACERT_add_attr_nconf(CONF *conf, const char *section,
                              int strtype, X509_ACERT *acert)
{
    int ret = 0, i;
    STACK_OF(CONF_VALUE) *attr_sk = NCONF_get_section(conf, section);

    if (attr_sk == NULL)
        goto err;

    for (i = 0; i < sk_CONF_VALUE_num(attr_sk); i++) {
        int att_len;
        unsigned char *att_data = NULL;
        CONF_VALUE *v = sk_CONF_VALUE_value(attr_sk, i);
        const char *value = v->value;

        if (check_asn1_attribute(&value) == 0) {
            ret = X509_ACERT_add1_attr_by_txt(acert, v->name, strtype,
                                              (unsigned char *)value, -1);
            if (!ret)
                goto err;
        } else {
            ASN1_TYPE *asn1 = ASN1_generate_nconf(value, conf);
            if (asn1 == NULL)
                goto err;

            att_len = i2d_ASN1_TYPE(asn1, &att_data);

            ret = X509_ACERT_add1_attr_by_txt(acert, v->name, V_ASN1_SEQUENCE,
                                              att_data, att_len);
            ASN1_TYPE_free(asn1);
            OPENSSL_free(att_data);

            if (!ret)
                goto err;
        }
    }
    ret = 1;
err:
    return ret;
}
