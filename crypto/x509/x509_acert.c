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
#include <crypto/x509_acert.h>

/*
 * OpenSSL ASN.1 template translation of RFC 5755 4.1.
 */

ASN1_SEQUENCE(OSSL_OBJECT_DIGEST_INFO) = {
    ASN1_SIMPLE(OSSL_OBJECT_DIGEST_INFO, digestedObjectType, ASN1_ENUMERATED),
    ASN1_OPT(OSSL_OBJECT_DIGEST_INFO, otherObjectTypeID, ASN1_OBJECT),
    ASN1_SIMPLE(OSSL_OBJECT_DIGEST_INFO, digestAlgorithm, X509_ALGOR),
    ASN1_SIMPLE(OSSL_OBJECT_DIGEST_INFO, objectDigest, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(OSSL_OBJECT_DIGEST_INFO)

ASN1_SEQUENCE(OSSL_ISSUER_SERIAL) = {
    ASN1_SEQUENCE_OF(OSSL_ISSUER_SERIAL, issuer, GENERAL_NAME),
    ASN1_EMBED(OSSL_ISSUER_SERIAL, serial, ASN1_INTEGER),
    ASN1_OPT(OSSL_ISSUER_SERIAL, issuerUID, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(OSSL_ISSUER_SERIAL)

ASN1_SEQUENCE(X509_ACERT_ISSUER_V2FORM) = {
    ASN1_SEQUENCE_OF_OPT(X509_ACERT_ISSUER_V2FORM, issuerName, GENERAL_NAME),
    ASN1_IMP_OPT(X509_ACERT_ISSUER_V2FORM, baseCertificateId, OSSL_ISSUER_SERIAL, 0),
    ASN1_IMP_OPT(X509_ACERT_ISSUER_V2FORM, objectDigestInfo, OSSL_OBJECT_DIGEST_INFO, 1),
} ASN1_SEQUENCE_END(X509_ACERT_ISSUER_V2FORM)

ASN1_CHOICE(X509_ACERT_ISSUER) = {
    ASN1_SEQUENCE_OF(X509_ACERT_ISSUER, u.v1Form, GENERAL_NAME),
    ASN1_IMP(X509_ACERT_ISSUER, u.v2Form, X509_ACERT_ISSUER_V2FORM, 0),
} ASN1_CHOICE_END(X509_ACERT_ISSUER)

ASN1_SEQUENCE(X509_HOLDER) = {
    ASN1_IMP_OPT(X509_HOLDER, baseCertificateID, OSSL_ISSUER_SERIAL, 0),
    ASN1_IMP_SEQUENCE_OF_OPT(X509_HOLDER, entityName, GENERAL_NAME, 1),
    ASN1_IMP_OPT(X509_HOLDER, objectDigestInfo, OSSL_OBJECT_DIGEST_INFO, 2),
} ASN1_SEQUENCE_END(X509_HOLDER)

ASN1_SEQUENCE(X509_ACERT_INFO) = {
    ASN1_EMBED(X509_ACERT_INFO, version, ASN1_INTEGER),
    ASN1_EMBED(X509_ACERT_INFO, holder, X509_HOLDER),
    ASN1_EMBED(X509_ACERT_INFO, issuer, X509_ACERT_ISSUER),
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
IMPLEMENT_ASN1_DUP_FUNCTION(X509_ACERT)
IMPLEMENT_ASN1_FUNCTIONS(X509_ACERT_INFO)
IMPLEMENT_ASN1_FUNCTIONS(OSSL_ISSUER_SERIAL)
IMPLEMENT_ASN1_FUNCTIONS(OSSL_OBJECT_DIGEST_INFO)
IMPLEMENT_ASN1_FUNCTIONS(X509_ACERT_ISSUER_V2FORM)
IMPLEMENT_ASN1_FUNCTIONS(X509_ACERT_ISSUER)
IMPLEMENT_ASN1_FUNCTIONS(X509_HOLDER)

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

void OSSL_OBJECT_DIGEST_INFO_get0_digest(OSSL_OBJECT_DIGEST_INFO *o,
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

X509_NAME *OSSL_ISSUER_SERIAL_get0_issuer(OSSL_ISSUER_SERIAL *isss)
{
    return get_dirName(isss->issuer);
}

ASN1_INTEGER *OSSL_ISSUER_SERIAL_get0_serial(OSSL_ISSUER_SERIAL *isss)
{
    return &isss->serial;
}

ASN1_BIT_STRING *OSSL_ISSUER_SERIAL_get0_issuerUID(OSSL_ISSUER_SERIAL *isss)
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

int X509_ACERT_get_signature_nid(const X509_ACERT *x)
{
    return OBJ_obj2nid(x->sig_alg.algorithm);
}

GENERAL_NAMES *X509_ACERT_get0_holder_entityName(const X509_ACERT *x)
{
    return x->acinfo->holder.entityName;
}

OSSL_ISSUER_SERIAL *X509_ACERT_get0_holder_baseCertId(const X509_ACERT *x)
{
    return x->acinfo->holder.baseCertificateID;
}

OSSL_OBJECT_DIGEST_INFO *X509_ACERT_get0_holder_digest(const X509_ACERT *x)
{
    return x->acinfo->holder.objectDigestInfo;
}

X509_NAME *X509_ACERT_get0_issuerName(const X509_ACERT *x)
{
    return get_dirName(x->acinfo->issuer.u.v2Form->issuerName);
}

ASN1_BIT_STRING *X509_ACERT_get0_issuerUID(X509_ACERT *x)
{
    return x->acinfo->issuerUID;
}

const X509_ALGOR *X509_ACERT_get0_info_sigalg(const X509_ACERT *x)
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

int X509_acert_get_ext_count(const X509_ACERT *x)
{
    return X509v3_get_ext_count(x->acinfo->extensions);
}

int X509_acert_get_ext_by_NID(const X509_ACERT *x, int nid, int lastpos)
{
    return X509v3_get_ext_by_NID(x->acinfo->extensions, nid, lastpos);
}

int X509_acert_get_ext_by_OBJ(const X509_ACERT *x, const ASN1_OBJECT *obj, int lastpos)
{
    return X509v3_get_ext_by_OBJ(x->acinfo->extensions, obj, lastpos);
}

int X509_acert_get_ext_by_critical(const X509_ACERT *x, int crit, int lastpos)
{
    return X509v3_get_ext_by_critical(x->acinfo->extensions, crit, lastpos);
}

X509_EXTENSION *X509_acert_get_ext(const X509_ACERT *x, int loc)
{
    return X509v3_get_ext(x->acinfo->extensions, loc);
}

X509_EXTENSION *X509_acert_delete_ext(X509_ACERT *x, int loc)
{
    return X509v3_delete_ext(x->acinfo->extensions, loc);
}

int X509_acert_add_ext(X509_ACERT *x, X509_EXTENSION *ex, int loc)
{
    return (X509v3_add_ext(&(x->acinfo->extensions), ex, loc) != NULL);
}

void *X509_acert_get_ext_d2i(const X509_ACERT *x, int nid, int *crit, int *idx)
{
    return X509V3_get_d2i(x->acinfo->extensions, nid, crit, idx);
}

int X509_acert_add1_ext_i2d(X509_ACERT *x, int nid, void *value, int crit,
                            unsigned long flags)
{
    return X509V3_add1_i2d(&x->acinfo->extensions, nid, value, crit, flags);
}
