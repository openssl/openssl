/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "x509_acert.h"

/*
 * OpenSSL ASN.1 template translation of RFC 5755 4.1.
 */

ASN1_SEQUENCE(OSSL_OBJECT_DIGEST_INFO) = {
    ASN1_EMBED(OSSL_OBJECT_DIGEST_INFO, digestedObjectType, ASN1_ENUMERATED),
    ASN1_OPT(OSSL_OBJECT_DIGEST_INFO, otherObjectTypeID, ASN1_OBJECT),
    ASN1_EMBED(OSSL_OBJECT_DIGEST_INFO, digestAlgorithm, X509_ALGOR),
    ASN1_EMBED(OSSL_OBJECT_DIGEST_INFO, objectDigest, ASN1_BIT_STRING),
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
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(X509_ACERT_INFO)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(OSSL_ISSUER_SERIAL)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(OSSL_OBJECT_DIGEST_INFO)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(X509_ACERT_ISSUER_V2FORM)

IMPLEMENT_PEM_rw(X509_ACERT, X509_ACERT, PEM_STRING_ACERT, X509_ACERT)

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

void OSSL_OBJECT_DIGEST_INFO_get0_digest(const OSSL_OBJECT_DIGEST_INFO *o,
                                         int *digestedObjectType,
                                         const X509_ALGOR **digestAlgorithm,
                                         const ASN1_BIT_STRING **digest)
{
    if (digestedObjectType != NULL)
        *digestedObjectType = ASN1_ENUMERATED_get(&o->digestedObjectType);
    if (digestAlgorithm != NULL)
        *digestAlgorithm = &o->digestAlgorithm;
    if (digest != NULL)
        *digest = &o->objectDigest;
}

const X509_NAME *OSSL_ISSUER_SERIAL_get0_issuer(const OSSL_ISSUER_SERIAL *isss)
{
    return get_dirName(isss->issuer);
}

const ASN1_INTEGER *OSSL_ISSUER_SERIAL_get0_serial(const OSSL_ISSUER_SERIAL *isss)
{
    return &isss->serial;
}

const ASN1_BIT_STRING *OSSL_ISSUER_SERIAL_get0_issuerUID(const OSSL_ISSUER_SERIAL *isss)
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

const GENERAL_NAMES *X509_ACERT_get0_holder_entityName(const X509_ACERT *x)
{
    return x->acinfo->holder.entityName;
}

const OSSL_ISSUER_SERIAL *X509_ACERT_get0_holder_baseCertId(const X509_ACERT *x)
{
    return x->acinfo->holder.baseCertificateID;
}

const OSSL_OBJECT_DIGEST_INFO *X509_ACERT_get0_holder_digest(const X509_ACERT *x)
{
    return x->acinfo->holder.objectDigestInfo;
}

const X509_NAME *X509_ACERT_get0_issuerName(const X509_ACERT *x)
{
    if (x->acinfo->issuer.type != X509_ACERT_ISSUER_V2
        || x->acinfo->issuer.u.v2Form == NULL)
        return NULL;

    return get_dirName(x->acinfo->issuer.u.v2Form->issuerName);
}

const ASN1_BIT_STRING *X509_ACERT_get0_issuerUID(const X509_ACERT *x)
{
    return x->acinfo->issuerUID;
}

const X509_ALGOR *X509_ACERT_get0_info_sigalg(const X509_ACERT *x)
{
    return &x->acinfo->signature;
}

const ASN1_INTEGER *X509_ACERT_get0_serialNumber(const X509_ACERT *x)
{
    return &x->acinfo->serialNumber;
}

const ASN1_GENERALIZEDTIME *X509_ACERT_get0_notBefore(const X509_ACERT *x)
{
    return x->acinfo->validityPeriod.notBefore;
}

const ASN1_GENERALIZEDTIME *X509_ACERT_get0_notAfter(const X509_ACERT *x)
{
    return x->acinfo->validityPeriod.notAfter;
}
