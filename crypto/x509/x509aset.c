/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <crypto/x509_acert.h>
#include <openssl/x509_acert.h>

static int replace_gentime(ASN1_STRING **dest, ASN1_GENERALIZEDTIME *src)
{
    ASN1_STRING *s;

    if (src->type != V_ASN1_GENERALIZEDTIME)
        return 0;

    if (*dest == src)
        return 1;

    s = ASN1_STRING_dup(src);
    if (s == NULL)
        goto oom;

    ASN1_STRING_free(*dest);
    *dest = s;

    return 1;

oom:
    ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
    return 0;
}

static int replace_dirName(GENERAL_NAMES **names, const X509_NAME *dirName)
{
    GENERAL_NAME *gen_name = NULL;
    STACK_OF(GENERAL_NAME) *new_names = NULL;
    X509_NAME *name_copy = NULL;

    if ((name_copy = X509_NAME_dup(dirName)) == NULL)
        goto oom;

    if ((new_names = sk_GENERAL_NAME_new_null()) == NULL)
        goto oom;

    if ((gen_name = GENERAL_NAME_new()) == NULL)
        goto oom;

    if (sk_GENERAL_NAME_push(new_names, gen_name) <= 0)
        goto err;

    GENERAL_NAME_set0_value(gen_name, GEN_DIRNAME, name_copy);

    GENERAL_NAMES_free(*names);
    *names = new_names;

    return 1;

oom:
    ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
err:
    GENERAL_NAME_free(gen_name);
    sk_GENERAL_NAME_free(new_names);
    X509_NAME_free(name_copy);
    return 0;
}

void OSSL_OBJECT_DIGEST_INFO_set0_digest(OSSL_OBJECT_DIGEST_INFO *o,
                                         ASN1_ENUMERATED *digestedObjectType,
                                         X509_ALGOR *digestAlgorithm,
                                         ASN1_BIT_STRING *digest)
{
    ASN1_ENUMERATED_free(o->digestedObjectType);
    X509_ALGOR_free(o->digestAlgorithm);
    ASN1_BIT_STRING_free(o->objectDigest);

    o->digestedObjectType = digestedObjectType;
    o->digestAlgorithm = digestAlgorithm;
    o->objectDigest = digest;
}

int OSSL_ISSUER_SERIAL_set1_issuer(OSSL_ISSUER_SERIAL *isss, X509_NAME *issuer)
{
    return replace_dirName(&isss->issuer, issuer);
}

int OSSL_ISSUER_SERIAL_set1_serial(OSSL_ISSUER_SERIAL *isss,
				   ASN1_INTEGER *serial)
{
    return ASN1_STRING_copy(&isss->serial, serial);
}

int OSSL_ISSUER_SERIAL_set1_issuerUID(OSSL_ISSUER_SERIAL *isss,
				      ASN1_BIT_STRING *uid)
{
    ASN1_BIT_STRING_free(isss->issuerUID);
    isss->issuerUID = ASN1_STRING_dup(uid);
    if (isss->issuerUID == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

int X509_ACERT_set_version(X509_ACERT *x, long version)
{
    return ASN1_INTEGER_set(&x->acinfo->version, version);
}

void X509_ACERT_set0_holder_entityName(X509_ACERT *x, GENERAL_NAMES *names)
{
    GENERAL_NAMES_free(x->acinfo->holder.entityName);
    x->acinfo->holder.entityName = names;
}

void X509_ACERT_set0_holder_baseCertId(X509_ACERT *x,
                                       OSSL_ISSUER_SERIAL *isss)
{
    OSSL_ISSUER_SERIAL_free(x->acinfo->holder.baseCertificateID);
    x->acinfo->holder.baseCertificateID = isss;
}

void X509_ACERT_set0_holder_digest(X509_ACERT *x,
                                   OSSL_OBJECT_DIGEST_INFO *dinfo)
{
    OSSL_OBJECT_DIGEST_INFO_free(x->acinfo->holder.objectDigestInfo);
    x->acinfo->holder.objectDigestInfo = dinfo;
}

int X509_ACERT_set1_issuerName(X509_ACERT *x, const X509_NAME *name)
{
    X509_ACERT_ISSUER_V2FORM *v2Form;

    v2Form = x->acinfo->issuer.u.v2Form;

    /* only v2Form is supported, so always create that version */
    if (v2Form == NULL) {
        v2Form = X509_ACERT_ISSUER_V2FORM_new();
        if (v2Form == NULL)
            goto oom;
        x->acinfo->issuer.u.v2Form = v2Form;
        x->acinfo->issuer.type = X509_ACERT_ISSUER_V2;
    }

    return replace_dirName(&(v2Form->issuerName), name);

oom:
    ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
    return 0;
}

int X509_ACERT_set1_serialNumber(X509_ACERT *x, ASN1_INTEGER *serial)
{
    return ASN1_STRING_copy(&x->acinfo->serialNumber, serial);
}

int X509_ACERT_set1_notBefore(X509_ACERT *x, ASN1_GENERALIZEDTIME *time)
{
    return replace_gentime(&x->acinfo->validityPeriod.notBefore, time);
}

int X509_ACERT_set1_notAfter(X509_ACERT *x, ASN1_GENERALIZEDTIME *time)
{
    return replace_gentime(&x->acinfo->validityPeriod.notAfter, time);
}
