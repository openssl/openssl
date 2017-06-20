/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/conf.h>
#include <openssl/ossl_typ.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <openssl/x509v3.h>

#include <openssl/safestack.h>

#include "v3_admis.h"
#include "ext_dat.h"


ASN1_SEQUENCE(NAMING_AUTHORITY) = {
    ASN1_OPT(NAMING_AUTHORITY, namingAuthorityId, ASN1_OBJECT),
    ASN1_OPT(NAMING_AUTHORITY, namingAuthorityUrl, ASN1_IA5STRING),
    ASN1_OPT(NAMING_AUTHORITY, namingAuthorityText, DIRECTORYSTRING),
} ASN1_SEQUENCE_END(NAMING_AUTHORITY)

ASN1_SEQUENCE(PROFESSION_INFO) = {
    ASN1_EXP_OPT(PROFESSION_INFO, namingAuthority, NAMING_AUTHORITY, 0),
    ASN1_SEQUENCE_OF(PROFESSION_INFO, professionItems, DIRECTORYSTRING),
    ASN1_SEQUENCE_OF_OPT(PROFESSION_INFO, professionOIDs, ASN1_OBJECT),
    ASN1_OPT(PROFESSION_INFO, registrationNumber, ASN1_PRINTABLESTRING),
    ASN1_OPT(PROFESSION_INFO, addProfessionInfo, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(PROFESSION_INFO)

ASN1_SEQUENCE(ADMISSIONS) = {
    ASN1_EXP_OPT(ADMISSIONS, admissionAuthority, GENERAL_NAME, 0),
    ASN1_EXP_OPT(ADMISSIONS, namingAuthority, NAMING_AUTHORITY, 1),
    ASN1_SEQUENCE_OF(ADMISSIONS, professionInfos, PROFESSION_INFO),
} ASN1_SEQUENCE_END(ADMISSIONS)

ASN1_SEQUENCE(ADMISSION_SYNTAX) = {
    ASN1_OPT(ADMISSION_SYNTAX, admissionAuthority, GENERAL_NAME),
    ASN1_SEQUENCE_OF(ADMISSION_SYNTAX, contentsOfAdmissions, ADMISSIONS),
} ASN1_SEQUENCE_END(ADMISSION_SYNTAX)

IMPLEMENT_ASN1_FUNCTIONS(NAMING_AUTHORITY)
IMPLEMENT_ASN1_FUNCTIONS(PROFESSION_INFO)
IMPLEMENT_ASN1_FUNCTIONS(ADMISSIONS)
IMPLEMENT_ASN1_FUNCTIONS(ADMISSION_SYNTAX)

static int i2r_ADMISSION_SYNTAX(const struct v3_ext_method *method, void *in,
                                BIO *bp, int ind);

const X509V3_EXT_METHOD v3_ext_admission = {
    NID_x509ExtAdmission,   /* .ext_nid = */
    0,                      /* .ext_flags = */
    ASN1_ITEM_ref(ADMISSION_SYNTAX), /* .it = */
    NULL, NULL, NULL, NULL,
    NULL,                   /* .i2s = */
    NULL,                   /* .s2i = */
    NULL,                   /* .i2v = */
    NULL,                   /* .v2i = */
    &i2r_ADMISSION_SYNTAX,  /* .i2r = */
    NULL,                   /* .r2i = */
    NULL                    /* extension-specific data */
};


static int i2r_NAMING_AUTHORITY(const struct v3_ext_method *method, void *in,
                                BIO *bp, int ind)
{
    NAMING_AUTHORITY * namingAuthority = (NAMING_AUTHORITY*) in;

    if (namingAuthority == NULL)
        return 0;

    if (namingAuthority->namingAuthorityId == NULL
        && namingAuthority->namingAuthorityText == NULL
        && namingAuthority->namingAuthorityUrl == NULL)
        return 0;

    if (BIO_printf(bp, "%*snamingAuthority: ", ind, "") <= 0)
        goto err;

    if (namingAuthority->namingAuthorityId != NULL) {
        char objbuf[128];
        const char *ln = OBJ_nid2ln(OBJ_obj2nid(namingAuthority->namingAuthorityId));

        if (BIO_printf(bp, "%*s  admissionAuthorityId: ", ind, "") <= 0)
            goto err;

        OBJ_obj2txt(objbuf, sizeof objbuf, namingAuthority->namingAuthorityId, 1);

        if (BIO_printf(bp, "%s%s%s%s\n", ln ? ln : "",
                       ln ? " (" : "", objbuf, ln ? ")" : "") <= 0)
            goto err;
    }
    if (namingAuthority->namingAuthorityText != NULL) {
        if (BIO_printf(bp, "%*s  namingAuthorityText: ", ind, "") <= 0
            || ASN1_STRING_print(bp, namingAuthority->namingAuthorityText) <= 0
            || BIO_printf(bp, "\n") <= 0)
            goto err;
    }
    if (namingAuthority->namingAuthorityUrl != NULL ) {
        if (BIO_printf(bp, "%*s  namingAuthorityUrl: ", ind, "") <= 0
            || ASN1_STRING_print(bp, namingAuthority->namingAuthorityUrl) <= 0
            || BIO_printf(bp, "\n") <= 0)
            goto err;
    }
    return 1;

err:
    return 0;
}

static int i2r_ADMISSION_SYNTAX(const struct v3_ext_method *method, void *in,
                                BIO *bp, int ind)
{
    ADMISSION_SYNTAX * admission = (ADMISSION_SYNTAX *)in;
    int i, j, k;

    if (admission->admissionAuthority != NULL) {
        if (BIO_printf(bp, "%*sadmissionAuthority:\n", ind, "") <= 0
            || BIO_printf(bp, "%*s  ", ind, "") <= 0
            || GENERAL_NAME_print(bp, admission->admissionAuthority) <= 0
            || BIO_printf(bp, "\n") <= 0)
            goto err;
    }

    for (i = 0; i < sk_ADMISSIONS_num(admission->contentsOfAdmissions); i++) {
        ADMISSIONS* entry = sk_ADMISSIONS_value(admission->contentsOfAdmissions, i);

        if (BIO_printf(bp, "%*sEntry %0d:\n", ind, "", 1 + i) <= 0) goto err;

        if (entry->admissionAuthority != NULL) {
            if (BIO_printf(bp, "%*s  admissionAuthority:\n", ind, "") <= 0
                || BIO_printf(bp, "%*s    ", ind, "") <= 0
                || GENERAL_NAME_print(bp, entry->admissionAuthority) <= 0
                || BIO_printf(bp, "\n") <= 0)
                goto err;
        }

        if (entry->namingAuthority != NULL) {
            if (i2r_NAMING_AUTHORITY(method, entry->namingAuthority, bp, ind) <= 0)
                goto err;
        }

        for (j = 0; j < sk_PROFESSION_INFO_num(entry->professionInfos); j++) {
            PROFESSION_INFO* pinfo = sk_PROFESSION_INFO_value(entry->professionInfos, j);

            if (BIO_printf(bp, "%*s  Profession Info Entry %0d:\n", ind, "", 1 + j) <= 0)
                goto err;

            if (pinfo->registrationNumber != NULL) {
                if (BIO_printf(bp, "%*s    registrationNumber: ", ind, "") <= 0
                    || ASN1_STRING_print(bp, pinfo->registrationNumber) <= 0
                    || BIO_printf(bp, "\n") <= 0)
                    goto err;
            }

            if (pinfo->namingAuthority != NULL) {
                if (i2r_NAMING_AUTHORITY(method, pinfo->namingAuthority, bp, ind + 2) <= 0)
                    goto err;
            }

            if (pinfo->professionItems != NULL) {

                if (BIO_printf(bp, "%*s    Info Entries:\n", ind, "") <= 0)
                    goto err;
                for (k = 0; k < sk_ASN1_STRING_num(pinfo->professionItems); k++) {
                    ASN1_STRING* val = sk_ASN1_STRING_value(pinfo->professionItems, k);

                    if (BIO_printf(bp, "%*s      ", ind, "") <= 0
                        || ASN1_STRING_print(bp, val) <= 0
                        || BIO_printf(bp, "\n") <= 0)
                        goto err;
                }
            }

            if (pinfo->professionOIDs != NULL) {
                if (BIO_printf(bp, "%*s    Profession OIDs:\n", ind, "") <= 0)
                    goto err;
                for (k = 0; k < sk_ASN1_OBJECT_num(pinfo->professionOIDs); k++) {
                    ASN1_OBJECT* obj = sk_ASN1_OBJECT_value(pinfo->professionOIDs, k);
                    const char *ln = OBJ_nid2ln(OBJ_obj2nid(obj));
                    char objbuf[128];

                    OBJ_obj2txt(objbuf, sizeof(objbuf), obj, 1);
                    if (BIO_printf(bp, "%*s      %s%s%s%s\n", ind, "",
                                   ln ? ln : "", ln ? " (" : "",
                                   objbuf, ln ? ")" : "") <= 0)
                        goto err;
                }
            }
        }
    }
    return 1;

err:
    return -1;
}
