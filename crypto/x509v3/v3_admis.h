/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_V3_ADMISSION_H
# define HEADER_V3_ADMISSION_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NamingAuthority_st {
    ASN1_OBJECT* namingAuthorityId;
    ASN1_IA5STRING* namingAuthorityUrl;
    ASN1_STRING* namingAuthorityText;          /* i.e. DIRECTORYSTRING */
} NAMING_AUTHORITY;

typedef struct ProfessionInfo_st {
    NAMING_AUTHORITY* namingAuthority;
    STACK_OF(ASN1_STRING)* professionItems;    /* i.e. DIRECTORYSTRING */
    STACK_OF(ASN1_OBJECT)* professionOIDs;
    ASN1_PRINTABLESTRING* registrationNumber;
    ASN1_OCTET_STRING* addProfessionInfo;
} PROFESSION_INFO;

typedef struct Admissions_st {
    GENERAL_NAME* admissionAuthority;
    NAMING_AUTHORITY* namingAuthority;
    STACK_OF(PROFESSION_INFO)* professionInfos;
} ADMISSIONS;

typedef struct AdmissionSyntax_st {
    GENERAL_NAME* admissionAuthority;
    STACK_OF(ADMISSIONS)* contentsOfAdmissions;
} ADMISSION_SYNTAX;

DECLARE_ASN1_ITEM(ADMISSIONS)
DECLARE_ASN1_ITEM(NAMING_AUTHORITY)
DECLARE_ASN1_ITEM(PROFESSION_INFO)
DECLARE_ASN1_ITEM(ADMISSION_SYNTAX)

DECLARE_ASN1_FUNCTIONS(NAMING_AUTHORITY)
DECLARE_ASN1_FUNCTIONS(PROFESSION_INFO)
DECLARE_ASN1_FUNCTIONS(ADMISSIONS)
DECLARE_ASN1_FUNCTIONS(ADMISSION_SYNTAX)

DEFINE_STACK_OF(ADMISSIONS)
DEFINE_STACK_OF(PROFESSION_INFO)
DEFINE_STACK_OF(ASN1_STRING)

#ifdef  __cplusplus
}
#endif
#endif
