/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "x509_local.h"
#include <stdio.h>
#include <openssl/x509v3.h>
#include <openssl/ts.h>
#include <crypto/x509.h>
#include <crypto/x509_acert.h>
#include <openssl/platcert.h>
#include <crypto/platcert.h>
#include <crypto/x509/x509_acert.h>

ASN1_SEQUENCE(OSSL_URI_REFERENCE) = {
    ASN1_SIMPLE(OSSL_URI_REFERENCE, uniformResourceIdentifier, ASN1_IA5STRING),
    ASN1_OPT(OSSL_URI_REFERENCE, hashAlgorithm, X509_ALGOR),
    ASN1_OPT(OSSL_URI_REFERENCE, hashValue, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(OSSL_URI_REFERENCE)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_URI_REFERENCE)

ASN1_SEQUENCE(OSSL_COMMON_CRITERIA_MEASURES) = {
    ASN1_SIMPLE(OSSL_COMMON_CRITERIA_MEASURES, version, ASN1_IA5STRING),
    ASN1_SIMPLE(OSSL_COMMON_CRITERIA_MEASURES, assurancelevel, ASN1_ENUMERATED),
    ASN1_SIMPLE(OSSL_COMMON_CRITERIA_MEASURES, evaluationStatus, ASN1_ENUMERATED),
    ASN1_OPT(OSSL_COMMON_CRITERIA_MEASURES, plus, ASN1_FBOOLEAN),
    ASN1_IMP_OPT(OSSL_COMMON_CRITERIA_MEASURES, strengthOfFunction, ASN1_ENUMERATED, 0),
    ASN1_IMP_OPT(OSSL_COMMON_CRITERIA_MEASURES, profileOid, ASN1_OBJECT, 1),
    ASN1_IMP_OPT(OSSL_COMMON_CRITERIA_MEASURES, profileUri, OSSL_URI_REFERENCE, 2),
    ASN1_IMP_OPT(OSSL_COMMON_CRITERIA_MEASURES, targetOid, ASN1_OBJECT, 3),
    ASN1_IMP_OPT(OSSL_COMMON_CRITERIA_MEASURES, targetUri, OSSL_URI_REFERENCE, 4),
} ASN1_SEQUENCE_END(OSSL_COMMON_CRITERIA_MEASURES)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_COMMON_CRITERIA_MEASURES)

ASN1_SEQUENCE(OSSL_FIPS_LEVEL) = {
    ASN1_SIMPLE(OSSL_FIPS_LEVEL, version, ASN1_IA5STRING),
    ASN1_SIMPLE(OSSL_FIPS_LEVEL, level, ASN1_ENUMERATED),
    ASN1_OPT(OSSL_FIPS_LEVEL, plus, ASN1_FBOOLEAN)
} ASN1_SEQUENCE_END(OSSL_FIPS_LEVEL)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_FIPS_LEVEL)

ASN1_SEQUENCE(OSSL_TBB_SECURITY_ASSERTIONS) = {
    ASN1_OPT(OSSL_TBB_SECURITY_ASSERTIONS, version, ASN1_INTEGER),
    ASN1_IMP_OPT(OSSL_TBB_SECURITY_ASSERTIONS, ccInfo, OSSL_COMMON_CRITERIA_MEASURES, 0),
    ASN1_IMP_OPT(OSSL_TBB_SECURITY_ASSERTIONS, fipsLevel, OSSL_FIPS_LEVEL, 1),
    ASN1_IMP_OPT(OSSL_TBB_SECURITY_ASSERTIONS, rtmType, ASN1_ENUMERATED, 2),
    ASN1_OPT(OSSL_TBB_SECURITY_ASSERTIONS, iso9000Certified, ASN1_FBOOLEAN),
    ASN1_OPT(OSSL_TBB_SECURITY_ASSERTIONS, iso9000Uri, ASN1_IA5STRING),
} ASN1_SEQUENCE_END(OSSL_TBB_SECURITY_ASSERTIONS)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_TBB_SECURITY_ASSERTIONS)

ASN1_SEQUENCE(OSSL_MANUFACTURER_ID) = {
    ASN1_SIMPLE(OSSL_MANUFACTURER_ID, manufacturerIdentifier, ASN1_OBJECT)
} ASN1_SEQUENCE_END(OSSL_MANUFACTURER_ID)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_MANUFACTURER_ID)

ASN1_SEQUENCE(OSSL_TCG_SPEC_VERSION) = {
    ASN1_SIMPLE(OSSL_TCG_SPEC_VERSION, majorVersion, ASN1_INTEGER),
    ASN1_SIMPLE(OSSL_TCG_SPEC_VERSION, minorVersion, ASN1_INTEGER),
    ASN1_SIMPLE(OSSL_TCG_SPEC_VERSION, revision, ASN1_INTEGER)
} ASN1_SEQUENCE_END(OSSL_TCG_SPEC_VERSION)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_TCG_SPEC_VERSION)

ASN1_SEQUENCE(OSSL_TCG_PLATFORM_SPEC) = {
    ASN1_SIMPLE(OSSL_TCG_PLATFORM_SPEC, version, OSSL_TCG_SPEC_VERSION),
    ASN1_SIMPLE(OSSL_TCG_PLATFORM_SPEC, platformClass, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(OSSL_TCG_PLATFORM_SPEC)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_TCG_PLATFORM_SPEC)

ASN1_SEQUENCE(OSSL_TCG_CRED_TYPE) = {
    ASN1_SIMPLE(OSSL_TCG_CRED_TYPE, certificateType, ASN1_OBJECT)
} ASN1_SEQUENCE_END(OSSL_TCG_CRED_TYPE)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_TCG_CRED_TYPE)

ASN1_SEQUENCE(OSSL_COMPONENT_ADDRESS) = {
    ASN1_SIMPLE(OSSL_COMPONENT_ADDRESS, addressType, ASN1_OBJECT),
    ASN1_SIMPLE(OSSL_COMPONENT_ADDRESS, addressValue, ASN1_UTF8STRING)
} ASN1_SEQUENCE_END(OSSL_COMPONENT_ADDRESS)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_COMPONENT_ADDRESS)

ASN1_SEQUENCE(OSSL_PLATFORM_PROPERTY) = {
    ASN1_SIMPLE(OSSL_PLATFORM_PROPERTY, propertyName, ASN1_UTF8STRING),
    ASN1_SIMPLE(OSSL_PLATFORM_PROPERTY, propertyValue, ASN1_UTF8STRING),
    ASN1_IMP_OPT(OSSL_PLATFORM_PROPERTY, status, ASN1_ENUMERATED, 0)
} ASN1_SEQUENCE_END(OSSL_PLATFORM_PROPERTY)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_PLATFORM_PROPERTY)

ASN1_SEQUENCE(OSSL_COMPONENT_CLASS) = {
    ASN1_SIMPLE(OSSL_COMPONENT_CLASS, componentClassRegistry, ASN1_OBJECT),
    ASN1_SIMPLE(OSSL_COMPONENT_CLASS, componentClassValue, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(OSSL_COMPONENT_CLASS)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_COMPONENT_CLASS)

ASN1_SEQUENCE(OSSL_COMPONENT_IDENTIFIER) = {
    ASN1_SIMPLE(OSSL_COMPONENT_IDENTIFIER, componentClass, OSSL_COMPONENT_CLASS),
    ASN1_SIMPLE(OSSL_COMPONENT_IDENTIFIER, componentManufacturer, ASN1_UTF8STRING),
    ASN1_SIMPLE(OSSL_COMPONENT_IDENTIFIER, componentModel, ASN1_UTF8STRING),
    ASN1_IMP_OPT(OSSL_COMPONENT_IDENTIFIER, componentSerial, ASN1_UTF8STRING, 0),
    ASN1_IMP_OPT(OSSL_COMPONENT_IDENTIFIER, componentRevision, ASN1_UTF8STRING, 1),
    ASN1_IMP_OPT(OSSL_COMPONENT_IDENTIFIER, componentManufacturerId, ASN1_OBJECT, 2),
    ASN1_IMP_OPT(OSSL_COMPONENT_IDENTIFIER, fieldReplaceable, ASN1_BOOLEAN, 3),
    ASN1_IMP_SEQUENCE_OF_OPT(OSSL_COMPONENT_IDENTIFIER, componentAddresses, OSSL_COMPONENT_ADDRESS, 4),
    ASN1_IMP_OPT(OSSL_COMPONENT_IDENTIFIER, componentPlatformCert, OSSL_PCV2_CERTIFICATE_IDENTIFIER, 5),
    ASN1_IMP_OPT(OSSL_COMPONENT_IDENTIFIER, componentPlatformCertUri, OSSL_URI_REFERENCE, 6),
    ASN1_IMP_OPT(OSSL_COMPONENT_IDENTIFIER, status, ASN1_ENUMERATED, 7)
} ASN1_SEQUENCE_END(OSSL_COMPONENT_IDENTIFIER)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_COMPONENT_IDENTIFIER)

ASN1_SEQUENCE(OSSL_PLATFORM_CONFIG) = {
    ASN1_IMP_SEQUENCE_OF_OPT(OSSL_PLATFORM_CONFIG, componentIdentifiers, OSSL_COMPONENT_IDENTIFIER, 0),
    ASN1_IMP_OPT(OSSL_PLATFORM_CONFIG, componentIdentifiersUri, OSSL_URI_REFERENCE, 1),
    ASN1_IMP_SEQUENCE_OF_OPT(OSSL_PLATFORM_CONFIG, platformProperties, OSSL_PLATFORM_PROPERTY, 2),
    ASN1_IMP_OPT(OSSL_PLATFORM_CONFIG, platformPropertiesUri, OSSL_URI_REFERENCE, 3)
} ASN1_SEQUENCE_END(OSSL_PLATFORM_CONFIG)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_PLATFORM_CONFIG)

ASN1_SEQUENCE(OSSL_PCV2_TRAIT) = {
    ASN1_SIMPLE(OSSL_PCV2_TRAIT, traitId, ASN1_OBJECT),
    ASN1_SIMPLE(OSSL_PCV2_TRAIT, traitCategory, ASN1_OBJECT),
    ASN1_SIMPLE(OSSL_PCV2_TRAIT, traitRegistry, ASN1_OBJECT),
    ASN1_IMP_OPT(OSSL_PCV2_TRAIT, description, ASN1_UTF8STRING, 0),
    ASN1_IMP_OPT(OSSL_PCV2_TRAIT, descriptionURI, ASN1_UTF8STRING, 1),
    ASN1_SIMPLE(OSSL_PCV2_TRAIT, traitValue, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(OSSL_PCV2_TRAIT)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_PCV2_TRAIT)

ASN1_ITEM_TEMPLATE(OSSL_PCV2_TRAITS) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, OSSL_PCV2_TRAITS, OSSL_PCV2_TRAIT)
ASN1_ITEM_TEMPLATE_END(OSSL_PCV2_TRAITS)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_PCV2_TRAITS)

ASN1_SEQUENCE(OSSL_HASHED_CERTIFICATE_IDENTIFIER) = {
    ASN1_SIMPLE(OSSL_HASHED_CERTIFICATE_IDENTIFIER, hashValue, X509_ALGOR),
    ASN1_SIMPLE(OSSL_HASHED_CERTIFICATE_IDENTIFIER, hashOverSignatureValue, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(OSSL_HASHED_CERTIFICATE_IDENTIFIER)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_HASHED_CERTIFICATE_IDENTIFIER)

ASN1_SEQUENCE(OSSL_PCV2_CERTIFICATE_IDENTIFIER) = {
    ASN1_IMP_OPT(OSSL_PCV2_CERTIFICATE_IDENTIFIER, hashedCertIdentifier, OSSL_HASHED_CERTIFICATE_IDENTIFIER, 0),
    ASN1_IMP_OPT(OSSL_PCV2_CERTIFICATE_IDENTIFIER, genericCertIdentifier, OSSL_ISSUER_SERIAL, 1)
} ASN1_SEQUENCE_END(OSSL_PCV2_CERTIFICATE_IDENTIFIER)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_PCV2_CERTIFICATE_IDENTIFIER)

ASN1_SEQUENCE(OSSL_COMMON_CRITERIA_EVALUATION) = {
    ASN1_SIMPLE(OSSL_COMMON_CRITERIA_EVALUATION, cCMeasures, OSSL_COMMON_CRITERIA_MEASURES),
    ASN1_SIMPLE(OSSL_COMMON_CRITERIA_EVALUATION, cCCertificateNumber, ASN1_UTF8STRING),
    ASN1_SIMPLE(OSSL_COMMON_CRITERIA_EVALUATION, cCCertificateAuthority, ASN1_UTF8STRING),
    ASN1_IMP_OPT(OSSL_COMMON_CRITERIA_EVALUATION, evaluationScheme, ASN1_UTF8STRING, 0),
    ASN1_IMP_OPT(OSSL_COMMON_CRITERIA_EVALUATION, cCCertificateIssuanceDate, ASN1_GENERALIZEDTIME, 1),
    ASN1_IMP_OPT(OSSL_COMMON_CRITERIA_EVALUATION, cCCertificateExpiryDate, ASN1_GENERALIZEDTIME, 2)
} ASN1_SEQUENCE_END(OSSL_COMMON_CRITERIA_EVALUATION)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_COMMON_CRITERIA_EVALUATION)

ASN1_SEQUENCE(OSSL_ISO9000_CERTIFICATION) = {
    ASN1_OPT(OSSL_ISO9000_CERTIFICATION, iso9000Certified, ASN1_FBOOLEAN),
    ASN1_OPT(OSSL_ISO9000_CERTIFICATION, iso9000Uri, ASN1_IA5STRING),
} ASN1_SEQUENCE_END(OSSL_ISO9000_CERTIFICATION)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_ISO9000_CERTIFICATION)

ASN1_ITEM_TEMPLATE(OSSL_COMPONENT_IDENTIFIER_V2) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Traits, OSSL_PCV2_TRAIT)
ASN1_ITEM_TEMPLATE_END(OSSL_COMPONENT_IDENTIFIER_V2)

ASN1_ITEM_TEMPLATE(OSSL_PLATFORM_COMPONENTS) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, PlatformComponents, OSSL_COMPONENT_IDENTIFIER_V2)
ASN1_ITEM_TEMPLATE_END(OSSL_PLATFORM_COMPONENTS)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_COMPONENT_IDENTIFIER_V2)
IMPLEMENT_ASN1_FUNCTIONS(OSSL_PLATFORM_COMPONENTS)

ASN1_SEQUENCE(OSSL_PLATFORM_CONFIG_V3) = {
    ASN1_IMP_SEQUENCE_OF_OPT(OSSL_PLATFORM_CONFIG_V3, platformComponents, OSSL_COMPONENT_IDENTIFIER_V2, 0),
    ASN1_IMP_SEQUENCE_OF_OPT(OSSL_PLATFORM_CONFIG_V3, platformProperties, OSSL_PLATFORM_PROPERTY, 1),
} ASN1_SEQUENCE_END(OSSL_PLATFORM_CONFIG_V3)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_PLATFORM_CONFIG_V3)

static int X509_ALGOR_print_bio(BIO *bio, const X509_ALGOR *alg)
{
    int i = OBJ_obj2nid(alg->algorithm);

    return BIO_printf(bio, "Hash Algorithm: %s\n",
                      (i == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(i));
}

int OSSL_URI_REFERENCE_print(BIO *out, OSSL_URI_REFERENCE *value, int indent)
{
    int rc;

    rc = BIO_printf(out, "%*sURI: %.*s\n", indent, "",
                    value->uniformResourceIdentifier->length,
                    value->uniformResourceIdentifier->data);
    if (rc <= 0)
        return rc;
    if (value->hashAlgorithm != NULL) {
        rc = BIO_printf(out, "%*s", indent, "");
        if (rc <= 0)
            return rc;
        rc = X509_ALGOR_print_bio(out, value->hashAlgorithm);
        if (rc <= 0)
            return rc;
    }
    if (value->hashValue != NULL) {
        rc = BIO_printf(out, "%*sHash Value: ", indent, "");
        if (rc <= 0)
            return rc;
        rc = ossl_bio_print_hex(out, value->hashValue->data, value->hashValue->length);
        if (rc <= 0)
            return rc;
    }
    return rc;
}

static ENUMERATED_NAMES measurement_root_types[] = {
    {OSSL_MEASUREMENT_ROOT_TYPE_STATIC, "Static (0)", "static"},
    {OSSL_MEASUREMENT_ROOT_TYPE_DYNAMIC, "Dynamic (1)", "dynamic"},
    {OSSL_MEASUREMENT_ROOT_TYPE_NONHOST, "Non-Host (2)", "nonHost"},
    {OSSL_MEASUREMENT_ROOT_TYPE_HYBRID, "Hybrid (3)", "hybrid"},
    {OSSL_MEASUREMENT_ROOT_TYPE_PHYSICAL, "Physical (4)", "physical"},
    {OSSL_MEASUREMENT_ROOT_TYPE_VIRTUAL, "Virtual (5)", "virtual"},
    {-1, NULL, NULL},
};

static ENUMERATED_NAMES evaluation_assurance_levels[] = {
    {OSSL_EVALUATION_ASSURANCE_LEVEL_1, "Level 1", "level1"},
    {OSSL_EVALUATION_ASSURANCE_LEVEL_2, "Level 2", "level2"},
    {OSSL_EVALUATION_ASSURANCE_LEVEL_3, "Level 3", "level3"},
    {OSSL_EVALUATION_ASSURANCE_LEVEL_4, "Level 4", "level4"},
    {OSSL_EVALUATION_ASSURANCE_LEVEL_5, "Level 5", "level5"},
    {OSSL_EVALUATION_ASSURANCE_LEVEL_6, "Level 6", "level6"},
    {OSSL_EVALUATION_ASSURANCE_LEVEL_7, "Level 7", "level7"},
    {-1, NULL, NULL},
};

static ENUMERATED_NAMES evaluation_statuses[] = {
    {OSSL_EVALUATION_STATUS_DESIGNED_TO_MEET, "Designed To Meet (0)", "designedToMeet"},
    {OSSL_EVALUATION_STATUS_EVAL_IN_PROGRESS, "Evaluation In Progress (1)", "evaluationInProgress"},
    {OSSL_EVALUATION_STATUS_EVAL_COMPLETED, "Evaluation Completed (2)", "evaluationCompleted"},
    {-1, NULL, NULL},
};

static ENUMERATED_NAMES strengths_of_function[] = {
    {OSSL_STRENGTH_OF_FUNCTION_BASIC, "Basic (0)", "basic"},
    {OSSL_STRENGTH_OF_FUNCTION_MEDIUM, "Medium (1)", "medium"},
    {OSSL_STRENGTH_OF_FUNCTION_HIGH, "High (2)", "high"},
    {-1, NULL, NULL},
};

static ENUMERATED_NAMES security_levels[] = {
    {OSSL_SECURITY_LEVEL_1, "Level 1", "level1"},
    {OSSL_SECURITY_LEVEL_2, "Level 2", "level2"},
    {OSSL_SECURITY_LEVEL_3, "Level 3", "level3"},
    {OSSL_SECURITY_LEVEL_4, "Level 4", "level4"},
    {-1, NULL, NULL},
};

static ENUMERATED_NAMES attribute_statuses[] = {
    {OSSL_ATTRIBUTE_STATUS_ADDED, "Added (0)", "added"},
    {OSSL_ATTRIBUTE_STATUS_MODIFIED, "Modified (1)", "modified"},
    {OSSL_ATTRIBUTE_STATUS_REMOVED, "Removed (2)", "removed"},
    {-1, NULL, NULL},
};

static int print_oid(BIO *out, const ASN1_OBJECT *oid)
{
    const char *ln;
    char objbuf[80];
    int rc;

    if (OBJ_obj2txt(objbuf, sizeof(objbuf), oid, 1) <= 0)
        return 0;
    ln = OBJ_nid2ln(OBJ_obj2nid(oid));
    rc = (ln != NULL)
        ? BIO_printf(out, "%s (%s)", objbuf, ln)
        : BIO_printf(out, "%s", objbuf);
    return (rc >= 0);
}

int OSSL_COMPONENT_CLASS_print(BIO *out, OSSL_COMPONENT_CLASS *value, int indent)
{
    int rc;

    rc = BIO_printf(out, "%*sComponent Class Registry: ", indent, "");
    if (rc <= 0)
        return rc;
    rc = print_oid(out, value->componentClassRegistry);
    if (rc <= 0)
        return rc;
    rc = BIO_puts(out, "\n");
    if (rc <= 0)
        return rc;
    rc = BIO_printf(out, "%*sComponent Class Registry: ", indent, "");
    if (rc <= 0)
        return rc;
    rc = ossl_bio_print_hex(out,
                            value->componentClassValue->data,
                            value->componentClassValue->length);
    if (rc <= 0)
        return rc;
    return BIO_puts(out, "\n");
}

int OSSL_COMMON_CRITERIA_MEASURES_print(BIO *out,
                                        OSSL_COMMON_CRITERIA_MEASURES *value,
                                        int indent)
{
    int rc;
    int64_t int_val;

    rc = BIO_printf(out, "%*sVersion: %.*s\n", indent, "",
                    value->version->length,
                    value->version->data);
    if (rc <= 0)
        return rc;
    rc = BIO_printf(out, "%*sAssurance Level: ", indent, "");
    if (rc <= 0)
        return rc;
    if (!ASN1_ENUMERATED_get_int64(&int_val, value->assurancelevel)
        || int_val <= 0
        || int_val > INT_MAX)
        return -1;
    if (int_val > 7) {
        rc = BIO_printf(out, "%lld\n", (long long int)int_val);
    } else {
        rc = BIO_printf(out, "%s\n", evaluation_assurance_levels[int_val - 1].lname);
    }
    if (rc <= 0)
        return rc;
    if (!ASN1_ENUMERATED_get_int64(&int_val, value->evaluationStatus)
        || int_val < 0
        || int_val > INT_MAX)
        return -1;
    if (int_val > 2) {
        rc = BIO_printf(out, "%*sEvaluation Status: %lld\n", indent, "", (long long int)int_val);
    } else {
        rc = BIO_printf(out, "%*sEvaluation Status: %s\n", indent, "",
                        evaluation_statuses[int_val].lname);
    }
    if (rc <= 0)
        return rc;
    rc = BIO_printf(out, "%*sPlus: ", indent, "");
    if (rc <= 0)
        return rc;
    if (value->plus) {
        rc = BIO_puts(out, "TRUE\n");
    } else {
        rc = BIO_puts(out, "FALSE\n");
    }
    if (rc <= 0)
        return rc;
    if (value->strengthOfFunction != NULL) {
        rc = BIO_printf(out, "%*sStrength Of Function: ", indent, "");
        if (rc <= 0)
            return rc;
        if (!ASN1_ENUMERATED_get_int64(&int_val, value->strengthOfFunction)
            || int_val < 0
            || int_val > INT_MAX)
            return -1;
        if (int_val > 2) {
            rc = BIO_printf(out, "%lld\n", (long long int)int_val);
        } else {
            rc = BIO_printf(out, "%s\n", strengths_of_function[int_val].lname);
        }
        if (rc <= 0)
            return rc;
    }
    if (value->profileOid != NULL) {
        rc = BIO_printf(out, "%*sProfile OID: ", indent, "");
        if (rc <= 0)
            return rc;
        rc = print_oid(out, value->profileOid);
        if (rc <= 0)
            return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0)
            return rc;
    }
    if (value->profileUri != NULL) {
        rc = BIO_printf(out, "%*sProfile URI:\n", indent, "");
        if (rc <= 0)
            return rc;
        rc = OSSL_URI_REFERENCE_print(out, value->profileUri, indent + 4);
        if (rc <= 0)
            return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0)
            return rc;
    }
    if (value->targetOid != NULL) {
        rc = BIO_printf(out, "%*sTarget OID: ", indent, "");
        if (rc <= 0)
            return rc;
        rc = print_oid(out, value->targetOid);
        if (rc <= 0)
            return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0)
            return rc;
    }
    if (value->targetUri != NULL) {
        rc = BIO_printf(out, "%*sTarget URI:\n", indent, "");
        if (rc <= 0)
            return rc;
        rc = OSSL_URI_REFERENCE_print(out, value->targetUri, indent + 4);
        if (rc <= 0)
            return rc;
    }
    rc = BIO_puts(out, "\n");
    return rc;
}

int OSSL_FIPS_LEVEL_print(BIO *out, OSSL_FIPS_LEVEL *value, int indent)
{
    int rc;
    int64_t int_val;

    rc = BIO_printf(out, "%*sVersion: %.*s\n", indent, "",
                    value->version->length,
                    value->version->data);
    if (rc <= 0)
        return rc;
    if (value->level != NULL) {
        rc = BIO_printf(out, "%*sLevel: ", indent, "");
        if (rc <= 0)
            return rc;
        if (!ASN1_ENUMERATED_get_int64(&int_val, value->level)
            || int_val <= 0
            || int_val > INT_MAX)
            return -1;
        if (int_val > 4) {
            rc = BIO_printf(out, "%lld\n", (long long int)int_val);
        } else {
            rc = BIO_printf(out, "%s\n", security_levels[int_val - 1].lname);
        }
        if (rc <= 0)
            return rc;
    }
    if (value->plus) {
        rc = BIO_printf(out, "%*sPlus: TRUE\n", indent, "");
    } else {
        rc = BIO_printf(out, "%*sPlus: FALSE\n", indent, "");
    }
    return rc;
}

int OSSL_TBB_SECURITY_ASSERTIONS_print(BIO *out, OSSL_TBB_SECURITY_ASSERTIONS *value, int indent)
{
    int rc = 1; /* All fields are OPTIONAL, so we start off at 1 in case all are omitted. */
    int64_t int_val;

    if (value->version != NULL) {
        if (!ASN1_INTEGER_get_int64(&int_val, value->version)
            || int_val < 0
            || int_val > INT_MAX)
            return -1;
        rc = BIO_printf(out, "%*sVersion: %lld\n", indent, "", (long long int)int_val);
    } else {
        rc = BIO_printf(out, "%*sVersion: 1\n", indent, "");
    }
    if (rc <= 0)
        return rc;
    if (value->ccInfo != NULL) {
        rc = BIO_printf(out, "%*sCommon Criteria Measures:\n", indent, "");
        if (rc <= 0)
            return rc;
        rc = OSSL_COMMON_CRITERIA_MEASURES_print(out, value->ccInfo, indent + 4);
        if (rc <= 0)
            return rc;
    }
    if (value->fipsLevel != NULL) {
        rc = BIO_printf(out, "%*sFIPS Level:\n", indent, "");
        if (rc <= 0)
            return rc;
        rc = OSSL_FIPS_LEVEL_print(out, value->fipsLevel, indent + 4);
        if (rc <= 0)
            return rc;
    }
    if (value->rtmType != NULL) {
        rc = BIO_printf(out, "%*sRoot Measurement Type: ", indent, "");
        if (rc <= 0)
            return rc;
        if (!ASN1_ENUMERATED_get_int64(&int_val, value->rtmType)
            || int_val < 0
            || int_val > INT_MAX)
            return -1;
        if (int_val > 5) {
            rc = BIO_printf(out, "%lld\n", (long long int)int_val);
        } else {
            rc = BIO_printf(out, "%s\n", measurement_root_types[int_val].lname);
        }
        if (rc <= 0)
            return rc;
    }
    if (value->iso9000Certified) {
        rc = BIO_printf(out, "%*sPlus: TRUE\n", indent, "");
    } else {
        rc = BIO_printf(out, "%*sPlus: FALSE\n", indent, "");
    }
    if (rc <= 0)
        return rc;
    if (value->iso9000Uri) {
        rc = BIO_printf(out, "%*sISO 9001 URI: %.*s",
                        indent,
                        "",
                        value->iso9000Uri->length,
                        value->iso9000Uri->data);
    }
    return rc;
}

int OSSL_MANUFACTURER_ID_print(BIO *out, OSSL_MANUFACTURER_ID *value, int indent)
{
    int rc;

    rc = BIO_printf(out, "%*sManufacturer Identifier: ", indent, "");
    if (rc <= 0)
        return rc;
    return print_oid(out, value->manufacturerIdentifier);
}

int OSSL_TCG_SPEC_VERSION_print(BIO *out, OSSL_TCG_SPEC_VERSION *value, int indent)
{
    int64_t major, minor, rev;

    if (!ASN1_INTEGER_get_int64(&major, value->majorVersion)
        || major < 0
        || major > INT_MAX)
        return -1;
    if (!ASN1_INTEGER_get_int64(&minor, value->minorVersion)
        || minor < 0
        || minor > INT_MAX)
        return -1;
    if (!ASN1_INTEGER_get_int64(&rev, value->revision)
        || rev < 0
        || rev > INT_MAX)
        return -1;
    return BIO_printf(out, "%*s%lld.%lld.%lld", indent, "",
                      (long long int)major,
                      (long long int)minor,
                      (long long int)rev);
}

int OSSL_TCG_PLATFORM_SPEC_print(BIO *out, OSSL_TCG_PLATFORM_SPEC *value)
{
    int rc;

    rc = OSSL_TCG_SPEC_VERSION_print(out, value->version, 0);
    if (rc <= 0)
        return rc;
    rc = BIO_puts(out, " : ");
    if (rc <= 0)
        return rc;
    return ossl_bio_print_hex(out,
                              value->platformClass->data,
                              value->platformClass->length);
}

int OSSL_TCG_CRED_TYPE_print(BIO *out, OSSL_TCG_CRED_TYPE *value, int indent)
{
    if (BIO_printf(out, "%*sCredential Type: ", indent, "") <= 0)
        return -1;
    return print_oid(out, value->certificateType);
}

int OSSL_COMPONENT_ADDRESS_print(BIO *out, OSSL_COMPONENT_ADDRESS *value, int indent)
{
    int rc;

    rc = BIO_printf(out, "%*sAddress Type: ", indent, "");
    if (rc <= 0)
        return rc;
    rc = print_oid(out, value->addressType);
    if (rc <= 0)
        return rc;
    rc = BIO_puts(out, "\n");
    if (rc <= 0)
        return rc;
    rc = BIO_printf(out, "%*sAddress Value: %.*s", indent, "",
                    value->addressValue->length, value->addressValue->data);
    if (rc <= 0)
        return rc;
    return BIO_puts(out, "\n");
}

int OSSL_PLATFORM_PROPERTY_print(BIO *out, OSSL_PLATFORM_PROPERTY *value, int indent)
{
    int rc;
    int64_t int_val;

    rc = BIO_printf(out, "%*sProperty Name: %.*s\n", indent, "",
                    value->propertyName->length, value->propertyName->data);
    if (rc <= 0)
        return rc;
    rc = BIO_printf(out, "%*sProperty Value: %.*s\n", indent, "",
                    value->propertyValue->length, value->propertyValue->data);
    if (rc <= 0)
        return rc;
    if (value->status != NULL) {
        rc = BIO_printf(out, "%*sStatus: ", indent, "");
        if (rc <= 0)
            return rc;
        if (!ASN1_ENUMERATED_get_int64(&int_val, value->status)
            || int_val < 0
            || int_val > INT_MAX)
            return -1;
        if (int_val > 2) {
            rc = BIO_printf(out, "%lld\n", (long long int)int_val);
        } else {
            rc = BIO_printf(out, "%s\n", attribute_statuses[int_val].lname);
        }
        if (rc <= 0)
            return rc;
    }
    return 1;
}

int OSSL_HASHED_CERTIFICATE_IDENTIFIER_print(BIO *out,
                                             OSSL_HASHED_CERTIFICATE_IDENTIFIER *value,
                                             int indent)
{
    int rc;

    rc = BIO_printf(out, "%*sHash Algorithm:\n%*s", indent, "", indent + 4, "");
    if (rc <= 0)
        return rc;
    rc = X509_ALGOR_print_bio(out, value->hashValue);
    if (rc <= 0)
        return rc;
    rc = BIO_printf(out, "%*sHash Over Signature Value: ", indent, "");
    if (rc <= 0)
        return rc;
    rc = ossl_bio_print_hex(out,
                            value->hashOverSignatureValue->data,
                            value->hashOverSignatureValue->length);
    if (rc <= 0)
        return rc;
    return BIO_puts(out, "\n");
}

int OSSL_PCV2_CERTIFICATE_IDENTIFIER_print(BIO *out,
                                           OSSL_PCV2_CERTIFICATE_IDENTIFIER *value,
                                           int indent)
{
    int rc;
    OSSL_ISSUER_SERIAL *iss;

    if (value->hashedCertIdentifier != NULL) {
        rc = BIO_printf(out, "%*sHashed Certificate Identifier:\n", indent, "");
        if (rc <= 0)
            return rc;
        rc = OSSL_HASHED_CERTIFICATE_IDENTIFIER_print(out,
                                                      value->hashedCertIdentifier,
                                                      indent + 4);
        if (rc <= 0)
            return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0)
            return rc;
    }
    if (value->genericCertIdentifier != NULL) {
        rc = BIO_printf(out, "%*sGeneric Certificate Identifier:\n", indent, "");
        if (rc <= 0)
            return rc;
        iss = value->genericCertIdentifier;
        if (iss->issuer != NULL) {
            rc = BIO_printf(out, "%*sIssuer Names:\n", indent + 4, "");
            if (rc <= 0)
                return rc;
            rc = OSSL_GENERAL_NAMES_print(out, iss->issuer, indent + 4);
            if (rc <= 0)
                return rc;
            rc = BIO_puts(out, "\n");
            if (rc <= 0)
                return rc;
        }
        rc = BIO_printf(out, "%*sIssuer Serial: 0x", indent + 4, "");
        if (rc <= 0)
            return rc;
        if (i2a_ASN1_INTEGER(out, &iss->serial) <= 0)
            return 0;
        rc = BIO_puts(out, "\n");
        if (rc <= 0)
            return rc;
        if (iss->issuerUID != NULL) {
            BIO_printf(out, "%*sIssuer UID: ", indent + 4, "");
            if (i2a_ASN1_STRING(out, iss->issuerUID, V_ASN1_BIT_STRING) <= 0)
                return 0;
            rc = BIO_puts(out, "\n");
            if (rc <= 0)
                return rc;
        }
    }
    return 1;
}

int OSSL_COMPONENT_IDENTIFIER_print(BIO *out, OSSL_COMPONENT_IDENTIFIER *value, int indent)
{
    int rc, i;
    int64_t int_val;
    OSSL_COMPONENT_ADDRESS *caddr;

    rc = BIO_printf(out, "%*sComponent Class:\n", indent, "");
    if (rc <= 0)
        return rc;
    rc = OSSL_COMPONENT_CLASS_print(out, value->componentClass, indent + 4);
    if (rc <= 0)
        return rc;
    rc = BIO_printf(out, "%*sComponent Manufacturer: %.*s\n", indent, "",
                    value->componentManufacturer->length,
                    value->componentManufacturer->data);
    if (rc <= 0)
        return rc;
    rc = BIO_printf(out, "%*sComponent Model: %.*s\n", indent, "",
                    value->componentModel->length,
                    value->componentModel->data);
    if (rc <= 0)
        return rc;
    if (value->componentSerial != NULL) {
        rc = BIO_printf(out, "%*sComponent Serial: %.*s\n", indent, "",
                        value->componentSerial->length,
                        value->componentSerial->data);
        if (rc <= 0)
            return rc;
    }
    if (value->componentRevision != NULL) {
        rc = BIO_printf(out, "%*sComponent Revision: %.*s\n", indent, "",
                        value->componentRevision->length,
                        value->componentRevision->data);
        if (rc <= 0)
            return rc;
    }
    if (value->componentManufacturerId != NULL) {
        rc = BIO_printf(out, "%*sComponent Manufacturer ID: ", indent, "");
        if (rc <= 0)
            return rc;
        rc = print_oid(out, value->componentManufacturerId);
        if (rc <= 0)
            return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0)
            return rc;
    }
    if (value->fieldReplaceable) {
        rc = BIO_printf(out, "%*sField Replaceable: TRUE\n", indent, "");
    } else {
        rc = BIO_printf(out, "%*sField Replaceable: TRUE\n", indent, "");
    }
    if (rc <= 0)
        return rc;
    if (value->componentAddresses != NULL) {
        rc = BIO_printf(out, "%*sComponent Addresses:\n", indent, "");
        for (i = 0; i < sk_OSSL_COMPONENT_ADDRESS_num(value->componentAddresses); i++) {
            rc = BIO_printf(out, "%*sComponent Address:\n", indent + 4, "");
            if (rc <= 0)
                return rc;
            caddr = sk_OSSL_COMPONENT_ADDRESS_value(value->componentAddresses, i);
            rc = OSSL_COMPONENT_ADDRESS_print(out, caddr, indent + 8);
            if (rc <= 0)
                return rc;
            rc = BIO_puts(out, "\n");
            if (rc <= 0)
                return rc;
        }
    }
    if (value->componentPlatformCert != NULL) {
        rc = BIO_printf(out, "%*sComponent Platform Certificate:\n", indent, "");
        if (rc <= 0)
            return rc;
        rc = OSSL_PCV2_CERTIFICATE_IDENTIFIER_print(out, value->componentPlatformCert, indent + 4);
        if (rc <= 0)
            return rc;
    }
    if (value->componentPlatformCertUri != NULL) {
        rc = BIO_printf(out, "%*sComponent Platform Certificate URI:\n", indent, "");
        if (rc <= 0)
            return rc;
        rc = OSSL_URI_REFERENCE_print(out, value->componentPlatformCertUri, indent + 4);
        if (rc <= 0)
            return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0)
            return rc;
    }
    if (value->status != NULL) {
        rc = BIO_printf(out, "%*sStatus: ", indent, "");
        if (rc <= 0)
            return rc;
        if (!ASN1_ENUMERATED_get_int64(&int_val, value->status)
            || int_val < 0
            || int_val > INT_MAX)
            return -1;
        if (int_val > 2) {
            rc = BIO_printf(out, "%lld\n", (long long int)int_val);
        } else {
            rc = BIO_printf(out, "%s\n", attribute_statuses[int_val].lname);
        }
        if (rc <= 0)
            return rc;
    }
    return 1;
}

int OSSL_PLATFORM_CONFIG_print(BIO *out, OSSL_PLATFORM_CONFIG *value, int indent)
{
    int rc = 1, i; /* All fields are OPTIONAL, so we start off rc at 1 in case all are omitted. */
    OSSL_COMPONENT_IDENTIFIER *cid;
    OSSL_PLATFORM_PROPERTY *p;

    if (value->componentIdentifiers) {
        rc = BIO_printf(out, "%*sComponent Identifiers:\n", indent, "");
        for (i = 0; i < sk_OSSL_COMPONENT_IDENTIFIER_num(value->componentIdentifiers); i++) {
            rc = BIO_printf(out, "%*sComponent Identifier:\n", indent + 4, "");
            if (rc <= 0)
                return rc;
            cid = sk_OSSL_COMPONENT_IDENTIFIER_value(value->componentIdentifiers, i);
            rc = OSSL_COMPONENT_IDENTIFIER_print(out, cid, indent + 8);
            if (rc <= 0)
                return rc;
            rc = BIO_puts(out, "\n");
            if (rc <= 0)
                return rc;
        }
    }
    if (value->componentIdentifiersUri) {
        rc = BIO_printf(out, "%*sComponent Identifier URI:\n", indent, "");
        if (rc <= 0)
            return rc;
        rc = OSSL_URI_REFERENCE_print(out, value->componentIdentifiersUri, indent + 4);
        if (rc <= 0)
            return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0)
            return rc;
    }
    if (value->platformProperties) {
        rc = BIO_printf(out, "%*sProperties:\n", indent, "");
        for (i = 0; i < sk_OSSL_PLATFORM_PROPERTY_num(value->platformProperties); i++) {
            rc = BIO_printf(out, "%*sProperty:\n", indent + 4, "");
            if (rc <= 0)
                return rc;
            p = sk_OSSL_PLATFORM_PROPERTY_value(value->platformProperties, i);
            rc = OSSL_PLATFORM_PROPERTY_print(out, p, indent + 8);
            if (rc <= 0)
                return rc;
        }
    }
    if (value->platformPropertiesUri) {
        rc = BIO_printf(out, "%*sPlatform Properties URI:\n", indent, "");
        if (rc <= 0)
            return rc;
        rc = OSSL_URI_REFERENCE_print(out, value->platformPropertiesUri, indent + 4);
        if (rc <= 0)
            return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0)
            return rc;
    }
    return 1;
}

static int print_trait(BIO *out, OSSL_PCV2_TRAIT *trait, int indent)
{
    ASN1_TYPE *value = ASN1_TYPE_new();
    unsigned char *bytes;
    int nid;

    if (BIO_printf(out, "%*sTrait ID: ", indent, "") <= 0)
        return -1;
    if (print_oid(out, trait->traitId) <= 0)
        return -1;
    if (BIO_puts(out, "\n") <= 0)
        return -1;

    if (BIO_printf(out, "%*sTrait Category: ", indent, "") <= 0)
        return -1;
    if (print_oid(out, trait->traitCategory) <= 0)
        return -1;
    if (BIO_puts(out, "\n") <= 0)
        return -1;

    if (BIO_printf(out, "%*sTrait Registry: ", indent, "") <= 0)
        return -1;
    if (print_oid(out, trait->traitRegistry) <= 0)
        return -1;
    if (BIO_puts(out, "\n") <= 0)
        return -1;

    if (trait->description != NULL) {
        if (BIO_printf(out, "%*sTrait Description: ", indent, "") <= 0)
            return -1;
        if (BIO_printf(out, "%.*s",
                       trait->description->length,
                       trait->description->data) <= 0)
            return -1;
        if (BIO_puts(out, "\n") <= 0)
            return -1;
    }

    if (trait->descriptionURI != NULL) {
        if (BIO_printf(out, "%*sTrait Description URI: ", indent, "") <= 0)
            return -1;
        if (BIO_printf(out, "%.*s",
                       trait->descriptionURI->length,
                       trait->descriptionURI->data) <= 0)
            return -1;
        if (BIO_puts(out, "\n") <= 0)
            return -1;
    }

    if (BIO_printf(out, "%*sTrait Value:\n", indent, "") <= 0)
        return -1;
    bytes = trait->traitValue->data;
    if (d2i_ASN1_TYPE(&value, (const unsigned char **)&bytes, trait->traitValue->length) == NULL)
        return -1;
    nid = OBJ_obj2nid(trait->traitId);
    if (ossl_print_attribute_value(out, nid, value, indent + 4) <= 0)
        return -1;
    return 1;
}

int print_traits(BIO *out, STACK_OF(OSSL_PCV2_TRAIT) *traits, int indent)
{
    int rc = 0;
    OSSL_PCV2_TRAIT *trait = NULL;

    for (int i = 0; i < sk_OSSL_PCV2_TRAIT_num(traits); i++) {
        trait = sk_OSSL_PCV2_TRAIT_value(traits, i);
        rc = print_trait(out, trait, indent);
        if (rc <= 0)
            return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0)
            return rc;
    }
    return rc;
}

int OSSL_PLATFORM_CONFIG_V3_print(BIO *out, OSSL_PLATFORM_CONFIG_V3 *value, int indent)
{
    int pcs, pps, numtraits;
    OSSL_COMPONENT_IDENTIFIER_V2 *pc;
    OSSL_PLATFORM_PROPERTY *pp;
    OSSL_PCV2_TRAIT *trait;

    if (value->platformComponents != NULL) {
        pcs = sk_OSSL_COMPONENT_IDENTIFIER_V2_num(value->platformComponents);
        if (BIO_printf(out, "%*sPlatform Components:\n", indent, "") <= 0)
            return -1;
        for (int i = 0; i < pcs; i++) {
            if (BIO_printf(out, "%*sPlatform Component (Traits):\n", indent + 4, "") <= 0)
                return -1;
            pc = sk_OSSL_COMPONENT_IDENTIFIER_V2_value(value->platformComponents, i);
            numtraits = sk_OSSL_PCV2_TRAIT_num(pc);
            for (int j = 0; j < numtraits; j++) {
                trait = sk_OSSL_PCV2_TRAIT_value(pc, j);
                if (print_trait(out, trait, indent + 8) <= 0)
                    return -1;
                if (BIO_puts(out, "\n") <= 0)
                    return -1;
            }
        }
    }

    if (value->platformProperties != NULL) {
        pps = sk_OSSL_PLATFORM_PROPERTY_num(value->platformProperties);
        if (BIO_printf(out, "%*sPlatform Properties:\n", indent, "") <= 0)
            return -1;
        for (int i = 0; i < pps; i++) {
            if (BIO_printf(out, "%*sPlatform Property:\n", indent + 4, "") <= 0)
                return -1;
            pp = sk_OSSL_PLATFORM_PROPERTY_value(value->platformProperties, i);
            if (OSSL_PLATFORM_PROPERTY_print(out, pp, indent + 8) <= 0)
                return -1;
        }
    }

    return 1;
}

int OSSL_ISO9000_CERTIFICATION_print(BIO *out, OSSL_ISO9000_CERTIFICATION *value, int indent)
{
    if (BIO_printf(out, "%*sISO 9000 Certified: %s\n", indent, "",
                   value->iso9000Certified ? "TRUE" : "FALSE") <= 0)
        return -1;
    if (value->iso9000Uri == NULL)
        return 1;
    return BIO_printf(out, "%*sISO 9000 Certification URI: %.*s\n", indent, "",
                      value->iso9000Uri->length,
                      value->iso9000Uri->data) > 0;
}

int OSSL_COMMON_CRITERIA_EVALUATION_print(BIO *out,
                                          OSSL_COMMON_CRITERIA_EVALUATION *value,
                                          int indent)
{
    int rc;

    if (BIO_printf(out, "%*sCommon Criteria Measures:\n", indent, "") <= 0)
        return -1;
    if (OSSL_COMMON_CRITERIA_MEASURES_print(out, value->cCMeasures, indent + 4) <= 0)
        return -1;
    rc = BIO_printf(out, "%*sCommon Criteria Cert. No.: %.*s\n", indent, "",
                    value->cCCertificateNumber->length,
                    value->cCCertificateNumber->data);
    if (rc <= 0)
        return rc;
    rc = BIO_printf(out, "%*sCommon Criteria Cert. Authority: %.*s\n", indent, "",
                    value->cCCertificateAuthority->length,
                    value->cCCertificateAuthority->data);
    if (rc <= 0)
        return rc;

    if (value->evaluationScheme != NULL) {
        rc = BIO_printf(out, "%*sEvaluation Scheme: %.*s\n", indent, "",
            value->evaluationScheme->length,
            value->evaluationScheme->data);
        if (rc <= 0)
            return rc;
    }

    if (value->cCCertificateIssuanceDate != NULL) {
        if (BIO_printf(out, "%*sCommon Criteria Cert. Issue Date: ", indent, "") <= 0)
            return -1;
        if (ASN1_GENERALIZEDTIME_print(out, value->cCCertificateIssuanceDate) != 1)
            return -1;
        if (BIO_puts(out, "\n") <= 0)
            return -1;
    }

    if (value->cCCertificateExpiryDate != NULL) {
        if (BIO_printf(out, "%*sCommon Criteria Cert. Expiry Date: ", indent, "") <= 0)
            return -1;
        if (ASN1_GENERALIZEDTIME_print(out, value->cCCertificateExpiryDate) != 1)
            return -1;
        if (BIO_puts(out, "\n") <= 0)
            return -1;
    }

    return 1;
}
