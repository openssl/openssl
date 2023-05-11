/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
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

ASN1_SEQUENCE(URI_REFERENCE) = {
    ASN1_SIMPLE(URI_REFERENCE, uniformResourceIdentifier, ASN1_IA5STRING),
    ASN1_OPT(URI_REFERENCE, hashAlgorithm, X509_ALGOR),
    ASN1_OPT(URI_REFERENCE, hashValue, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(URI_REFERENCE)

IMPLEMENT_ASN1_FUNCTIONS(URI_REFERENCE)

ASN1_SEQUENCE(COMMON_CRITERIA_MEASURES) = {
    ASN1_SIMPLE(COMMON_CRITERIA_MEASURES, version, ASN1_IA5STRING),
    ASN1_SIMPLE(COMMON_CRITERIA_MEASURES, assurancelevel, ASN1_ENUMERATED),
    ASN1_SIMPLE(COMMON_CRITERIA_MEASURES, evaluationStatus, ASN1_ENUMERATED),
    ASN1_OPT(COMMON_CRITERIA_MEASURES, plus, ASN1_FBOOLEAN),
    ASN1_IMP_OPT(COMMON_CRITERIA_MEASURES, strengthOfFunction, ASN1_ENUMERATED, 0),
    ASN1_IMP_OPT(COMMON_CRITERIA_MEASURES, profileOid, ASN1_OBJECT, 1),
    ASN1_IMP_OPT(COMMON_CRITERIA_MEASURES, profileUri, URI_REFERENCE, 2),
    ASN1_IMP_OPT(COMMON_CRITERIA_MEASURES, targetOid, ASN1_OBJECT, 3),
    ASN1_IMP_OPT(COMMON_CRITERIA_MEASURES, targetUri, URI_REFERENCE, 4),
} ASN1_SEQUENCE_END(COMMON_CRITERIA_MEASURES)

IMPLEMENT_ASN1_FUNCTIONS(COMMON_CRITERIA_MEASURES)

ASN1_SEQUENCE(FIPS_LEVEL) = {
    ASN1_SIMPLE(FIPS_LEVEL, version, ASN1_IA5STRING),
    ASN1_SIMPLE(FIPS_LEVEL, level, ASN1_ENUMERATED),
    ASN1_OPT(FIPS_LEVEL, plus, ASN1_FBOOLEAN)
} ASN1_SEQUENCE_END(FIPS_LEVEL)

IMPLEMENT_ASN1_FUNCTIONS(FIPS_LEVEL)

ASN1_SEQUENCE(TBB_SECURITY_ASSERTIONS) = {
    ASN1_OPT(TBB_SECURITY_ASSERTIONS, version, ASN1_INTEGER),
    ASN1_IMP_OPT(TBB_SECURITY_ASSERTIONS, ccInfo, COMMON_CRITERIA_MEASURES, 0),
    ASN1_IMP_OPT(TBB_SECURITY_ASSERTIONS, fipsLevel, FIPS_LEVEL, 1),
    ASN1_IMP_OPT(TBB_SECURITY_ASSERTIONS, rtmType, ASN1_ENUMERATED, 2),
    ASN1_OPT(TBB_SECURITY_ASSERTIONS, iso9000Certified, ASN1_FBOOLEAN),
    ASN1_OPT(TBB_SECURITY_ASSERTIONS, iso9000Uri, ASN1_IA5STRING),
} ASN1_SEQUENCE_END(TBB_SECURITY_ASSERTIONS)

IMPLEMENT_ASN1_FUNCTIONS(TBB_SECURITY_ASSERTIONS)

ASN1_SEQUENCE(MANUFACTURER_ID) = {
    ASN1_SIMPLE(MANUFACTURER_ID, manufacturerIdentifier, ASN1_OBJECT)
} ASN1_SEQUENCE_END(MANUFACTURER_ID)

IMPLEMENT_ASN1_FUNCTIONS(MANUFACTURER_ID)

ASN1_SEQUENCE(TCG_SPEC_VERSION) = {
    ASN1_SIMPLE(TCG_SPEC_VERSION, majorVersion, ASN1_INTEGER),
    ASN1_SIMPLE(TCG_SPEC_VERSION, minorVersion, ASN1_INTEGER),
    ASN1_SIMPLE(TCG_SPEC_VERSION, revision, ASN1_INTEGER)
} ASN1_SEQUENCE_END(TCG_SPEC_VERSION)

IMPLEMENT_ASN1_ALLOC_FUNCTIONS(TCG_SPEC_VERSION)

ASN1_SEQUENCE(TCG_PLATFORM_SPEC) = {
    ASN1_SIMPLE(TCG_PLATFORM_SPEC, version, TCG_SPEC_VERSION),
    ASN1_SIMPLE(TCG_PLATFORM_SPEC, platformClass, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TCG_PLATFORM_SPEC)

IMPLEMENT_ASN1_FUNCTIONS(TCG_PLATFORM_SPEC)

ASN1_SEQUENCE(TCG_CRED_TYPE) = {
    ASN1_SIMPLE(TCG_CRED_TYPE, certificateType, ASN1_OBJECT)
} ASN1_SEQUENCE_END(TCG_CRED_TYPE)

IMPLEMENT_ASN1_FUNCTIONS(TCG_CRED_TYPE)

ASN1_SEQUENCE(COMPONENT_ADDRESS) = {
    ASN1_SIMPLE(COMPONENT_ADDRESS, addressType, ASN1_OBJECT),
    ASN1_SIMPLE(COMPONENT_ADDRESS, addressValue, ASN1_UTF8STRING)
} ASN1_SEQUENCE_END(COMPONENT_ADDRESS)

IMPLEMENT_ASN1_FUNCTIONS(COMPONENT_ADDRESS)

ASN1_SEQUENCE(PLATFORM_PROPERTY) = {
    ASN1_SIMPLE(PLATFORM_PROPERTY, propertyName, ASN1_UTF8STRING),
    ASN1_SIMPLE(PLATFORM_PROPERTY, propertyValue, ASN1_UTF8STRING),
    ASN1_IMP_OPT(PLATFORM_PROPERTY, status, ASN1_ENUMERATED, 0)
} ASN1_SEQUENCE_END(PLATFORM_PROPERTY)

IMPLEMENT_ASN1_FUNCTIONS(PLATFORM_PROPERTY)

ASN1_SEQUENCE(ATTRIBUTE_CERTIFICATE_IDENTIFIER) = {
    ASN1_SIMPLE(ATTRIBUTE_CERTIFICATE_IDENTIFIER, hashAlgorithm, X509_ALGOR),
    ASN1_SIMPLE(ATTRIBUTE_CERTIFICATE_IDENTIFIER, hashOverSignatureValue, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(ATTRIBUTE_CERTIFICATE_IDENTIFIER)

ASN1_SEQUENCE(CERTIFICATE_IDENTIFIER) = {
    ASN1_IMP_OPT(CERTIFICATE_IDENTIFIER, attributeCertIdentifier, ATTRIBUTE_CERTIFICATE_IDENTIFIER, 0),
    ASN1_IMP_OPT(CERTIFICATE_IDENTIFIER, genericCertIdentifier, ISSUER_SERIAL, 1)
} ASN1_SEQUENCE_END(CERTIFICATE_IDENTIFIER)

ASN1_SEQUENCE(COMPONENT_CLASS) = {
    ASN1_SIMPLE(COMPONENT_CLASS, componentClassRegistry, ASN1_OBJECT),
    ASN1_SIMPLE(COMPONENT_CLASS, componentClassValue, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(COMPONENT_CLASS)

IMPLEMENT_ASN1_ALLOC_FUNCTIONS(COMPONENT_CLASS)

ASN1_SEQUENCE(COMPONENT_IDENTIFIER) = {
    ASN1_SIMPLE(COMPONENT_IDENTIFIER, componentClass, COMPONENT_CLASS),
    ASN1_SIMPLE(COMPONENT_IDENTIFIER, componentManufacturer, ASN1_UTF8STRING),
    ASN1_SIMPLE(COMPONENT_IDENTIFIER, componentModel, ASN1_UTF8STRING),
    ASN1_IMP_OPT(COMPONENT_IDENTIFIER, componentSerial, ASN1_UTF8STRING, 0),
    ASN1_IMP_OPT(COMPONENT_IDENTIFIER, componentRevision, ASN1_UTF8STRING, 1),
    ASN1_IMP_OPT(COMPONENT_IDENTIFIER, componentManufacturerId, ASN1_OBJECT, 2),
    ASN1_IMP_OPT(COMPONENT_IDENTIFIER, fieldReplaceable, ASN1_BOOLEAN, 3),
    ASN1_IMP_SEQUENCE_OF_OPT(COMPONENT_IDENTIFIER, componentAddresses, COMPONENT_ADDRESS, 4),
    ASN1_IMP_OPT(COMPONENT_IDENTIFIER, componentPlatformCert, CERTIFICATE_IDENTIFIER, 5),
    ASN1_IMP_OPT(COMPONENT_IDENTIFIER, componentPlatformCertUri, URI_REFERENCE, 6),
    ASN1_IMP_OPT(COMPONENT_IDENTIFIER, status, ASN1_ENUMERATED, 7)
} ASN1_SEQUENCE_END(COMPONENT_IDENTIFIER)

IMPLEMENT_ASN1_FUNCTIONS(COMPONENT_IDENTIFIER)

ASN1_SEQUENCE(PLATFORM_CONFIG) = {
    ASN1_IMP_SEQUENCE_OF_OPT(PLATFORM_CONFIG, componentIdentifiers, COMPONENT_IDENTIFIER, 0),
    ASN1_IMP_OPT(PLATFORM_CONFIG, componentIdentifiersUri, URI_REFERENCE, 1),
    ASN1_IMP_SEQUENCE_OF_OPT(PLATFORM_CONFIG, platformProperties, PLATFORM_PROPERTY, 2),
    ASN1_IMP_OPT(PLATFORM_CONFIG, platformPropertiesUri, URI_REFERENCE, 3)
} ASN1_SEQUENCE_END(PLATFORM_CONFIG)

IMPLEMENT_ASN1_FUNCTIONS(PLATFORM_CONFIG)

static int print_hex(BIO *out, unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        if (BIO_printf(out, "%02X ", buf[i]) <= 0) {
            return 0;
        }
    }
    return 1;
}

int URI_REFERENCE_print (BIO *out, URI_REFERENCE *value, int indent) {
    int rc;
    
    rc = BIO_printf(out, "%*sURI: %.*s\n", indent, "",
        value->uniformResourceIdentifier->length,
        value->uniformResourceIdentifier->data);
    if (rc <= 0) return rc;
    if (value->hashAlgorithm != NULL) {
        rc = BIO_printf(out, "%*sHash Algorithm:\n%*s", indent, "", indent + 4, "");
        if (rc <= 0) return rc;
        rc = TS_X509_ALGOR_print_bio(out, value->hashAlgorithm);
        if (rc <= 0) return rc;
    }
    if (value->hashValue != NULL) {
        rc = BIO_printf(out, "%*sHash Value: ", indent, "");
        if (rc <= 0) return rc;
        rc = print_hex(out, value->hashValue->data, value->hashValue->length);
        if (rc <= 0) return rc;
    }
    return rc;
}

static ENUMERATED_NAMES measurement_root_types[] = {
    {MEASUREMENT_ROOT_TYPE_STATIC, "Static (0)", "static"},
    {MEASUREMENT_ROOT_TYPE_DYNAMIC, "Dynamic (1)", "dynamic"},
    {MEASUREMENT_ROOT_TYPE_NONHOST, "Non-Host (2)", "nonHost"},
    {MEASUREMENT_ROOT_TYPE_HYBRID, "Hybrid (3)", "hybrid"},
    {MEASUREMENT_ROOT_TYPE_PHYSICAL, "Physical (4)", "physical"},
    {MEASUREMENT_ROOT_TYPE_VIRTUAL, "Virtual (5)", "virtual"},
    {-1, NULL, NULL},
};

static ENUMERATED_NAMES evaluation_assurance_levels[] = {
    {EVALUATION_ASSURANCE_LEVEL_1, "Level 1", "level1"},
    {EVALUATION_ASSURANCE_LEVEL_2, "Level 2", "level2"},
    {EVALUATION_ASSURANCE_LEVEL_3, "Level 3", "level3"},
    {EVALUATION_ASSURANCE_LEVEL_4, "Level 4", "level4"},
    {EVALUATION_ASSURANCE_LEVEL_5, "Level 5", "level5"},
    {EVALUATION_ASSURANCE_LEVEL_6, "Level 6", "level6"},
    {EVALUATION_ASSURANCE_LEVEL_7, "Level 7", "level7"},
    {-1, NULL, NULL},
};

static ENUMERATED_NAMES evaluation_statuses[] = {
    {EVALUATION_STATUS_DESIGNED_TO_MEET, "Designed To Meet (0)", "designedToMeet"},
    {EVALUATION_STATUS_EVAL_IN_PROGRESS, "Evaluation In Progress (1)", "evaluationInProgress"},
    {EVALUATION_STATUS_EVAL_COMPLETED, "Evaluation Completed (2)", "evaluationCompleted"},
    {-1, NULL, NULL},
};

static ENUMERATED_NAMES strengths_of_function[] = {
    {STRENGTH_OF_FUNCTION_BASIC, "Basic (0)", "basic"},
    {STRENGTH_OF_FUNCTION_MEDIUM, "Medium (1)", "medium"},
    {STRENGTH_OF_FUNCTION_HIGH, "High (2)", "high"},
    {-1, NULL, NULL},
};

static ENUMERATED_NAMES security_levels[] = {
    {SECURITY_LEVEL_1, "Level 1", "level1"},
    {SECURITY_LEVEL_2, "Level 2", "level2"},
    {SECURITY_LEVEL_3, "Level 3", "level3"},
    {SECURITY_LEVEL_4, "Level 4", "level4"},
    {-1, NULL, NULL},
};

static ENUMERATED_NAMES attribute_statuses[] = {
    {ATTRIBUTE_STATUS_ADDED, "Added (0)", "added"},
    {ATTRIBUTE_STATUS_MODIFIED, "Modified (1)", "modified"},
    {ATTRIBUTE_STATUS_REMOVED, "Removed (2)", "removed"},
    {-1, NULL, NULL},
};

int COMPONENT_CLASS_print (BIO *out, COMPONENT_CLASS *value, int indent) {
    int rc;
    
    rc = BIO_printf(out, "%*sComponent Class Registry: ", indent, "");
    if (rc <= 0) return rc;
    rc = print_oid(out, value->componentClassRegistry);
    if (rc <= 0) return rc;
    rc = BIO_puts(out, "\n");
    if (rc <= 0) return rc;
    rc = BIO_printf(out, "%*sComponent Class Registry: ", indent, "");
    if (rc <= 0) return rc;
    rc = print_hex(out, value->componentClassValue->data, value->componentClassValue->length);
    if (rc <= 0) return rc;
    return BIO_puts(out, "\n");
}

int COMMON_CRITERIA_MEASURES_print (BIO *out,
                                    COMMON_CRITERIA_MEASURES *value,
                                    int indent) {
    int rc;
    int64_t int_val;

    rc = BIO_printf(out, "%*sVersion: %.*s\n", indent, "",
                    value->version->length,
                    value->version->data);
    if (rc <= 0) return rc;
    rc = BIO_printf(out, "%*sAssurance Level: ", indent, "");
    if (rc <= 0) return rc;
    if (!ASN1_ENUMERATED_get_int64(&int_val, value->assurancelevel)
        || int_val <= 0
        || int_val > INT_MAX)
        return -1;
    if (int_val > 7) {
        rc = BIO_printf(out, "%ld\n", int_val);
    } else {
        rc = BIO_printf(out, "%s\n", evaluation_assurance_levels[int_val - 1].lname);
    }
    if (rc <= 0) return rc;
    if (!ASN1_ENUMERATED_get_int64(&int_val, value->evaluationStatus)
        || int_val < 0
        || int_val > INT_MAX)
        return -1;
    if (int_val > 2) {
        rc = BIO_printf(out, "%*sEvaluation Status: %ld\n", indent, "", int_val);
    } else {
        rc = BIO_printf(out, "%*sEvaluation Status: %s\n", indent, "", evaluation_statuses[int_val].lname);
    }
    if (rc <= 0) return rc;
    rc = BIO_printf(out, "%*sPlus: ", indent, "");
    if (rc <= 0) return rc;
    if (value->plus) {
        rc = BIO_puts(out, "TRUE\n");
    } else {
        rc = BIO_puts(out, "FALSE\n");
    }
    if (rc <= 0) return rc;
    if (value->strengthOfFunction != NULL) {
        rc = BIO_printf(out, "%*sStrength Of Function: ", indent, "");
        if (rc <= 0) return rc;
        if (!ASN1_ENUMERATED_get_int64(&int_val, value->strengthOfFunction)
            || int_val < 0
            || int_val > INT_MAX)
            return -1;
        if (int_val > 2) {
            rc = BIO_printf(out, "%ld\n", int_val);
        } else {
            rc = BIO_printf(out, "%s\n", strengths_of_function[int_val].lname);
        }
        if (rc <= 0) return rc;
    }
    if (value->profileOid != NULL) {
        rc = BIO_printf(out, "%*sProfile OID: ", indent, "");
        if (rc <= 0) return rc;
        rc = print_oid(out, value->profileOid);
        if (rc <= 0) return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0) return rc;
    }
    if (value->profileUri != NULL) {
        rc = BIO_printf(out, "%*sProfile URI:\n", indent, "");
        if (rc <= 0) return rc;
        rc = URI_REFERENCE_print(out, value->profileUri, indent + 4);
        if (rc <= 0) return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0) return rc;
    }
    if (value->targetOid != NULL) {
        rc = BIO_printf(out, "%*sTarget OID: ", indent, "");
        if (rc <= 0) return rc;
        rc = print_oid(out, value->targetOid);
        if (rc <= 0) return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0) return rc;
    }
    if (value->targetUri != NULL) {
        rc = BIO_printf(out, "%*sTarget URI:\n", indent, "");
        if (rc <= 0) return rc;
        rc = URI_REFERENCE_print(out, value->targetUri, indent + 4);
        if (rc <= 0) return rc;
    }
    return rc;
}

int FIPS_LEVEL_print (BIO *out, FIPS_LEVEL *value, int indent) {
    int rc;
    int64_t int_val;

    rc = BIO_printf(out, "%*sVersion: %.*s\n", indent, "",
                    value->version->length,
                    value->version->data);
    if (rc <= 0) return rc;
    if (value->level != NULL) {
        rc = BIO_printf(out, "%*sLevel: ", indent, "");
        if (rc <= 0) return rc;
        if (!ASN1_ENUMERATED_get_int64(&int_val, value->level)
            || int_val <= 0
            || int_val > INT_MAX)
            return -1;
        if (int_val > 4) {
            rc = BIO_printf(out, "%ld\n", int_val);
        } else {
            rc = BIO_printf(out, "%s\n", security_levels[int_val - 1].lname);
        }
        if (rc <= 0) return rc;
    }
    if (value->plus) {
        rc = BIO_printf(out, "%*sPlus: TRUE\n", indent, "");
    } else {
        rc = BIO_printf(out, "%*sPlus: FALSE\n", indent, "");
    }
    return rc;
}

int TBB_SECURITY_ASSERTIONS_print (BIO *out, TBB_SECURITY_ASSERTIONS *value, int indent) {
    int rc = 1; /* All fields are OPTIONAL, so we start off at 1 in case all are omitted. */
    int64_t int_val;

    if (value->version != NULL) {
        if (!ASN1_INTEGER_get_int64(&int_val, value->version)
            || int_val < 0
            || int_val > INT_MAX)
            return -1;
        rc = BIO_printf(out, "%*sVersion: %ld\n", indent, "", int_val);
    } else {
        rc = BIO_printf(out, "%*sVersion: 1\n", indent, "");
    }
    if (rc <= 0) return rc;
    if (value->ccInfo != NULL) {
        rc = BIO_printf(out, "%*sCommon Criteria Measures:\n", indent, "");
        if (rc <= 0) return rc;
        rc = COMMON_CRITERIA_MEASURES_print(out, value->ccInfo, indent + 4);
        if (rc <= 0) return rc;
    }
    if (value->fipsLevel != NULL) {
        rc = BIO_printf(out, "%*sFIPS Level:\n", indent, "");
        if (rc <= 0) return rc;
        rc = FIPS_LEVEL_print(out, value->fipsLevel, indent + 4);
        if (rc <= 0) return rc;
    }
    if (value->rtmType != NULL) {
        rc = BIO_printf(out, "%*sRoot Measurement Type: ", indent, "");
        if (rc <= 0) return rc;
        if (!ASN1_ENUMERATED_get_int64(&int_val, value->rtmType)
            || int_val < 0
            || int_val > INT_MAX)
            return -1;
        if (int_val > 5) {
            rc = BIO_printf(out, "%ld\n", int_val);
        } else {
            rc = BIO_printf(out, "%s\n", measurement_root_types[int_val].lname);
        }
        if (rc <= 0) return rc;
    }
    if (value->iso9000Certified) {
        rc = BIO_printf(out, "%*sPlus: TRUE\n", indent, "");
    } else {
        rc = BIO_printf(out, "%*sPlus: FALSE\n", indent, "");
    }
    if (rc <= 0) return rc;
    if (value->iso9000Uri) {
        rc = BIO_printf(out, "%*sISO 9001 URI: %.*s",
                        indent,
                        "",
                        value->iso9000Uri->length,
                        value->iso9000Uri->data);
    }
    return rc;
}

int MANUFACTURER_ID_print (BIO *out, MANUFACTURER_ID *value, int indent) {
    int rc;

    rc = BIO_printf(out, "%*sManufacturer Identifier: ", indent, "");
    if (rc <= 0) return rc;
    return print_oid(out, value->manufacturerIdentifier);
}

int TCG_SPEC_VERSION_print (BIO *out, TCG_SPEC_VERSION *value) {
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
    return BIO_printf(out, "%ld.%ld.%ld", major, minor, rev);
}

int TCG_PLATFORM_SPEC_print (BIO *out, TCG_PLATFORM_SPEC *value) {
    int rc;

    rc = TCG_SPEC_VERSION_print(out, value->version);
    if (rc <= 0) return rc;
    rc = BIO_puts(out, " : ");
    if (rc <= 0) return rc;
    return print_hex(out, value->platformClass->data, value->platformClass->length);
}

int TCG_CRED_TYPE_print (BIO *out, TCG_CRED_TYPE *value, int indent) {
    int rc;
    rc = BIO_printf(out, "%*sCredential Type: ", indent, "");
    if (rc <= 0) return rc;
    return print_oid(out, value->certificateType);
}

int COMPONENT_ADDRESS_print (BIO *out, COMPONENT_ADDRESS *value, int indent) {
    int rc;

    rc = BIO_printf(out, "%*sAddress Type: ", indent, "");
    if (rc <= 0) return rc;
    rc = print_oid(out, value->addressType);
    if (rc <= 0) return rc;
    rc = BIO_puts(out, "\n");
    if (rc <= 0) return rc;
    rc = BIO_printf(out, "%*sAddress Value: %.*s", indent, "", value->addressValue->length, value->addressValue->data);
    if (rc <= 0) return rc;
    return BIO_puts(out, "\n");
}

int PLATFORM_PROPERTY_print (BIO *out, PLATFORM_PROPERTY *value, int indent) {
    int rc;
    int64_t int_val;

    rc = BIO_printf(out, "%*sProperty Name: %.*s\n", indent, "", value->propertyName->length, value->propertyName->data);
    if (rc <= 0) return rc;
    rc = BIO_printf(out, "%*sProperty Value: %.*s\n", indent, "", value->propertyValue->length, value->propertyValue->data);
    if (rc <= 0) return rc;
    if (value->status != NULL) {
        rc = BIO_printf(out, "%*sStatus: ", indent, "");
        if (rc <= 0) return rc;
        if (!ASN1_ENUMERATED_get_int64(&int_val, value->status)
            || int_val < 0
            || int_val > INT_MAX)
            return -1;
        if (int_val > 2) {
            rc = BIO_printf(out, "%ld\n", int_val);
        } else {
            rc = BIO_printf(out, "%s\n", attribute_statuses[int_val].lname);
        }
        if (rc <= 0) return rc;
    }
    return 1;
}

int ATTRIBUTE_CERTIFICATE_IDENTIFIER_print (BIO *out, ATTRIBUTE_CERTIFICATE_IDENTIFIER *value, int indent) {
    int rc;

    rc = BIO_printf(out, "%*sHash Algorithm:\n%*s", indent, "", indent + 4, "");
    if (rc <= 0) return rc;
    rc = TS_X509_ALGOR_print_bio(out, value->hashAlgorithm);
    if (rc <= 0) return rc;
    rc = BIO_printf(out, "%*sHash Over Signature Value: ", indent, "");
    if (rc <= 0) return rc;
    rc = print_hex(out, value->hashOverSignatureValue->data, value->hashOverSignatureValue->length);
    if (rc <= 0) return rc;
    return BIO_puts(out, "\n");
}

int CERTIFICATE_IDENTIFIER_print (BIO *out, CERTIFICATE_IDENTIFIER *value, int indent) {
    int rc;
    ISSUER_SERIAL *iss;

    if (value->attributeCertIdentifier != NULL) {
        rc = BIO_printf(out, "%*sAttribute Certificate Identifier:\n", indent, "");
        if (rc <= 0) return rc;
        rc = ATTRIBUTE_CERTIFICATE_IDENTIFIER_print(out, value->attributeCertIdentifier, indent + 4);
        if (rc <= 0) return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0) return rc;
    }
    if (value->genericCertIdentifier != NULL) {
        rc = BIO_printf(out, "%*sGeneric Certificate Identifier:\n", indent, "");
        if (rc <= 0) return rc;
        iss = value->genericCertIdentifier;
        if (iss->issuer != NULL) {
            rc = BIO_printf(out, "%*sIssuer Names:\n", indent + 4, "");
            if (rc <= 0) return rc;
            rc = ossl_print_gens(out, iss->issuer, indent + 4);
            if (rc <= 0) return rc;
            rc = BIO_puts(out, "\n");
            if (rc <= 0) return rc;
        }
        if (iss->serial != NULL) {
            rc = BIO_printf(out, "%*sIssuer Serial: 0x", indent + 4, "");
            if (rc <= 0) return rc;
            if (i2a_ASN1_INTEGER(out, iss->serial) <= 0)
                return 0;
            rc = BIO_puts(out, "\n");
            if (rc <= 0) return rc;
        }
        if (iss->issuerUID != NULL) {
            BIO_printf(out, "%*sIssuer UID: ", indent + 4, "");
            if (i2a_ASN1_STRING(out, iss->issuerUID, V_ASN1_BIT_STRING) <= 0)
                return 0;
            rc = BIO_puts(out, "\n");
            if (rc <= 0) return rc;
        }
    }
    return 1;
}

int COMPONENT_IDENTIFIER_print (BIO *out, COMPONENT_IDENTIFIER *value, int indent) {
    int rc, i;
    int64_t int_val;
    COMPONENT_ADDRESS *caddr;

    rc = BIO_printf(out, "%*sComponent Class:\n", indent, "");
    if (rc <= 0) return rc;
    rc = COMPONENT_CLASS_print(out, value->componentClass, indent + 4);
    if (rc <= 0) return rc;
    rc = BIO_printf(out, "%*sComponent Manufacturer: %.*s\n", indent, "",
                    value->componentManufacturer->length,
                    value->componentManufacturer->data);
    if (rc <= 0) return rc;
    rc = BIO_printf(out, "%*sComponent Model: %.*s\n", indent, "",
                    value->componentModel->length,
                    value->componentModel->data);
    if (rc <= 0) return rc;
    if (value->componentSerial != NULL) {
        rc = BIO_printf(out, "%*sComponent Serial: %.*s\n", indent, "",
                        value->componentSerial->length,
                        value->componentSerial->data);
        if (rc <= 0) return rc;
    }
    if (value->componentRevision != NULL) {
        rc = BIO_printf(out, "%*sComponent Revision: %.*s\n", indent, "",
                        value->componentRevision->length,
                        value->componentRevision->data);
        if (rc <= 0) return rc;
    }
    if (value->componentManufacturerId != NULL) {
        rc = BIO_printf(out, "%*sComponent Manufacturer ID: ", indent, "");
        if (rc <= 0) return rc;
        rc = print_oid(out, value->componentManufacturerId);
        if (rc <= 0) return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0) return rc;
    }
    if (value->fieldReplaceable) {
        rc = BIO_printf(out, "%*sField Replaceable: TRUE\n", indent, "");
    } else {
        rc = BIO_printf(out, "%*sField Replaceable: TRUE\n", indent, "");
    }
    if (rc <= 0) return rc;
    if (value->componentAddresses != NULL) {
        rc = BIO_printf(out, "%*sComponent Addresses:\n", indent, "");
        for (i = 0; i < sk_COMPONENT_ADDRESS_num(value->componentAddresses); i++) {
            rc = BIO_printf(out, "%*sComponent Address:\n", indent + 4, "");
            if (rc <= 0) return rc;
            caddr = sk_COMPONENT_ADDRESS_value(value->componentAddresses, i);
            rc = COMPONENT_ADDRESS_print(out, caddr, indent + 8);
            if (rc <= 0) return rc;
            rc = BIO_puts(out, "\n");
            if (rc <= 0) return rc;
        }
    }
    if (value->componentPlatformCert != NULL) {
        rc = BIO_printf(out, "%*sComponent Platform Certificate:\n", indent, "");
        if (rc <= 0) return rc;
        rc = CERTIFICATE_IDENTIFIER_print(out, value->componentPlatformCert, indent + 4);
        if (rc <= 0) return rc;
    }
    if (value->componentPlatformCertUri != NULL) {
        rc = BIO_printf(out, "%*sComponent Platform Certificate URI:\n", indent, "");
        if (rc <= 0) return rc;
        rc = URI_REFERENCE_print(out, value->componentPlatformCertUri, indent + 4);
        if (rc <= 0) return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0) return rc;
    }
    if (value->status != NULL) {
        rc = BIO_printf(out, "%*sStatus: ", indent, "");
        if (rc <= 0) return rc;
        if (!ASN1_ENUMERATED_get_int64(&int_val, value->status)
            || int_val < 0
            || int_val > INT_MAX)
            return -1;
        if (int_val > 2) {
            rc = BIO_printf(out, "%ld\n", int_val);
        } else {
            rc = BIO_printf(out, "%s\n", attribute_statuses[int_val].lname);
        }
        if (rc <= 0) return rc;
    }
    return 1;
}

int PLATFORM_CONFIG_print (BIO *out, PLATFORM_CONFIG *value, int indent) {
    int rc = 1, i; /* All fields are OPTIONAL, so we start off rc at 1 in case all are omitted. */
    COMPONENT_IDENTIFIER *cid;
    PLATFORM_PROPERTY *p;

    if (value->componentIdentifiers) {
        rc = BIO_printf(out, "%*sComponent Identifiers:\n", indent, "");
        for (i = 0; i < sk_COMPONENT_IDENTIFIER_num(value->componentIdentifiers); i++) {
            rc = BIO_printf(out, "%*sComponent Identifier:\n", indent + 4, "");
            if (rc <= 0) return rc;
            cid = sk_COMPONENT_IDENTIFIER_value(value->componentIdentifiers, i);
            rc = COMPONENT_IDENTIFIER_print(out, cid, indent + 8);
            if (rc <= 0) return rc;
            rc = BIO_puts(out, "\n");
            if (rc <= 0) return rc;
        }
    }
    if (value->componentIdentifiersUri) {
        rc = BIO_printf(out, "%*sComponent Identifier URI:\n", indent, "");
        if (rc <= 0) return rc;
        rc = URI_REFERENCE_print(out, value->componentIdentifiersUri, indent + 4);
        if (rc <= 0) return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0) return rc;
    }
    if (value->platformProperties) {
        rc = BIO_printf(out, "%*sProperties:\n", indent, "");
        for (i = 0; i < sk_PLATFORM_PROPERTY_num(value->platformProperties); i++) {
            rc = BIO_printf(out, "%*sProperty:\n", indent + 4, "");
            if (rc <= 0) return rc;
            p = sk_PLATFORM_PROPERTY_value(value->platformProperties, i);
            rc = PLATFORM_PROPERTY_print(out, p, indent + 8);
            if (rc <= 0) return rc;
        }
    }
    if (value->platformPropertiesUri) {
        rc = BIO_printf(out, "%*sPlatform Properties URI:\n", indent, "");
        if (rc <= 0) return rc;
        rc = URI_REFERENCE_print(out, value->platformPropertiesUri, indent + 4);
        if (rc <= 0) return rc;
        rc = BIO_puts(out, "\n");
        if (rc <= 0) return rc;
    }
    return 1;
}
