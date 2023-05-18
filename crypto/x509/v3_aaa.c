/*
 * Copyright 1999-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/asn1t.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>

IMPLEMENT_ASN1_FUNCTIONS(ALLOWED_ATTRIBUTES_SYNTAX)

ASN1_CHOICE(ALLOWED_ATTRIBUTES_CHOICE) = {
    ASN1_IMP(ALLOWED_ATTRIBUTES_CHOICE, choice.attributeType, ASN1_OBJECT, AAA_ATTRIBUTE_TYPE),
    ASN1_IMP(ALLOWED_ATTRIBUTES_CHOICE, choice.attributeTypeandValues, X509_ATTRIBUTE, AAA_ATTRIBUTE_VALUES),
} ASN1_CHOICE_END(ALLOWED_ATTRIBUTES_CHOICE)

ASN1_SEQUENCE(ALLOWED_ATTRIBUTES_ITEM) = {
    ASN1_IMP_SET_OF(ALLOWED_ATTRIBUTES_ITEM, attributes, ALLOWED_ATTRIBUTES_CHOICE, 0),
    // This MUST be EXPLICIT, because it contains a CHOICE.
    ASN1_EXP(ALLOWED_ATTRIBUTES_ITEM, holderDomain, GENERAL_NAME, 1),
} ASN1_SEQUENCE_END(ALLOWED_ATTRIBUTES_ITEM)

ASN1_ITEM_TEMPLATE(ALLOWED_ATTRIBUTES_SYNTAX) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SET_OF, 0, ALLOWED_ATTRIBUTES_SYNTAX, ALLOWED_ATTRIBUTES_ITEM)
ASN1_ITEM_TEMPLATE_END(ALLOWED_ATTRIBUTES_SYNTAX)

static int i2r_ALLOWED_ATTRIBUTES_CHOICE(X509V3_EXT_METHOD *method,
                                       ALLOWED_ATTRIBUTES_CHOICE *a,
                                       BIO *out, int indent)
{
    ASN1_OBJECT *attr_obj;
    int attr_nid, j;
    X509_ATTRIBUTE *attr;
    ASN1_TYPE *av;

    switch (a->type) {
    case (AAA_ATTRIBUTE_TYPE):
        if (BIO_printf(out, "%*sAttribute Type: ", indent, "") <= 0) {
            return 0;
        }
        if (i2a_ASN1_OBJECT(out, a->choice.attributeType) <= 0) {
            return 0;
        }
        return BIO_puts(out, "\n");
    case (AAA_ATTRIBUTE_VALUES):
        attr = a->choice.attributeTypeandValues;
        attr_obj = X509_ATTRIBUTE_get0_object(attr);
        attr_nid = OBJ_obj2nid(attr_obj);
        if (BIO_printf(out, "%*sAttribute Values: ", indent, "") <= 0) {
            return 0;
        }
        if (i2a_ASN1_OBJECT(out, attr_obj) <= 0) {
            return 0;
        }
        if (BIO_puts(out, "\n") <= 0) {
            return 0;
        }
        for (j = 0; j < X509_ATTRIBUTE_count(attr); j++)
        {
            av = X509_ATTRIBUTE_get0_type(attr, j);
            if (print_attribute_value(out, attr_nid, av, indent + 4) <= 0) {
                return 0;
            }
            if (BIO_puts(out, "\n") <= 0) {
                return 0;
            }
        }
        // BIO_puts(out, "\n");
        break;
    default: return 0;
    }
    return 1;
}

static int i2r_ALLOWED_ATTRIBUTES_ITEM(X509V3_EXT_METHOD *method,
                                       ALLOWED_ATTRIBUTES_ITEM *aai,
                                       BIO *out, int indent)
{
    int i;
    ALLOWED_ATTRIBUTES_CHOICE *a;
    for (i = 0; i < sk_ALLOWED_ATTRIBUTES_CHOICE_num(aai->attributes); i++) {
        if (BIO_printf(out, "%*sAllowed Attribute Type or Values:\n", indent, "") <= 0) {
            return 0;
        }
        a = sk_ALLOWED_ATTRIBUTES_CHOICE_value(aai->attributes, i);
        if (i2r_ALLOWED_ATTRIBUTES_CHOICE(method, a, out, indent + 4) <= 0) {
            return 0;
        }
    }
    if (BIO_printf(out, "%*sHolder Domain: ", indent, "") <= 0) {
        return 0;
    }
    if (GENERAL_NAME_print(out, aai->holderDomain) <= 0) {
        return 0;
    }
    if (BIO_puts(out, "\n") <= 0) {
        return 0;
    }
    return 1;
}

static int i2r_ALLOWED_ATTRIBUTES_SYNTAX(X509V3_EXT_METHOD *method,
                                         ALLOWED_ATTRIBUTES_SYNTAX *aaa,
                                         BIO *out, int indent)
{
    int i;
    ALLOWED_ATTRIBUTES_ITEM *aai;
    for (i = 0; i < sk_ALLOWED_ATTRIBUTES_ITEM_num(aaa); i++) {
        if (BIO_printf(out, "%*sAllowed Attributes:\n", indent, "") <= 0) {
            return 0;
        }
        aai = sk_ALLOWED_ATTRIBUTES_ITEM_value(aaa, i);
        if (i2r_ALLOWED_ATTRIBUTES_ITEM(method, aai, out, indent + 4) <= 0) {
            return 0;
        }
    }
    return 1;
}

const X509V3_EXT_METHOD ossl_v3_allowed_attribute_assignments = {
    NID_allowed_attribute_assignments, X509V3_EXT_MULTILINE,
    ASN1_ITEM_ref(ALLOWED_ATTRIBUTES_SYNTAX),
    0, 0, 0, 0,
    0, 0,
    0,
    0,
    (X509V3_EXT_I2R)i2r_ALLOWED_ATTRIBUTES_SYNTAX,
    0,
    NULL
};
