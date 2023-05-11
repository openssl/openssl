/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "x509_local.h"

/*-
 * X509_ATTRIBUTE: this has the following form:
 *
 * typedef struct x509_attributes_st
 *      {
 *      ASN1_OBJECT *object;
 *      STACK_OF(ASN1_TYPE) *set;
 *      } X509_ATTRIBUTE;
 *
 */

ASN1_SEQUENCE(X509_ATTRIBUTE) = {
        ASN1_SIMPLE(X509_ATTRIBUTE, object, ASN1_OBJECT),
        ASN1_SET_OF(X509_ATTRIBUTE, set, ASN1_ANY)
} ASN1_SEQUENCE_END(X509_ATTRIBUTE)

IMPLEMENT_ASN1_FUNCTIONS(X509_ATTRIBUTE)
IMPLEMENT_ASN1_DUP_FUNCTION(X509_ATTRIBUTE)

X509_ATTRIBUTE *X509_ATTRIBUTE_create(int nid, int atrtype, void *value)
{
    X509_ATTRIBUTE *ret = NULL;
    ASN1_TYPE *val = NULL;
    ASN1_OBJECT *oid;

    if ((oid = OBJ_nid2obj(nid)) == NULL)
        return NULL;
    if ((ret = X509_ATTRIBUTE_new()) == NULL)
        return NULL;
    ret->object = oid;
    if ((val = ASN1_TYPE_new()) == NULL)
        goto err;
    if (!sk_ASN1_TYPE_push(ret->set, val))
        goto err;

    ASN1_TYPE_set(val, atrtype, value);
    return ret;
 err:
    X509_ATTRIBUTE_free(ret);
    ASN1_TYPE_free(val);
    return NULL;
}

static int ASN1_INTEGER_print_bio(BIO *bio, const ASN1_INTEGER *num)
{
    BIGNUM *num_bn;
    int result = 0;
    char *hex;

    num_bn = ASN1_INTEGER_to_BN(num, NULL);
    if (num_bn == NULL)
        return -1;
    if ((hex = BN_bn2hex(num_bn))) {
        result = BIO_write(bio, "0x", 2) > 0;
        result = result && BIO_write(bio, hex, strlen(hex)) > 0;
        OPENSSL_free(hex);
    }
    BN_free(num_bn);

    return result;
}

int print_hex(BIO *out, unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        if (BIO_printf(out, "%02X ", buf[i]) <= 0) {
            return 0;
        }
    }
    return 1;
}

int print_attribute_value(BIO *out, int obj_nid, const ASN1_TYPE *av, int indent)
{
    const char *ln;
    char objbuf[80];
    ASN1_STRING *str;
    unsigned char *value;
    X509_NAME *xn = NULL;
    int64_t int_val;
    PLATFORM_CONFIG *pc = NULL;
    TCG_PLATFORM_SPEC *ps = NULL;
    TCG_CRED_TYPE *ct = NULL;
    MANUFACTURER_ID *mid = NULL;
    TBB_SECURITY_ASSERTIONS *tbb = NULL;
    URI_REFERENCE *uri = NULL;

    // This switch-case is only for syntaxes that are not encoded as a single
    // primitively-constructed value universal ASN.1 type.
    switch (obj_nid) {
    case NID_undef: break; // Unrecognized OID.
    // Attribute types with DN syntax.
    case NID_member:
    case NID_roleOccupant:
    case NID_seeAlso:
    case NID_manager:
    case NID_documentAuthor:
    case NID_secretary:
    case NID_associatedName:
    case NID_dITRedirect:
    case NID_owner:
        value = av->value.sequence->data;
        if ((xn = d2i_X509_NAME(NULL, (const unsigned char**)&(av->value.sequence->data), av->value.sequence->length)) == NULL) {
            BIO_puts(out, "(COULD NOT DECODE DISTINGUISHED NAME)\n");
            return 0;
        }
        // d2i_ functions increment the ppin pointer. See doc/man3/d2i_X509.pod.
        // This resets the pointer. We don't want to corrupt this value.
        av->value.sequence->data = value;
        if (X509_NAME_print_ex(out, xn, indent, 0) <= 0) {
            return 0;
        }
        X509_NAME_free(xn);
        return 1;

    case NID_tcg_at_platformConfiguration_v2:
        value = av->value.sequence->data;
        if ((pc = d2i_PLATFORM_CONFIG(NULL, (const unsigned char**)&(av->value.sequence->data), av->value.sequence->length)) == NULL) {
            BIO_puts(out, "(COULD NOT DECODE PLATFORM CONFIG)\n");
            return 0;
        }
        // d2i_ functions increment the ppin pointer. See doc/man3/d2i_X509.pod.
        // This resets the pointer. We don't want to corrupt this value.
        av->value.sequence->data = value;
        if (PLATFORM_CONFIG_print(out, pc, indent) <= 0) {
            return 0;
        }
        PLATFORM_CONFIG_free(pc);
        return 1;

    case NID_tcg_at_tcgPlatformSpecification:
        if (indent && BIO_printf(out, "%*s", indent, "") <= 0) {
            return 0;
        }
        value = av->value.sequence->data;
        if ((ps = d2i_TCG_PLATFORM_SPEC(NULL, (const unsigned char**)&(av->value.sequence->data), av->value.sequence->length)) == NULL) {
            BIO_puts(out, "(COULD NOT DECODE PLATFORM SPECIFICATION)\n");
            return 0;
        }
        // d2i_ functions increment the ppin pointer. See doc/man3/d2i_X509.pod.
        // This resets the pointer. We don't want to corrupt this value.
        av->value.sequence->data = value;
        if (TCG_PLATFORM_SPEC_print(out, ps) <= 0) {
            return 0;
        }
        TCG_PLATFORM_SPEC_free(ps);
        return 1;

    case NID_tcg_at_tcgCredentialType:
        value = av->value.sequence->data;
        if ((ct = d2i_TCG_CRED_TYPE(NULL, (const unsigned char**)&(av->value.sequence->data), av->value.sequence->length)) == NULL) {
            BIO_puts(out, "(COULD NOT DECODE PLATFORM CERT CREDENTIAL TYPE)\n");
            return 0;
        }
        // d2i_ functions increment the ppin pointer. See doc/man3/d2i_X509.pod.
        // This resets the pointer. We don't want to corrupt this value.
        av->value.sequence->data = value;
        if (TCG_CRED_TYPE_print(out, ct, indent) <= 0) {
            return 0;
        }
        TCG_CRED_TYPE_free(ct);
        return 1;

    case NID_tcg_at_platformManufacturerId:
        value = av->value.sequence->data;
        if ((mid = d2i_MANUFACTURER_ID(NULL, (const unsigned char**)&(av->value.sequence->data), av->value.sequence->length)) == NULL) {
            BIO_puts(out, "(COULD NOT DECODE PLATFORM MANUFACTURER ID)\n");
            return 0;
        }
        // d2i_ functions increment the ppin pointer. See doc/man3/d2i_X509.pod.
        // This resets the pointer. We don't want to corrupt this value.
        av->value.sequence->data = value;
        if (MANUFACTURER_ID_print(out, mid, indent) <= 0) {
            return 0;
        }
        MANUFACTURER_ID_free(mid);
        return 1;

    case NID_tcg_at_tbbSecurityAssertions:
        value = av->value.sequence->data;
        if ((tbb = d2i_TBB_SECURITY_ASSERTIONS(NULL, (const unsigned char**)&(av->value.sequence->data), av->value.sequence->length)) == NULL) {
            BIO_puts(out, "(COULD NOT DECODE TBB SECURITY ASSERTIONS)\n");
            return 0;
        }
        // d2i_ functions increment the ppin pointer. See doc/man3/d2i_X509.pod.
        // This resets the pointer. We don't want to corrupt this value.
        av->value.sequence->data = value;
        if (TBB_SECURITY_ASSERTIONS_print(out, tbb, indent) <= 0) {
            return 0;
        }
        TBB_SECURITY_ASSERTIONS_free(tbb);
        return 1;

    case NID_tcg_at_platformConfigUri:
        value = av->value.sequence->data;
        if ((uri = d2i_URI_REFERENCE(NULL, (const unsigned char**)&(av->value.sequence->data), av->value.sequence->length)) == NULL) {
            BIO_puts(out, "(COULD NOT DECODE TBB SECURITY ASSERTIONS)\n");
            return 0;
        }
        // d2i_ functions increment the ppin pointer. See doc/man3/d2i_X509.pod.
        // This resets the pointer. We don't want to corrupt this value.
        av->value.sequence->data = value;
        if (URI_REFERENCE_print(out, uri, indent) <= 0) {
            return 0;
        }
        URI_REFERENCE_free(uri);
        return 1;

    default: break;
    }

    switch (av->type) {
    case V_ASN1_BOOLEAN:
        if (av->value.boolean) {
            return BIO_printf(out, "%*sTRUE", indent, "");
        } else {
            return BIO_printf(out, "%*sFALSE", indent, "");
        }

    case V_ASN1_INTEGER:
        if (indent && BIO_printf(out, "%*s", indent, "") <= 0) {
            return 0;
        }
        if (ASN1_INTEGER_get_int64(&int_val, av->value.integer) > 0) {
            return BIO_printf(out, "%ld", int_val);
        } else {
            return ASN1_INTEGER_print_bio(out, str);
        }

    case V_ASN1_ENUMERATED:
        if (indent && BIO_printf(out, "%*s", indent, "") <= 0) {
            return 0;
        }
        if (ASN1_ENUMERATED_get_int64(&int_val, av->value.enumerated) > 0) {
            return BIO_printf(out, "%ld", int_val);
        } else {
            return ASN1_INTEGER_print_bio(out, str);
        }

    case V_ASN1_BIT_STRING:
        if (indent && BIO_printf(out, "%*s", indent, "") <= 0) {
            return 0;
        }
        return print_hex(out, av->value.bit_string->data,
                 av->value.bit_string->length);

    case V_ASN1_OCTET_STRING:
    case V_ASN1_VIDEOTEXSTRING:
        if (indent && BIO_printf(out, "%*s", indent, "") <= 0) {
            return 0;
        }
        return print_hex(out, av->value.octet_string->data,
                 av->value.octet_string->length);

    case V_ASN1_NULL:
        return BIO_printf(out, "%*sNULL", indent, "");

    case V_ASN1_OBJECT:
        if (indent && BIO_printf(out, "%*s", indent, "") <= 0) {
            return 0;
        }
        return print_oid(out, av->value.object);

    /* ObjectDescriptor is an IMPLICIT GraphicString, but GeneralString is a
    superset supported by OpenSSL, so we will use that anywhere a GraphicString
    is needed here. */
    case V_ASN1_GENERALSTRING:
    case V_ASN1_GRAPHICSTRING:
    case V_ASN1_OBJECT_DESCRIPTOR:
        return BIO_printf(out, "%*s%.*s", indent, "",
                          av->value.generalstring->length,
                          av->value.generalstring->data);

    /* EXTERNAL */
    /* EMBEDDED PDV */

    case V_ASN1_UTF8STRING:
        return BIO_printf(out, "%*s%.*s", indent, "",
                          av->value.utf8string->length,
                          av->value.utf8string->data);

    case V_ASN1_REAL:
        return BIO_printf(out, "%*sREAL", indent, "");

    /* RELATIVE-OID */
    /* TIME */

    case V_ASN1_SEQUENCE:
        return ASN1_parse_dump(out, av->value.sequence->data,
                        av->value.sequence->length, indent, 1);

    case V_ASN1_SET:
        return ASN1_parse_dump(out, av->value.set->data,
                av->value.set->length, indent, 1);

    /*
        UTCTime ::= [UNIVERSAL 23] IMPLICIT VisibleString
        GeneralizedTime ::= [UNIVERSAL 24] IMPLICIT VisibleString
        VisibleString is a superset for NumericString, so it will work for that.
    */
    case V_ASN1_VISIBLESTRING:
    case V_ASN1_UTCTIME:
    case V_ASN1_GENERALIZEDTIME:
    case V_ASN1_NUMERICSTRING:
        return BIO_printf(out, "%*s%.*s", indent, "",
                          av->value.visiblestring->length,
                          av->value.visiblestring->data);

    case V_ASN1_PRINTABLESTRING:
        return BIO_printf(out, "%*s%.*s", indent, "",
                          av->value.printablestring->length,
                          av->value.printablestring->data);

    case V_ASN1_T61STRING:
        return BIO_printf(out, "%*s%.*s", indent, "",
                          av->value.t61string->length,
                          av->value.t61string->data);

    case V_ASN1_IA5STRING:
        return BIO_printf(out, "%*s%.*s", indent, "",
                          av->value.ia5string->length,
                          av->value.ia5string->data);

    /* UniversalString */
    /* CHARACTER STRING */

    case V_ASN1_BMPSTRING:
        value = OPENSSL_uni2asc(av->value.bmpstring->data,
                                av->value.bmpstring->length);
        int ret = BIO_printf(out, "%*s%s", indent, "", value);
        OPENSSL_free(value);
        return ret;

    /* DATE */
    /* TIME-OF-DAY */
    /* DATE-TIME */
    /* DURATION */
    /* OID-IRI */
    /* RELATIVE-OID-IRI */

    /* Would it be approriate to just hexdump? */
    default:
        return BIO_printf(out, "%*s<Unsupported tag %d>", indent, "", av->type);
    }
}