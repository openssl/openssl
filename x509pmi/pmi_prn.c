/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <libx509pmi/names.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include "pmi_local.h"

int ossl_x509pmi_bio_print_hex(BIO *out, const unsigned char *buf, int len)
{
    int result;
    char *hexbuf;

    if (len == 0)
        return 1;

    hexbuf = OPENSSL_buf2hexstr(buf, len);
    if (hexbuf == NULL)
        return 0;
    result = BIO_puts(out, hexbuf) > 0;

    OPENSSL_free(hexbuf);
    return result;
}

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

int ossl_x509pmi_print_attribute_value(BIO *out,
    int obj_nid,
    const ASN1_TYPE *av,
    int indent)
{
    ASN1_STRING *str;
    const unsigned char *value;
    X509_NAME *xn = NULL;
    int64_t int_val;
    int ret = 1;

    switch (av->type) {
    case V_ASN1_BOOLEAN:
        if (av->value.boolean) {
            return BIO_printf(out, "%*sTRUE", indent, "") >= 4;
        } else {
            return BIO_printf(out, "%*sFALSE", indent, "") >= 5;
        }

    case V_ASN1_INTEGER:
        if (BIO_printf(out, "%*s", indent, "") < 0)
            return 0;
        if (ASN1_INTEGER_get_int64(&int_val, av->value.integer) > 0)
            return BIO_printf(out, "%lld", (long long int)int_val) > 0;
        str = av->value.integer;
        return ossl_x509pmi_bio_print_hex(out, ASN1_STRING_get0_data(str),
            (int)ASN1_STRING_get_length(str));

    case V_ASN1_ENUMERATED:
        if (BIO_printf(out, "%*s", indent, "") < 0)
            return 0;
        if (ASN1_ENUMERATED_get_int64(&int_val, av->value.enumerated) > 0)
            return BIO_printf(out, "%lld", (long long int)int_val) > 0;
        str = av->value.enumerated;
        return ossl_x509pmi_bio_print_hex(out, ASN1_STRING_get0_data(str),
            (int)ASN1_STRING_get_length(str));

    case V_ASN1_BIT_STRING:
        if (BIO_printf(out, "%*s", indent, "") < 0)
            return 0;
        return ossl_x509pmi_bio_print_hex(out, ASN1_STRING_get0_data(av->value.bit_string),
            (int)ASN1_STRING_get_length(av->value.bit_string));

    case V_ASN1_OCTET_STRING:
    case V_ASN1_VIDEOTEXSTRING:
        if (BIO_printf(out, "%*s", indent, "") < 0)
            return 0;
        return ossl_x509pmi_bio_print_hex(out, ASN1_STRING_get0_data(av->value.octet_string),
            (int)ASN1_STRING_get_length(av->value.octet_string));

    case V_ASN1_NULL:
        return BIO_printf(out, "%*sNULL", indent, "") >= 4;

    case V_ASN1_OBJECT:
        if (BIO_printf(out, "%*s", indent, "") < 0)
            return 0;
        return print_oid(out, av->value.object);

    /*
     * ObjectDescriptor is an IMPLICIT GraphicString, but GeneralString is a
     * superset supported by OpenSSL, so we will use that anywhere a
     * GraphicString is needed here.
     */
    case V_ASN1_GENERALSTRING:
    case V_ASN1_GRAPHICSTRING:
    case V_ASN1_OBJECT_DESCRIPTOR:
        return BIO_printf(out, "%*s%.*s", indent, "",
                   (int)ASN1_STRING_get_length(av->value.generalstring),
                   ASN1_STRING_get_length(av->value.generalstring)
                       ? ASN1_STRING_get0_data(av->value.generalstring)
                       : (const unsigned char *)"")
            >= 0;

        /* EXTERNAL would go here. */
        /* EMBEDDED PDV would go here. */

    case V_ASN1_UTF8STRING:
        return BIO_printf(out, "%*s%.*s", indent, "",
                   (int)ASN1_STRING_get_length(av->value.utf8string),
                   ASN1_STRING_get_length(av->value.utf8string)
                       ? ASN1_STRING_get0_data(av->value.utf8string)
                       : (const unsigned char *)"")
            >= 0;

    case V_ASN1_REAL:
        return BIO_printf(out, "%*sREAL", indent, "") >= 4;

        /* RELATIVE-OID would go here. */
        /* TIME would go here. */

    case V_ASN1_SEQUENCE:
        switch (obj_nid) {
        case NID_undef: /* Unrecognized OID. */
            break;
        /* Attribute types with DN syntax. */
        case NID_member:
        case NID_roleOccupant:
        case NID_seeAlso:
        case NID_manager:
        case NID_documentAuthor:
        case NID_secretary:
        case NID_associatedName:
        case NID_dITRedirect:
        case NID_owner:
            /*
             * d2i_ functions increment the ppin pointer. See doc/man3/d2i_X509.pod.
             * This preserves the original  pointer. We don't want to corrupt this
             * value.
             */
            value = ASN1_STRING_get0_data(av->value.sequence);
            xn = d2i_X509_NAME(NULL, &value,
                (long)ASN1_STRING_get_length(av->value.sequence));
            if (xn == NULL) {
                BIO_puts(out, "(COULD NOT DECODE DISTINGUISHED NAME)\n");
                return 0;
            }
            if (X509_NAME_print_ex(out, xn, indent, XN_FLAG_SEP_CPLUS_SPC) <= 0)
                ret = 0;
            X509_NAME_free(xn);
            return ret;

        default:
            break;
        }
        return ASN1_parse_dump(out, ASN1_STRING_get0_data(av->value.sequence),
                   (long)ASN1_STRING_get_length(av->value.sequence), indent, 1)
            > 0;

    case V_ASN1_SET:
        return ASN1_parse_dump(out, ASN1_STRING_get0_data(av->value.set),
                   (long)ASN1_STRING_get_length(av->value.set), indent, 1)
            > 0;

    /*
     * UTCTime ::= [UNIVERSAL 23] IMPLICIT VisibleString
     * GeneralizedTime ::= [UNIVERSAL 24] IMPLICIT VisibleString
     * VisibleString is a superset for NumericString, so it will work for that.
     */
    case V_ASN1_VISIBLESTRING:
    case V_ASN1_UTCTIME:
    case V_ASN1_GENERALIZEDTIME:
    case V_ASN1_NUMERICSTRING:
        return BIO_printf(out, "%*s%.*s", indent, "",
                   (int)ASN1_STRING_get_length(av->value.visiblestring),
                   ASN1_STRING_get_length(av->value.visiblestring)
                       ? ASN1_STRING_get0_data(av->value.visiblestring)
                       : (const unsigned char *)"")
            >= 0;

    case V_ASN1_PRINTABLESTRING:
        return BIO_printf(out, "%*s%.*s", indent, "",
                   (int)ASN1_STRING_get_length(av->value.printablestring),
                   ASN1_STRING_get_length(av->value.printablestring)
                       ? ASN1_STRING_get0_data(av->value.printablestring)
                       : (const unsigned char *)"")
            >= 0;

    case V_ASN1_T61STRING:
        return BIO_printf(out, "%*s%.*s", indent, "",
                   (int)ASN1_STRING_get_length(av->value.t61string),
                   ASN1_STRING_get_length(av->value.t61string)
                       ? ASN1_STRING_get0_data(av->value.t61string)
                       : (const unsigned char *)"")
            >= 0;

    case V_ASN1_IA5STRING:
        return BIO_printf(out, "%*s%.*s", indent, "",
                   (int)ASN1_STRING_get_length(av->value.ia5string),
                   ASN1_STRING_get_length(av->value.ia5string)
                       ? ASN1_STRING_get0_data(av->value.ia5string)
                       : (const unsigned char *)"")
            >= 0;

    /* UniversalString would go here. */
    /* CHARACTER STRING would go here. */
    /* BMPString would go here. */
    /* DATE would go here. */
    /* TIME-OF-DAY would go here. */
    /* DATE-TIME would go here. */
    /* DURATION would go here. */
    /* OID-IRI would go here. */
    /* RELATIVE-OID-IRI would go here. */

    /* Would it be appropriate to just hexdump? */
    default:
        return BIO_printf(out,
                   "%*s<Unsupported tag %d>",
                   indent,
                   "",
                   av->type)
            >= 0;
    }
}
