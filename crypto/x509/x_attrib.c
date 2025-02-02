/*
 * Copyright 1995-2024 The OpenSSL Project Authors. All Rights Reserved.
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
#include "x509_local.h"
#include <crypto/x509.h>
#include <openssl/platcert.h>
#include <crypto/platcert.h>
#include <openssl/x509v3.h>

#include <crypto/asn1.h>

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

static int print_pubkey(BIO *out, X509_PUBKEY *pubkey, int indent) {
    ASN1_OBJECT *xpoid;
    EVP_PKEY *pkey;

    X509_PUBKEY_get0_param(&xpoid, NULL, NULL, NULL, pubkey);
    if (BIO_printf(out, "%*sPublic Key Algorithm: ", indent, "") <= 0)
         return -1;
    if (i2a_ASN1_OBJECT(out, xpoid) <= 0)
        return -1;
    if (BIO_puts(out, "\n") <= 0)
        return -1;

    pkey = X509_PUBKEY_get0(pubkey);
    if (pkey == NULL) {
        BIO_printf(out, "%*sUnable to load Public Key\n", indent, "");
        ERR_print_errors(out);
    } else {
        EVP_PKEY_print_public(out, pkey, indent, NULL);
    }
    return 1;
}

#define TRY_PRINT_SEQ_FUNC(local, type, name, printer) value = av->value.sequence->data; \
    if ((local = d2i_##type(NULL, (const unsigned char**)&value,\
                            av->value.sequence->length)) == NULL) {\
        BIO_printf(out, "(COULD NOT DECODE %s)\n", name);\
        return 0;\
    }\
    if (printer(out, local, indent) <= 0) {\
        type##_free(local);\
        return 0;\
    }\
    type##_free(local);\
    return 1;

#define TRY_PRINT_SEQ(local, type, name) TRY_PRINT_SEQ_FUNC(local, type, name, type##_print)

int ossl_print_attribute_value(BIO *out,
    int obj_nid,
    const ASN1_TYPE *av,
    int indent)
{
    ASN1_STRING *str;
    unsigned char *value;
    X509_NAME *xn = NULL;
    int64_t int_val;
    int ret = 1;
    OSSL_PLATFORM_CONFIG *pc = NULL;
    OSSL_TCG_PLATFORM_SPEC *ps = NULL;
    OSSL_TCG_CRED_TYPE *ct = NULL;
    OSSL_TCG_SPEC_VERSION *sv = NULL;
    OSSL_MANUFACTURER_ID *mid = NULL;
    OSSL_TBB_SECURITY_ASSERTIONS *tbb = NULL;
    OSSL_URI_REFERENCE *uri = NULL;
    STACK_OF(OSSL_PCV2_TRAIT) *traits = NULL;
    OSSL_PLATFORM_CONFIG_V3 *platconf3 = NULL;
    OSSL_FIPS_LEVEL *fips = NULL;
    OSSL_PCV2_CERTIFICATE_IDENTIFIER *certid = NULL;
    OSSL_COMPONENT_IDENTIFIER *compid = NULL;
    OSSL_COMPONENT_ADDRESS *compaddr = NULL;
    OSSL_ISO9000_CERTIFICATION *iso9000 = NULL;
    X509_PUBKEY *pubkey = NULL;

    switch (av->type) {
    case V_ASN1_BOOLEAN:
        if (av->value.boolean) {
            return BIO_printf(out, "%*sTRUE", indent, "") >= 4;
        } else {
            return BIO_printf(out, "%*sFALSE", indent, "") >= 5;
        }

    case V_ASN1_INTEGER:
    case V_ASN1_ENUMERATED:
        if (BIO_printf(out, "%*s", indent, "") < 0)
            return 0;
        if (ASN1_ENUMERATED_get_int64(&int_val, av->value.integer) > 0) {
            return BIO_printf(out, "%lld", (long long int)int_val) > 0;
        }
        str = av->value.integer;
        return ossl_bio_print_hex(out, str->data, str->length);

    case V_ASN1_BIT_STRING:
        if (BIO_printf(out, "%*s", indent, "") < 0)
            return 0;
        return ossl_bio_print_hex(out, av->value.bit_string->data,
            av->value.bit_string->length);

    case V_ASN1_OCTET_STRING:
    case V_ASN1_VIDEOTEXSTRING:
        if (BIO_printf(out, "%*s", indent, "") < 0)
            return 0;
        return ossl_bio_print_hex(out, av->value.octet_string->data,
            av->value.octet_string->length);

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
                   av->value.generalstring->length,
                   av->value.generalstring->data)
            >= 0;

        /* EXTERNAL would go here. */
        /* EMBEDDED PDV would go here. */

    case V_ASN1_UTF8STRING:
        return BIO_printf(out, "%*s%.*s", indent, "",
                   av->value.utf8string->length,
                   av->value.utf8string->data)
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
            value = av->value.sequence->data;
            xn = d2i_X509_NAME(NULL,
                (const unsigned char **)&value,
                av->value.sequence->length);
            if (xn == NULL) {
                BIO_puts(out, "(COULD NOT DECODE DISTINGUISHED NAME)\n");
                return 0;
            }
            if (X509_NAME_print_ex(out, xn, indent, XN_FLAG_SEP_CPLUS_SPC) <= 0)
                ret = 0;
            X509_NAME_free(xn);
            return ret;

        case NID_tcg_at_platformConfiguration_v2:
            value = av->value.sequence->data;
            if ((pc = d2i_OSSL_PLATFORM_CONFIG(NULL,
                                               (const unsigned char**)&value,
                                               av->value.sequence->length)) == NULL) {
                BIO_puts(out, "(COULD NOT DECODE PLATFORM CONFIG)\n");
                return 0;
            }
            if (OSSL_PLATFORM_CONFIG_print(out, pc, indent) <= 0)
                return 0;
            OSSL_PLATFORM_CONFIG_free(pc);
            return 1;

        case NID_tcg_at_tcgPlatformSpecification:
            if (indent && BIO_printf(out, "%*s", indent, "") <= 0)
                return 0;
            value = av->value.sequence->data;
            if ((ps = d2i_OSSL_TCG_PLATFORM_SPEC(NULL,
                                                 (const unsigned char**)&value,
                                                 av->value.sequence->length)) == NULL) {
                BIO_puts(out, "(COULD NOT DECODE PLATFORM SPECIFICATION)\n");
                return 0;
            }
            if (OSSL_TCG_PLATFORM_SPEC_print(out, ps) <= 0)
                return 0;
            OSSL_TCG_PLATFORM_SPEC_free(ps);
            return 1;

        case NID_tcg_at_tcgCredentialType:
            value = av->value.sequence->data;
            if ((ct = d2i_OSSL_TCG_CRED_TYPE(NULL,
                                             (const unsigned char**)&value,
                                             av->value.sequence->length)) == NULL) {
                BIO_puts(out, "(COULD NOT DECODE PLATFORM CERT CREDENTIAL TYPE)\n");
                return 0;
            }
            if (OSSL_TCG_CRED_TYPE_print(out, ct, indent) <= 0)
                return 0;
            OSSL_TCG_CRED_TYPE_free(ct);
            return 1;

        case NID_tcg_at_platformManufacturerId:
            value = av->value.sequence->data;
            if ((mid = d2i_OSSL_MANUFACTURER_ID(NULL,
                                                (const unsigned char**)&value,
                                                av->value.sequence->length)) == NULL) {
                BIO_puts(out, "(COULD NOT DECODE PLATFORM MANUFACTURER ID)\n");
                return 0;
            }
            if (OSSL_MANUFACTURER_ID_print(out, mid, indent) <= 0)
                return 0;
            OSSL_MANUFACTURER_ID_free(mid);
            return 1;

        case NID_tcg_at_tbbSecurityAssertions:
            value = av->value.sequence->data;
            if ((tbb = d2i_OSSL_TBB_SECURITY_ASSERTIONS(NULL,
                                                        (const unsigned char**)&value,
                                                        av->value.sequence->length)) == NULL) {
                BIO_puts(out, "(COULD NOT DECODE TBB SECURITY ASSERTIONS)\n");
                return 0;
            }
            if (OSSL_TBB_SECURITY_ASSERTIONS_print(out, tbb, indent) <= 0)
                return 0;
            OSSL_TBB_SECURITY_ASSERTIONS_free(tbb);
            return 1;

        case NID_tcg_at_platformConfigUri:
            value = av->value.sequence->data;
            if ((uri = d2i_OSSL_URI_REFERENCE(NULL,
                                              (const unsigned char**)&value,
                                              av->value.sequence->length)) == NULL) {
                BIO_puts(out, "(COULD NOT DECODE URI REFERENCE)\n");
                return 0;
            }
            if (OSSL_URI_REFERENCE_print(out, uri, indent) <= 0)
                return 0;
            OSSL_URI_REFERENCE_free(uri);
            return 1;

        case NID_tcg_at_tcgCredentialSpecification:
            value = av->value.sequence->data;
            if ((sv = d2i_OSSL_TCG_SPEC_VERSION(NULL,
                                                (const unsigned char**)&value,
                                                av->value.sequence->length)) == NULL) {
                BIO_puts(out, "(COULD NOT DECODE TCG CREDENTIAL SPECIFICATION)\n");
                return 0;
            }
            // FIXME: Free structures on failure.
            if (OSSL_TCG_SPEC_VERSION_print(out, sv, indent) <= 0)
                return 0;
            OSSL_TCG_SPEC_VERSION_free(sv);
            return 1;

        case NID_tcg_at_platformIdentifier:
        case NID_tcg_at_platformConfigUri_v3:
        case NID_tcg_at_previousPlatformCertificates:
        case NID_tcg_at_tbbSecurityAssertions_v3:
        case NID_tcg_at_cryptographicAnchors:
            value = av->value.sequence->data;
            if ((traits = d2i_OSSL_PCV2_TRAITS(NULL,
                                               (const unsigned char**)&value,
                                               av->value.sequence->length)) == NULL) {
                BIO_puts(out, "(COULD NOT DECODE TCG TRAITS)\n");
                return 0;
            }
            if (print_traits(out, traits, indent) <= 0)
                return 0;
            OSSL_PCV2_TRAITS_free(traits);
            return 1;

        case NID_tcg_at_platformConfiguration_v3:
            value = av->value.sequence->data;
            if ((platconf3 = d2i_OSSL_PLATFORM_CONFIG_V3(NULL,
                                                         (const unsigned char**)&value,
                                                         av->value.sequence->length)) == NULL) {
                BIO_puts(out, "(COULD NOT DECODE PLATFORM CONFIG V3)\n");
                return 0;
            }
            if (OSSL_PLATFORM_CONFIG_V3_print(out, platconf3, indent) <= 0)
                return 0;
            OSSL_PLATFORM_CONFIG_V3_free(platconf3);
            return 1;

        case NID_tcg_tr_ID_FIPSLevel:
            TRY_PRINT_SEQ(fips, OSSL_FIPS_LEVEL, "FIPSLevel")
        case NID_tcg_tr_ID_CertificateIdentifier:
            TRY_PRINT_SEQ(certid, OSSL_PCV2_CERTIFICATE_IDENTIFIER, "TCG Certificate Identifier")
        case NID_tcg_tr_ID_componentIdentifierV11:
            TRY_PRINT_SEQ(compid, OSSL_COMPONENT_IDENTIFIER, "TCG Platform Certificate Component Identifier")
        case NID_tcg_tr_ID_networkMAC:
            TRY_PRINT_SEQ(compaddr, OSSL_COMPONENT_ADDRESS, "TCG Platform Certificate Component Address")
        case NID_tcg_tr_ID_ISO9000Level:
            TRY_PRINT_SEQ(iso9000, OSSL_ISO9000_CERTIFICATION, "TCG Platform Certificate ISO 9000 Certification")
        case NID_tcg_tr_ID_PublicKey:
            TRY_PRINT_SEQ_FUNC(pubkey, X509_PUBKEY, "TCG Public Key Trait", print_pubkey)

        default:
            break;
        }
        return ASN1_parse_dump(out, av->value.sequence->data,
                   av->value.sequence->length, indent, 1)
            > 0;

    case V_ASN1_SET:
        return ASN1_parse_dump(out, av->value.set->data,
                   av->value.set->length, indent, 1)
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
                   av->value.visiblestring->length,
                   av->value.visiblestring->data)
            >= 0;

    case V_ASN1_PRINTABLESTRING:
        return BIO_printf(out, "%*s%.*s", indent, "",
                   av->value.printablestring->length,
                   av->value.printablestring->data)
            >= 0;

    case V_ASN1_T61STRING:
        return BIO_printf(out, "%*s%.*s", indent, "",
                   av->value.t61string->length,
                   av->value.t61string->data)
            >= 0;

    case V_ASN1_IA5STRING:
        return BIO_printf(out, "%*s%.*s", indent, "",
                   av->value.ia5string->length,
                   av->value.ia5string->data)
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
