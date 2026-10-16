/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <openssl/posix_time.h>
#include <openssl/x509v3.h>

#include "crypto/asn1.h"
#include "crypto/objects.h"
#include "crypto/x509_view.h"
#include "internal/bytestring.h"
#include "internal/nelem.h"

/* Extension OIDs, as DER content octets. */
static const uint8_t oid_basic_constraints[] = { 0x55, 0x1d, 0x13 };
static const uint8_t oid_key_usage[] = { 0x55, 0x1d, 0x0f };
static const uint8_t oid_ext_key_usage[] = { 0x55, 0x1d, 0x25 };
static const uint8_t oid_subject_alt_name[] = { 0x55, 0x1d, 0x11 };
static const uint8_t oid_subject_key_id[] = { 0x55, 0x1d, 0x0e };
static const uint8_t oid_authority_key_id[] = { 0x55, 0x1d, 0x23 };
static const uint8_t oid_name_constraints[] = { 0x55, 0x1d, 0x1e };
static const uint8_t oid_certificate_policies[] = { 0x55, 0x1d, 0x20 };
static const uint8_t oid_policy_mappings[] = { 0x55, 0x1d, 0x21 };
static const uint8_t oid_policy_constraints[] = { 0x55, 0x1d, 0x24 };
static const uint8_t oid_inhibit_any_policy[] = { 0x55, 0x1d, 0x36 };
static const uint8_t oid_ip_addr_blocks[] = {
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x07
};
static const uint8_t oid_autonomous_sys_ids[] = {
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x08
};

/* Extended key usage OIDs, as DER content octets. */
static const uint8_t oid_server_auth[] = {
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01
};
static const uint8_t oid_client_auth[] = {
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02
};
static const uint8_t oid_code_sign[] = {
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03
};
static const uint8_t oid_email_protect[] = {
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04
};
static const uint8_t oid_time_stamp[] = {
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08
};
static const uint8_t oid_ocsp_sign[] = {
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09
};
static const uint8_t oid_dvcs[] = {
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x0a
};
static const uint8_t oid_ns_sgc[] = {
    0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x04, 0x01
};
static const uint8_t oid_ms_sgc[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x03
};
static const uint8_t oid_any_eku[] = { 0x55, 0x1d, 0x25, 0x00 };

static const struct {
    const uint8_t *oid;
    size_t oid_len;
    uint32_t usage;
} ext_key_usages[] = {
    { oid_server_auth, sizeof(oid_server_auth), XKU_SSL_SERVER },
    { oid_client_auth, sizeof(oid_client_auth), XKU_SSL_CLIENT },
    { oid_email_protect, sizeof(oid_email_protect), XKU_SMIME },
    { oid_code_sign, sizeof(oid_code_sign), XKU_CODE_SIGN },
    { oid_ns_sgc, sizeof(oid_ns_sgc), XKU_SGC },
    { oid_ms_sgc, sizeof(oid_ms_sgc), XKU_SGC },
    { oid_ocsp_sign, sizeof(oid_ocsp_sign), XKU_OCSP_SIGN },
    { oid_time_stamp, sizeof(oid_time_stamp), XKU_TIMESTAMP },
    { oid_dvcs, sizeof(oid_dvcs), XKU_DVCS },
    { oid_any_eku, sizeof(oid_any_eku), XKU_ANYEKU }
};

#define CLASS_MASK 0xc0

/* Version numbers as encoded (RFC 5280 4.1). */
#define X509_VIEW_V1 0
#define X509_VIEW_V2 1
#define X509_VIEW_V3 2

static int cbs_equals(const CBS *cbs, const uint8_t *data, size_t len)
{
    return CBS_len(cbs) == len && memcmp(CBS_data(cbs), data, len) == 0;
}

/* The content octets of the next element, whatever its tag. */
static int get_any_asn1(CBS *cbs, CBS *out, unsigned int *out_tag)
{
    size_t header_len;

    if (!CBS_get_any_asn1_element(cbs, out, out_tag, &header_len))
        return 0;

    return CBS_skip(out, header_len);
}

/*
 * Reads a BOOLEAN if one is next, else leaves *out false.  Only 0xff is
 * TRUE, as DER requires (X.690 11.1).
 */
static int get_optional_bool(CBS *cbs, int *out)
{
    CBS boolean;

    *out = 0;

    if (!CBS_peek_asn1_tag(cbs, CBS_ASN1_BOOLEAN))
        return 1;
    if (!CBS_get_asn1(cbs, &boolean, CBS_ASN1_BOOLEAN))
        return 0;
    if (CBS_len(&boolean) != 1)
        return 0;
    if (CBS_data(&boolean)[0] == 0xff)
        *out = 1;
    else if (CBS_data(&boolean)[0] != 0)
        return 0;

    return 1;
}

/*
 * Reads an element with the given tag into *out if one is next, setting
 * *out_present.
 */
static int get_optional_element(CBS *cbs, CBS *out, int *out_present,
    unsigned int tag)
{
    *out_present = 0;

    if (!CBS_peek_asn1_tag(cbs, tag))
        return 1;
    if (!CBS_get_asn1_element(cbs, out, tag))
        return 0;
    *out_present = 1;

    return 1;
}

/*
 * Reads an INTEGER element with a minimal encoding into *out and its
 * content octets into *out_contents.
 */
static int get_integer(CBS *cbs, CBS *out, CBS *out_contents)
{
    CBS integer;

    if (!CBS_get_asn1_element(cbs, out, CBS_ASN1_INTEGER))
        return 0;
    CBS_dup(out, &integer);
    if (!CBS_get_asn1(&integer, out_contents, CBS_ASN1_INTEGER))
        return 0;
    if (CBS_len(out_contents) == 0)
        return 0;
    if (CBS_len(out_contents) > 1) {
        if (CBS_data(out_contents)[0] == 0x00
            && (CBS_data(out_contents)[1] & 0x80) == 0)
            return 0;
        if (CBS_data(out_contents)[0] == 0xff
            && (CBS_data(out_contents)[1] & 0x80) != 0)
            return 0;
    }

    return 1;
}

/* Reads a BIT STRING element with no unused bits into *out. */
static int get_bit_string(CBS *cbs, CBS *out)
{
    CBS bit_string, bits;
    uint8_t unused;

    if (!CBS_get_asn1_element(cbs, out, CBS_ASN1_BITSTRING))
        return 0;
    CBS_dup(out, &bit_string);
    if (!CBS_get_asn1(&bit_string, &bits, CBS_ASN1_BITSTRING))
        return 0;
    if (!CBS_get_u8(&bits, &unused))
        return 0;

    return unused == 0;
}

static int parse_basic_constraints(CBS *value, struct x509_view *cert)
{
    CBS seq;
    uint64_t path_len;

    if (!CBS_get_asn1(value, &seq, CBS_ASN1_SEQUENCE))
        return 0;
    if (!get_optional_bool(&seq, &cert->ca))
        return 0;
    cert->path_len = -1;
    if (CBS_peek_asn1_tag(&seq, CBS_ASN1_INTEGER)) {
        if (!CBS_get_asn1_uint64(&seq, &path_len))
            return 0;
        if (path_len > INT64_MAX)
            return 0;
        if (!cert->ca)
            return 0;
        cert->path_len = (int64_t)path_len;
    }
    if (CBS_len(&seq) != 0 || CBS_len(value) != 0)
        return 0;

    cert->has_basic_constraints = 1;

    return 1;
}

/*
 * The named bits of a KeyUsage.  Unused bits of the final octet must be
 * zero; bits beyond the second octet have no name and are ignored.
 */
static int parse_key_usage(CBS *value, struct x509_view *cert)
{
    CBS bits;
    uint8_t unused, last;

    if (!CBS_get_asn1(value, &bits, CBS_ASN1_BITSTRING))
        return 0;
    if (!CBS_get_u8(&bits, &unused))
        return 0;
    if (unused > 7)
        return 0;
    if (CBS_len(&bits) == 0) {
        if (unused != 0)
            return 0;
    } else {
        last = CBS_data(&bits)[CBS_len(&bits) - 1];
        if ((last & ((1U << unused) - 1)) != 0)
            return 0;
    }
    if (CBS_len(value) != 0)
        return 0;

    cert->key_usage = 0;
    if (CBS_len(&bits) > 0)
        cert->key_usage = CBS_data(&bits)[0];
    if (CBS_len(&bits) > 1)
        cert->key_usage |= (uint32_t)CBS_data(&bits)[1] << 8;
    cert->has_key_usage = 1;

    return 1;
}

static int parse_ext_key_usage(CBS *value, struct x509_view *cert)
{
    CBS seq, oid;
    size_t i;

    if (!CBS_get_asn1(value, &seq, CBS_ASN1_SEQUENCE))
        return 0;
    if (CBS_len(&seq) == 0)
        return 0;

    cert->ext_key_usage = 0;
    while (CBS_len(&seq) > 0) {
        if (!CBS_get_asn1(&seq, &oid, CBS_ASN1_OBJECT))
            return 0;
        if (CBS_len(&oid) == 0)
            return 0;
        for (i = 0; i < OSSL_NELEM(ext_key_usages); i++) {
            if (cbs_equals(&oid, ext_key_usages[i].oid,
                    ext_key_usages[i].oid_len))
                cert->ext_key_usage |= ext_key_usages[i].usage;
        }
    }
    if (CBS_len(value) != 0)
        return 0;

    cert->has_ext_key_usage = 1;

    return 1;
}

/*
 * A GeneralName is a context specific element numbered 0 to 8, constructed
 * for otherName, x400Address, directoryName and ediPartyName and primitive
 * otherwise.  Only its framing is checked.
 */
static int get_general_name(CBS *cbs, unsigned int *out_tag, CBS *out)
{
    unsigned int tag;

    if (!get_any_asn1(cbs, out, &tag))
        return 0;
    if ((tag & CLASS_MASK) != CBS_ASN1_CONTEXT_SPECIFIC)
        return 0;
    switch (tag & ~(CLASS_MASK | CBS_ASN1_CONSTRUCTED)) {
    case GEN_OTHERNAME:
    case GEN_X400:
    case GEN_DIRNAME:
    case GEN_EDIPARTY:
        if ((tag & CBS_ASN1_CONSTRUCTED) == 0)
            return 0;
        break;
    case GEN_EMAIL:
    case GEN_DNS:
    case GEN_URI:
    case GEN_IPADD:
    case GEN_RID:
        if ((tag & CBS_ASN1_CONSTRUCTED) != 0)
            return 0;
        break;
    default:
        return 0;
    }

    *out_tag = tag;

    return 1;
}

static int parse_subject_alt_name(CBS *value, struct x509_view *cert)
{
    CBS san, names, name;
    unsigned int tag;

    if (!CBS_get_asn1_element(value, &cert->san, CBS_ASN1_SEQUENCE))
        return 0;
    if (CBS_len(value) != 0)
        return 0;

    cert->san_count = 0;
    CBS_dup(&cert->san, &san);
    if (!CBS_get_asn1(&san, &names, CBS_ASN1_SEQUENCE))
        return 0;
    while (CBS_len(&names) > 0) {
        if (!get_general_name(&names, &tag, &name))
            return 0;
        cert->san_count++;
    }

    cert->has_san = 1;

    return 1;
}

static int parse_subject_key_id(CBS *value, struct x509_view *cert)
{
    if (!CBS_get_asn1_element(value, &cert->skid, CBS_ASN1_OCTETSTRING))
        return 0;
    if (CBS_len(value) != 0)
        return 0;

    cert->has_skid = 1;

    return 1;
}

static int parse_authority_key_id(CBS *value, struct x509_view *cert)
{
    CBS seq, keyid, issuer, serial;
    int has_keyid, has_issuer, has_serial;

    if (!CBS_get_asn1(value, &seq, CBS_ASN1_SEQUENCE))
        return 0;
    if (!get_optional_element(&seq, &keyid, &has_keyid,
            CBS_ASN1_CONTEXT_SPECIFIC | 0))
        return 0;
    if (!get_optional_element(&seq, &issuer, &has_issuer,
            CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 1))
        return 0;
    if (!get_optional_element(&seq, &serial, &has_serial,
            CBS_ASN1_CONTEXT_SPECIFIC | 2))
        return 0;
    if (CBS_len(&seq) != 0 || CBS_len(value) != 0)
        return 0;

    if (has_keyid)
        CBS_dup(&keyid, &cert->akid_keyid);
    if (has_issuer)
        CBS_dup(&issuer, &cert->akid_issuer);
    if (has_serial)
        CBS_dup(&serial, &cert->akid_serial);
    cert->has_akid_keyid = has_keyid;
    cert->has_akid_issuer = has_issuer;
    cert->has_akid_serial = has_serial;
    cert->has_akid = 1;

    return 1;
}

/*
 * A GeneralSubtrees under the given tag, if one is next: a SEQUENCE OF
 * GeneralSubtree, each a GeneralName with optional [0] minimum and [1]
 * maximum.  Only the framing is checked.
 */
static int get_optional_general_subtrees(CBS *cbs, unsigned int tag)
{
    CBS subtrees, subtree, name, bound;
    unsigned int name_tag;
    int present;

    if (!CBS_get_optional_asn1(cbs, &subtrees, &present,
            tag | CBS_ASN1_CONSTRUCTED))
        return 0;
    if (!present)
        return 1;
    while (CBS_len(&subtrees) > 0) {
        if (!CBS_get_asn1(&subtrees, &subtree, CBS_ASN1_SEQUENCE))
            return 0;
        if (!get_general_name(&subtree, &name_tag, &name))
            return 0;
        if (!CBS_get_optional_asn1(&subtree, &bound, &present,
                CBS_ASN1_CONTEXT_SPECIFIC | 0))
            return 0;
        if (!CBS_get_optional_asn1(&subtree, &bound, &present,
                CBS_ASN1_CONTEXT_SPECIFIC | 1))
            return 0;
        if (CBS_len(&subtree) != 0)
            return 0;
    }

    return 1;
}

/* The NameConstraints is kept whole, with its header. */
static int parse_name_constraints(CBS *value, struct x509_view *cert)
{
    CBS element, seq;

    if (!CBS_get_asn1_element(value, &cert->nc, CBS_ASN1_SEQUENCE))
        return 0;
    if (CBS_len(value) != 0)
        return 0;
    CBS_dup(&cert->nc, &element);
    if (!CBS_get_asn1(&element, &seq, CBS_ASN1_SEQUENCE))
        return 0;
    if (!get_optional_general_subtrees(&seq, CBS_ASN1_CONTEXT_SPECIFIC | 0))
        return 0;
    if (!get_optional_general_subtrees(&seq, CBS_ASN1_CONTEXT_SPECIFIC | 1))
        return 0;
    if (CBS_len(&seq) != 0)
        return 0;

    cert->has_nc = 1;

    return 1;
}

static const struct {
    const uint8_t *oid;
    size_t oid_len;
    int (*parse)(CBS *value, struct x509_view *cert);
    uint32_t present;
} extensions[] = {
    { oid_basic_constraints, sizeof(oid_basic_constraints),
        parse_basic_constraints, 0 },
    { oid_key_usage, sizeof(oid_key_usage), parse_key_usage, 0 },
    { oid_ext_key_usage, sizeof(oid_ext_key_usage), parse_ext_key_usage, 0 },
    { oid_subject_alt_name, sizeof(oid_subject_alt_name),
        parse_subject_alt_name, 0 },
    { oid_subject_key_id, sizeof(oid_subject_key_id), parse_subject_key_id,
        0 },
    { oid_authority_key_id, sizeof(oid_authority_key_id),
        parse_authority_key_id, 0 },
    { oid_name_constraints, sizeof(oid_name_constraints),
        parse_name_constraints, X509_VIEW_EXT_NAME_CONSTRAINTS },
    { oid_certificate_policies, sizeof(oid_certificate_policies), NULL,
        X509_VIEW_EXT_CERTIFICATE_POLICIES },
    { oid_policy_mappings, sizeof(oid_policy_mappings), NULL,
        X509_VIEW_EXT_POLICY_MAPPINGS },
    { oid_policy_constraints, sizeof(oid_policy_constraints), NULL,
        X509_VIEW_EXT_POLICY_CONSTRAINTS },
    { oid_inhibit_any_policy, sizeof(oid_inhibit_any_policy), NULL,
        X509_VIEW_EXT_INHIBIT_ANY_POLICY },
    { oid_ip_addr_blocks, sizeof(oid_ip_addr_blocks), NULL,
        X509_VIEW_EXT_IP_ADDR_BLOCKS },
    { oid_autonomous_sys_ids, sizeof(oid_autonomous_sys_ids), NULL,
        X509_VIEW_EXT_AUTONOMOUS_SYS_IDS }
};

/* Splits an Extension into its OID, critical flag and extnValue octets. */
static int get_extension(CBS *cbs, CBS *out_oid, int *out_critical,
    CBS *out_value)
{
    CBS ext;

    if (!CBS_get_asn1(cbs, &ext, CBS_ASN1_SEQUENCE))
        return 0;
    if (!CBS_get_asn1(&ext, out_oid, CBS_ASN1_OBJECT))
        return 0;
    if (CBS_len(out_oid) == 0)
        return 0;
    if (!get_optional_bool(&ext, out_critical))
        return 0;
    if (!CBS_get_asn1(&ext, out_value, CBS_ASN1_OCTETSTRING))
        return 0;

    return CBS_len(&ext) == 0;
}

/*
 * The number of extensions in exts carrying oid.  Counting stops at the
 * first extension get_extension cannot read, which parse_extensions
 * rejects on reaching it.
 */
static size_t count_extension(const CBS *exts, const CBS *oid)
{
    CBS cbs, ext_oid, value;
    int critical;
    size_t count = 0;

    CBS_dup(exts, &cbs);
    while (get_extension(&cbs, &ext_oid, &critical, &value)) {
        if (cbs_equals(&ext_oid, CBS_data(oid), CBS_len(oid)))
            count++;
    }

    return count;
}

/*
 * An empty Extensions, an extension whose OID occurs more than once and
 * a handled extension that does not parse set has_malformed_extension;
 * the fields the extension would set stay absent.
 */
static int parse_extensions(CBS *exts, struct x509_view *cert)
{
    CBS all, oid, value;
    int critical;
    size_t i;

    if (CBS_len(exts) == 0)
        cert->has_malformed_extension = 1;

    CBS_dup(exts, &all);
    while (CBS_len(exts) > 0) {
        if (!get_extension(exts, &oid, &critical, &value))
            return 0;

        for (i = 0; i < OSSL_NELEM(extensions); i++) {
            if (cbs_equals(&oid, extensions[i].oid, extensions[i].oid_len))
                break;
        }
        if (i < OSSL_NELEM(extensions))
            cert->extensions_present |= extensions[i].present;
        if (i == OSSL_NELEM(extensions) && critical)
            cert->has_unhandled_critical = 1;
        if (count_extension(&all, &oid) > 1) {
            cert->has_malformed_extension = 1;
            continue;
        }
        if (i < OSSL_NELEM(extensions) && extensions[i].parse != NULL
            && !extensions[i].parse(&value, cert))
            cert->has_malformed_extension = 1;
    }

    return 1;
}

/*
 * Reads an optional UniqueIdentifier, an IMPLICIT BIT STRING under tag,
 * into *out.  A v1 certificate has none (RFC 5280 4.1.2.8).
 */
static int get_optional_unique_id(CBS *cbs, int version, unsigned int tag,
    CBS *out, int *out_present)
{
    CBS element, bits;
    uint8_t unused;

    if (!get_optional_element(cbs, out, out_present, tag))
        return 0;
    if (!*out_present)
        return 1;
    if (version == X509_VIEW_V1)
        return 0;
    CBS_dup(out, &element);
    if (!CBS_get_asn1(&element, &bits, tag))
        return 0;
    if (!CBS_get_u8(&bits, &unused))
        return 0;
    if (unused > 7 || (CBS_len(&bits) == 0 && unused != 0))
        return 0;

    return 1;
}

/*
 * Reads a UTCTime or GeneralizedTime element into *out and its POSIX time
 * into *out_posix_time.
 */
static int get_time(CBS *cbs, CBS *out, int64_t *out_posix_time)
{
    CBS asn1_time, contents;
    struct tm tm;
    unsigned int tag;

    if (CBS_peek_asn1_tag(cbs, CBS_ASN1_UTCTIME))
        tag = CBS_ASN1_UTCTIME;
    else if (CBS_peek_asn1_tag(cbs, CBS_ASN1_GENERALIZEDTIME))
        tag = CBS_ASN1_GENERALIZEDTIME;
    else
        return 0;
    if (!CBS_get_asn1_element(cbs, out, tag))
        return 0;
    CBS_dup(out, &asn1_time);
    if (!CBS_get_asn1(&asn1_time, &contents, tag))
        return 0;
    if (!ossl_asn1_time_parse_cbs(&contents, tag == CBS_ASN1_GENERALIZEDTIME,
            &tm))
        return 0;

    return OPENSSL_tm_to_posix(&tm, out_posix_time);
}

/*
 * Whether oid is the content octets of a valid OBJECT IDENTIFIER: one or
 * more subidentifiers, each in minimal base 128 (X.690 8.19.2).
 */
static int oid_is_valid(const CBS *oid)
{
    const uint8_t *data = CBS_data(oid);
    size_t i, len = CBS_len(oid);
    int start = 1;

    if (len == 0 || len > INT_MAX || (data[len - 1] & 0x80) != 0)
        return 0;
    for (i = 0; i < len; i++) {
        if (start && data[i] == 0x80)
            return 0;
        start = (data[i] & 0x80) == 0;
    }

    return 1;
}

/* The NID of an AlgorithmIdentifier's algorithm, NID_undef if unknown. */
static int sig_alg_nid(const CBS *sig_alg, int *out_nid)
{
    CBS element, seq, oid;

    CBS_dup(sig_alg, &element);
    if (!CBS_get_asn1(&element, &seq, CBS_ASN1_SEQUENCE))
        return 0;
    if (!CBS_get_asn1(&seq, &oid, CBS_ASN1_OBJECT))
        return 0;
    if (!oid_is_valid(&oid))
        return 0;
    *out_nid = ossl_obj_cbs2nid(&oid);

    return 1;
}

int x509_view_parse(const uint8_t *der, size_t der_len, struct x509_view *cert)
{
    CBS cbs, certificate, tbs_element, tbs, version, serial, validity,
        exts_element, exts_seq, exts;
    uint64_t v;
    int present;

    memset(cert, 0, sizeof(*cert));

    CBS_init(&cbs, der, der_len);
    if (!CBS_get_asn1(&cbs, &certificate, CBS_ASN1_SEQUENCE))
        return 0;
    if (CBS_len(&cbs) != 0)
        return 0;

    if (!CBS_get_asn1_element(&certificate, &cert->tbs, CBS_ASN1_SEQUENCE))
        return 0;
    CBS_dup(&cert->tbs, &tbs_element);
    if (!CBS_get_asn1(&tbs_element, &tbs, CBS_ASN1_SEQUENCE))
        return 0;

    /* An encoded v1 is not DER, which omits a DEFAULT value. */
    cert->version = X509_VIEW_V1;
    if (!CBS_get_optional_asn1(&tbs, &version, &present,
            CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0))
        return 0;
    if (present) {
        if (!CBS_get_asn1_uint64(&version, &v))
            return 0;
        if (v != X509_VIEW_V2 && v != X509_VIEW_V3)
            return 0;
        if (CBS_len(&version) != 0)
            return 0;
        cert->version = (int)v;
    }
    if (!get_integer(&tbs, &cert->serial, &serial))
        return 0;
    if (!CBS_get_asn1_element(&tbs, &cert->inner_sig_alg, CBS_ASN1_SEQUENCE))
        return 0;
    if (!CBS_get_asn1_element(&tbs, &cert->issuer, CBS_ASN1_SEQUENCE))
        return 0;
    if (!CBS_get_asn1(&tbs, &validity, CBS_ASN1_SEQUENCE))
        return 0;
    if (!get_time(&validity, &cert->not_before, &cert->not_before_posix))
        return 0;
    if (!get_time(&validity, &cert->not_after, &cert->not_after_posix))
        return 0;
    if (CBS_len(&validity) != 0)
        return 0;
    if (!CBS_get_asn1_element(&tbs, &cert->subject, CBS_ASN1_SEQUENCE))
        return 0;
    cert->self_issued = CBS_mem_equal(&cert->issuer, CBS_data(&cert->subject),
        CBS_len(&cert->subject));
    if (!CBS_get_asn1_element(&tbs, &cert->spki, CBS_ASN1_SEQUENCE))
        return 0;
    if (!get_optional_unique_id(&tbs, cert->version,
            CBS_ASN1_CONTEXT_SPECIFIC | 1, &cert->issuer_uid,
            &cert->has_issuer_uid))
        return 0;
    if (!get_optional_unique_id(&tbs, cert->version,
            CBS_ASN1_CONTEXT_SPECIFIC | 2, &cert->subject_uid,
            &cert->has_subject_uid))
        return 0;
    if (!CBS_get_optional_asn1(&tbs, &exts_element, &present,
            CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 3))
        return 0;
    if (present) {
        if (cert->version != X509_VIEW_V3)
            return 0;
        if (!CBS_get_asn1_element(&exts_element, &cert->extensions,
                CBS_ASN1_SEQUENCE))
            return 0;
        if (CBS_len(&exts_element) != 0)
            return 0;
        CBS_dup(&cert->extensions, &exts_seq);
        if (!CBS_get_asn1(&exts_seq, &exts, CBS_ASN1_SEQUENCE))
            return 0;
        if (!parse_extensions(&exts, cert))
            return 0;
    }
    if (CBS_len(&tbs) != 0)
        return 0;

    if (!CBS_get_asn1_element(&certificate, &cert->sig_alg, CBS_ASN1_SEQUENCE))
        return 0;
    cert->sig_alg_matches = CBS_mem_equal(&cert->sig_alg,
        CBS_data(&cert->inner_sig_alg), CBS_len(&cert->inner_sig_alg));
    if (!sig_alg_nid(&cert->sig_alg, &cert->sig_nid))
        return 0;
    if (!get_bit_string(&certificate, &cert->signature))
        return 0;

    return CBS_len(&certificate) == 0;
}

int x509_view_get_tbs(const struct x509_view *view, CBS *out)
{
    CBS_dup(&view->tbs, out);

    return 1;
}

int x509_view_get_serial(const struct x509_view *view, CBS *out)
{
    CBS_dup(&view->serial, out);

    return 1;
}

int x509_view_get_tbs_sig_alg(const struct x509_view *view, CBS *out)
{
    CBS_dup(&view->inner_sig_alg, out);

    return 1;
}

int x509_view_get_issuer(const struct x509_view *view, CBS *out)
{
    CBS_dup(&view->issuer, out);

    return 1;
}

int x509_view_get_not_before(const struct x509_view *view, CBS *out)
{
    CBS_dup(&view->not_before, out);

    return 1;
}

int x509_view_get_not_after(const struct x509_view *view, CBS *out)
{
    CBS_dup(&view->not_after, out);

    return 1;
}

int x509_view_get_subject(const struct x509_view *view, CBS *out)
{
    CBS_dup(&view->subject, out);

    return 1;
}

int x509_view_get_spki(const struct x509_view *view, CBS *out)
{
    CBS_dup(&view->spki, out);

    return 1;
}

int x509_view_get_sig_alg(const struct x509_view *view, CBS *out)
{
    CBS_dup(&view->sig_alg, out);

    return 1;
}

int x509_view_get_signature(const struct x509_view *view, CBS *out)
{
    CBS_dup(&view->signature, out);

    return 1;
}

int x509_view_get_issuer_uid(const struct x509_view *view, CBS *out)
{
    if (!view->has_issuer_uid)
        return 0;
    CBS_dup(&view->issuer_uid, out);

    return 1;
}

int x509_view_get_subject_uid(const struct x509_view *view, CBS *out)
{
    if (!view->has_subject_uid)
        return 0;
    CBS_dup(&view->subject_uid, out);

    return 1;
}

int x509_view_get_san(const struct x509_view *view, CBS *out)
{
    if (!view->has_san)
        return 0;
    CBS_dup(&view->san, out);

    return 1;
}

int64_t x509_view_not_before_posix(const struct x509_view *view)
{
    return view->not_before_posix;
}

int64_t x509_view_not_after_posix(const struct x509_view *view)
{
    return view->not_after_posix;
}

int x509_view_sig_nid(const struct x509_view *view)
{
    return view->sig_nid;
}

int x509_view_version(const struct x509_view *view)
{
    return view->version;
}

int x509_view_sig_algs_match(const struct x509_view *view)
{
    return view->sig_alg_matches;
}

int x509_view_is_self_issued(const struct x509_view *view)
{
    return view->self_issued;
}

int x509_view_key_usage(const struct x509_view *view, uint32_t *out)
{
    if (!view->has_key_usage)
        return 0;
    *out = view->key_usage;

    return 1;
}

int x509_view_ext_key_usage(const struct x509_view *view, uint32_t *out)
{
    if (!view->has_ext_key_usage)
        return 0;
    *out = view->ext_key_usage;

    return 1;
}

int x509_view_is_ca(const struct x509_view *view)
{
    return view->has_basic_constraints && view->ca;
}

int x509_view_path_len(const struct x509_view *view, int64_t *out)
{
    if (!view->has_basic_constraints || view->path_len < 0)
        return 0;
    *out = view->path_len;

    return 1;
}

int x509_view_has_unhandled_critical(const struct x509_view *view)
{
    return view->has_unhandled_critical;
}

uint32_t x509_view_extensions_present(const struct x509_view *view,
    uint32_t mask)
{
    return view->extensions_present & mask;
}

int x509_view_has_malformed_extension(const struct x509_view *view)
{
    return view->has_malformed_extension;
}

int x509_view_get_skid(const struct x509_view *view, CBS *out)
{
    if (!view->has_skid)
        return 0;
    CBS_dup(&view->skid, out);

    return 1;
}

int x509_view_get_akid_keyid(const struct x509_view *view, CBS *out)
{
    if (!view->has_akid_keyid)
        return 0;
    CBS_dup(&view->akid_keyid, out);

    return 1;
}

int x509_view_get_akid_issuer(const struct x509_view *view, CBS *out)
{
    if (!view->has_akid_issuer)
        return 0;
    CBS_dup(&view->akid_issuer, out);

    return 1;
}

int x509_view_get_akid_serial(const struct x509_view *view, CBS *out)
{
    if (!view->has_akid_serial)
        return 0;
    CBS_dup(&view->akid_serial, out);

    return 1;
}

int x509_view_get_name_constraints(const struct x509_view *view, CBS *out)
{
    if (!view->has_nc)
        return 0;
    CBS_dup(&view->nc, out);

    return 1;
}

int x509_view_get_extensions(const struct x509_view *view, CBS *out)
{
    CBS_dup(&view->extensions, out);

    return 1;
}

int x509_view_next_general_name(CBS *names, int *out_type, CBS *out)
{
    unsigned int tag;

    if (!get_general_name(names, &tag, out))
        return 0;
    *out_type = (int)(tag & ~(CLASS_MASK | CBS_ASN1_CONSTRUCTED));

    return 1;
}

int x509_view_next_extension(CBS *exts, CBS *out_oid, int *out_critical,
    CBS *out_value)
{
    return get_extension(exts, out_oid, out_critical, out_value);
}
