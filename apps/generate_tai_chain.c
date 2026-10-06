/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdint.h>
#include <string.h>

#include "apps.h"
#include "progs.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/tls1.h>

/*
 * Decorate a PEM certificate chain with a CERTIFICATE PROPERTIES block so that
 * a relying party which loads it as a trust anchor requests the trust anchor by
 * default (section 7 of
 * https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids-05/).  The
 * block encodes a CertificatePropertyList carrying a trust_anchor_id, optional
 * trust_anchor_groups, and an optional trust_anchor_negotiation marker.
 */

typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_CHAIN,
    OPT_OID,
    OPT_GROUP,
    OPT_TRUST_ANCHOR_NEGOTIATION,
    OPT_OUT
} OPTION_CHOICE;

const OPTIONS generate_tai_chain_options[] = {
    OPT_SECTION("General"),
    { "help", OPT_HELP, '-', "Display this summary" },

    OPT_SECTION("Input"),
    { "chain", OPT_CHAIN, '<',
        "PEM certificate chain to decorate; must not already carry a"
        " CERTIFICATE PROPERTIES block" },
    { "oid", OPT_OID, 's',
        "Trust anchor ID, a dotted relative object identifier (e.g. 32473.1)" },
    { "group", OPT_GROUP, 's',
        "Comma-separated trust_anchor_groups patterns, such as"
        " 32473.1.2.1.{3-}" },
    { "trust-anchor-negotiation", OPT_TRUST_ANCHOR_NEGOTIATION, '-',
        "Add the trust_anchor_negotiation property, so the chain is served"
        " only when its trust anchor was requested (off by default)" },

    OPT_SECTION("Output"),
    { "out", OPT_OUT, '>', "Output file (default stdout)" },

    { NULL }
};

/* Append len bytes at p to buf. */
static int buf_put(BUF_MEM *buf, const void *p, size_t len)
{
    size_t off = buf->length;

    if (BUF_MEM_grow(buf, off + len) == 0)
        return 0;
    memcpy(buf->data + off, p, len);
    return 1;
}

/* Append v to buf as a big-endian 16-bit integer. */
static int buf_put_u16(BUF_MEM *buf, unsigned int v)
{
    uint8_t b[2];

    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
    return buf_put(buf, b, sizeof(b));
}

/*
 * Open a length prefix of prefix_len (1 or 2) bytes, recording its offset in
 * *at for buf_close().
 */
static int buf_open(BUF_MEM *buf, size_t prefix_len, size_t *at)
{
    static const uint8_t zero[2] = { 0, 0 };

    *at = buf->length;
    return buf_put(buf, zero, prefix_len);
}

/*
 * Fill in the length prefix of prefix_len bytes at offset at with the number
 * of bytes that follow it.  Fails if that does not fit the prefix.
 */
static int buf_close(BUF_MEM *buf, size_t prefix_len, size_t at)
{
    size_t len = buf->length - at - prefix_len;

    if (len >> (8 * prefix_len) != 0)
        return 0;
    if (prefix_len == 2)
        buf->data[at++] = (char)(len >> 8);
    buf->data[at] = (char)len;
    return 1;
}

/*
 * Append the decimal integer of len bytes at text to buf in the base-128
 * encoding of a relative object identifier component.
 */
static int put_decimal(BUF_MEM *buf, const char *text, size_t len)
{
    uint8_t tmp[10], enc[10];
    uint64_t v = 0;
    size_t i, n = 0;

    if (len == 0)
        return 0;
    for (i = 0; i < len; i++) {
        if (text[i] < '0' || text[i] > '9' || v > (UINT64_MAX - 9) / 10)
            return 0;
        v = v * 10 + (uint64_t)(text[i] - '0');
    }
    do {
        tmp[n++] = (uint8_t)(v & 0x7f);
        v >>= 7;
    } while (v != 0);
    for (i = 0; i < n; i++)
        enc[i] = tmp[n - 1 - i] | (i + 1 < n ? 0x80 : 0);
    return buf_put(buf, enc, n);
}

/* Encode a dotted relative object identifier as its content octets. */
static int add_relative_oid(BUF_MEM *buf, const char *text)
{
    for (;;) {
        const char *dot = strchr(text, '.');
        size_t len = dot != NULL ? (size_t)(dot - text) : strlen(text);

        if (!put_decimal(buf, text, len))
            return 0;
        if (dot == NULL)
            return 1;
        text = dot + 1;
    }
}

/*
 * Encode a trust anchor ID pattern from its text representation, dot-separated
 * components each "n", "{min-max}" or "{min-}" (section 5.3.1 of
 * https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids-05/).
 */
static int add_pattern(BUF_MEM *buf, const char *text)
{
    static const uint8_t infinity = 0x80;
    const char *p = text;

    for (;;) {
        const char *dot = strchr(p, '.');
        size_t len = dot != NULL ? (size_t)(dot - p) : strlen(p);
        const char *dash;

        if (len >= 2 && p[0] == '{' && p[len - 1] == '}') {
            if ((dash = memchr(p + 1, '-', len - 2)) == NULL
                || !put_decimal(buf, p + 1, dash - (p + 1)))
                return 0;
            if (dash + 1 == p + len - 1) {
                /* An empty max is infinity, the single byte 0x80. */
                if (!buf_put(buf, &infinity, 1))
                    return 0;
            } else if (!put_decimal(buf, dash + 1, p + len - 1 - (dash + 1))) {
                return 0;
            }
        } else if (!put_decimal(buf, p, len) || !put_decimal(buf, p, len)) {
            return 0;
        }
        if (dot == NULL)
            return 1;
        p = dot + 1;
    }
}

/*
 * Encode the trust_anchor_groups list from a mutable, comma-separated list of
 * patterns.  The string is modified in place while tokenising.
 */
static int add_groups(BUF_MEM *buf, char *group)
{
    char *p = group;

    while (p != NULL && *p != '\0') {
        char *comma = strchr(p, ',');
        char *tok, *end;
        size_t at;

        if (comma != NULL)
            *comma = '\0';

        /* Trim surrounding whitespace. */
        tok = p;
        while (*tok == ' ' || *tok == '\t')
            tok++;
        end = tok + strlen(tok);
        while (end > tok && (end[-1] == ' ' || end[-1] == '\t'))
            *--end = '\0';

        if (!buf_open(buf, 1, &at)
            || !add_pattern(buf, tok)
            || !buf_close(buf, 1, at))
            return 0;

        p = (comma != NULL) ? comma + 1 : NULL;
    }
    return 1;
}

/*
 * Build a CertificatePropertyList into buf: a trust_anchor_id property, then
 * any trust_anchor_groups, then trust_anchor_negotiation.  Properties are
 * ordered by type.  group is modified in place and may be NULL.
 */
static int build_properties(BUF_MEM *buf, size_t *out_len, const char *oid,
    char *group, int negotiation)
{
    size_t list, data, groups;

    /* trust_anchor_id (type 0) */
    if (!buf_open(buf, 2, &list)
        || !buf_put_u16(buf, 0)
        || !buf_open(buf, 2, &data)
        || !add_relative_oid(buf, oid)
        || buf->length - data - 2 > TLSEXT_TRUST_ANCHOR_ID_MAX_LEN
        || !buf_close(buf, 2, data))
        return 0;

    /* trust_anchor_groups (type 1) */
    if (group != NULL
        && (!buf_put_u16(buf, 1)
            || !buf_open(buf, 2, &data)
            || !buf_open(buf, 2, &groups)
            || !add_groups(buf, group)
            || !buf_close(buf, 2, groups)
            || !buf_close(buf, 2, data)))
        return 0;

    /* trust_anchor_negotiation (type 2), empty data */
    if (negotiation
        && (!buf_put_u16(buf, 2)
            || !buf_open(buf, 2, &data)
            || !buf_close(buf, 2, data)))
        return 0;

    if (!buf_close(buf, 2, list))
        return 0;
    *out_len = buf->length;
    return 1;
}

int generate_tai_chain_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *certs = NULL;
    BUF_MEM *props = NULL;
    char *chainfile = NULL, *oid = NULL, *group = NULL, *groupdup = NULL;
    char *outfile = NULL, *prog, *certdata = NULL;
    int negotiation = 0, ncerts = 0, has_props = 0, failed = 0;
    size_t propslen = 0;
    long certlen;
    OPTION_CHOICE o;
    int ret = 1;

    prog = opt_init(argc, argv, generate_tai_chain_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
        opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(generate_tai_chain_options);
            goto end;
        case OPT_CHAIN:
            chainfile = opt_arg();
            break;
        case OPT_OID:
            oid = opt_arg();
            break;
        case OPT_GROUP:
            group = opt_arg();
            break;
        case OPT_TRUST_ANCHOR_NEGOTIATION:
            negotiation = 1;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        }
    }

    if (!opt_check_rest_arg(NULL))
        goto opthelp;
    if (chainfile == NULL || oid == NULL) {
        BIO_printf(bio_err, "%s: -chain and -oid are required\n", prog);
        goto opthelp;
    }

    /* Read the chain, collecting its certificates and rejecting properties. */
    in = bio_open_default(chainfile, 'r', FORMAT_PEM);
    if (in == NULL)
        goto end;
    certs = BIO_new(BIO_s_mem());
    if (certs == NULL)
        goto end;
    for (;;) {
        char *name = NULL, *header = NULL;
        unsigned char *data = NULL;
        long len = 0;

        if (!PEM_read_bio(in, &name, &header, &data, &len)) {
            unsigned long e = ERR_peek_last_error();

            if (ncerts > 0 && ERR_GET_LIB(e) == ERR_LIB_PEM
                && ERR_GET_REASON(e) == PEM_R_NO_START_LINE)
                ERR_clear_error();
            else
                failed = 1;
            break;
        }
        if (strcmp(name, "CERTIFICATE PROPERTIES") == 0)
            has_props = 1;
        else if (strcmp(name, "CERTIFICATE") == 0
            && PEM_write_bio(certs, "CERTIFICATE", "", data, len))
            ncerts++;
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
        if (has_props)
            break;
    }
    if (has_props) {
        BIO_printf(bio_err,
            "%s: input chain already has a CERTIFICATE PROPERTIES block\n",
            prog);
        goto end;
    }
    if (failed || ncerts == 0) {
        BIO_printf(bio_err, "%s: no certificates read from %s\n", prog,
            chainfile);
        ERR_print_errors(bio_err);
        goto end;
    }

    /* Build the CertificatePropertyList. */
    if (group != NULL && (groupdup = OPENSSL_strdup(group)) == NULL)
        goto end;
    props = BUF_MEM_new();
    if (props == NULL
        || !build_properties(props, &propslen, oid, groupdup, negotiation)) {
        BIO_printf(bio_err, "%s: could not encode certificate properties\n",
            prog);
        goto end;
    }

    /* Write the properties block, then the certificates. */
    out = bio_open_default(outfile, 'w', FORMAT_PEM);
    if (out == NULL)
        goto end;
    certlen = BIO_get_mem_data(certs, &certdata);
    if (!PEM_write_bio(out, "CERTIFICATE PROPERTIES", "",
            (unsigned char *)props->data, (long)propslen)
        || BIO_write(out, certdata, (int)certlen) != (int)certlen) {
        BIO_printf(bio_err, "%s: error writing output\n", prog);
        goto end;
    }
    ret = 0;
end:
    OPENSSL_free(groupdup);
    BUF_MEM_free(props);
    BIO_free(certs);
    BIO_free(in);
    BIO_free_all(out);
    return ret;
}
