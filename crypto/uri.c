/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Parsing of URIs as specified in RFC 3986.
 *
 * Parsing has two phases. The URI is first split into its components at
 * the delimiters ":", "//", "@", "[", "]", "?" and "#", which RFC 3986
 * Appendix B shows is unambiguous. Each component is then checked against
 * its ABNF rule from RFC 3986 Appendix A.
 *
 * This file is compiled into both libcrypto and libapps, so it uses only
 * the public libcrypto API and the inline PACKET functions.
 */

#include <string.h>
#include "internal/uri.h"

static int is_alpha(unsigned int c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static int is_digit(unsigned int c)
{
    return c >= '0' && c <= '9';
}

static int is_hexdig(unsigned int c)
{
    return is_digit(c) || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

static int is_unreserved(unsigned int c)
{
    return is_alpha(c) || is_digit(c) || c == '-' || c == '.' || c == '_'
        || c == '~';
}

static int is_sub_delim(unsigned int c)
{
    switch (c) {
    case '!':
    case '$':
    case '&':
    case '\'':
    case '(':
    case ')':
    case '*':
    case '+':
    case ',':
    case ';':
    case '=':
        return 1;
    default:
        return 0;
    }
}

static int is_userinfo_char(unsigned int c)
{
    return is_unreserved(c) || is_sub_delim(c) || c == ':';
}

static int is_reg_name_char(unsigned int c)
{
    return is_unreserved(c) || is_sub_delim(c);
}

static int is_path_char(unsigned int c)
{
    return is_unreserved(c) || is_sub_delim(c) || c == ':' || c == '@'
        || c == '/';
}

static int is_query_char(unsigned int c)
{
    return is_path_char(c) || c == '?';
}

static int is_scheme_end(unsigned int c)
{
    return c == ':' || c == '/' || c == '?' || c == '#';
}

static int is_authority_end(unsigned int c)
{
    return c == '/' || c == '?' || c == '#';
}

static int is_path_end(unsigned int c)
{
    return c == '?' || c == '#';
}

/*-
 * Take the bytes of pkt before the first byte for which is_end is true.
 * That byte, if any, remains in pkt.
 */
static int packet_get_until(PACKET *pkt, int (*is_end)(unsigned int c),
    PACKET *out)
{
    const uint8_t *data = PACKET_data(pkt);
    size_t len = PACKET_remaining(pkt);
    size_t i;

    for (i = 0; i < len && !is_end(data[i]); i++)
        ;
    return PACKET_get_sub_packet(pkt, out, i);
}

/*-
 * Take the bytes of pkt before the first byte equal to end.
 * That byte, if any, remains in pkt.
 */
static int packet_get_until_byte(PACKET *pkt, uint8_t end, PACKET *out)
{
    const uint8_t *data = PACKET_data(pkt);
    size_t len = PACKET_remaining(pkt);
    size_t i;

    for (i = 0; i < len && data[i] != end; i++)
        ;
    return PACKET_get_sub_packet(pkt, out, i);
}

/* Consume c if it is the next byte of pkt. */
static int packet_skip_byte(PACKET *pkt, unsigned int c)
{
    unsigned int next;

    return PACKET_peek_1(pkt, &next) && next == c && PACKET_forward(pkt, 1);
}

/*-
 * Check that pkt consists of allowed characters and pct-encoded
 * octets.
 * pct-encoded = "%" HEXDIG HEXDIG
 */
static int packet_is_pct_valid(const PACKET *pkt,
    int (*is_allowed)(unsigned int c))
{
    PACKET tmp = *pkt;
    unsigned int c, hi, lo;

    while (PACKET_get_1(&tmp, &c)) {
        if (c == '%') {
            if (!PACKET_get_1(&tmp, &hi) || !PACKET_get_1(&tmp, &lo)
                || !is_hexdig(hi) || !is_hexdig(lo))
                return 0;
        } else if (!is_allowed(c)) {
            return 0;
        }
    }
    return 1;
}

/* scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) */
static int packet_is_scheme(const PACKET *pkt)
{
    PACKET tmp = *pkt;
    unsigned int c;

    if (!PACKET_get_1(&tmp, &c) || !is_alpha(c))
        return 0;
    while (PACKET_get_1(&tmp, &c)) {
        if (!is_alpha(c) && !is_digit(c) && c != '+' && c != '-' && c != '.')
            return 0;
    }
    return 1;
}

/*-
 * dec-octet = DIGIT / %x31-39 DIGIT / "1" 2DIGIT / "2" %x30-34 DIGIT
 *           / "25" %x30-35
 * which is a decimal number from 0 to 255 with no leading zero.
 */
static int packet_is_dec_octet(const PACKET *pkt)
{
    PACKET tmp = *pkt;
    size_t len = PACKET_remaining(pkt);
    unsigned int c, value = 0;

    if (len == 0 || len > 3)
        return 0;
    if (len > 1 && *PACKET_data(pkt) == '0')
        return 0;
    while (PACKET_get_1(&tmp, &c)) {
        if (!is_digit(c))
            return 0;
        value = value * 10 + (c - '0');
    }
    return value <= 255;
}

/* IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet */
static int packet_is_ipv4(const PACKET *pkt)
{
    PACKET tmp = *pkt, octet;
    int i;

    for (i = 0; i < 4; i++) {
        if (i > 0 && !packet_skip_byte(&tmp, '.'))
            return 0;
        if (!packet_get_until_byte(&tmp, '.', &octet)
            || !packet_is_dec_octet(&octet))
            return 0;
    }
    return PACKET_remaining(&tmp) == 0;
}

/* h16 = 1*4HEXDIG */
static int packet_is_h16(const PACKET *pkt)
{
    PACKET tmp = *pkt;
    unsigned int c;

    if (PACKET_remaining(pkt) == 0 || PACKET_remaining(pkt) > 4)
        return 0;
    while (PACKET_get_1(&tmp, &c)) {
        if (!is_hexdig(c))
            return 0;
    }
    return 1;
}

/*-
 * Check one side of the optional "::" in an IPv6 address.
 * The side is empty, or a list of h16 separated by ":", of which the last
 * may be an IPv4address when ipv4_ok is set. *group_count is the number
 * of 16-bit groups, an IPv4address counting as two.
 */
static int packet_ipv6_groups(const PACKET *pkt, int ipv4_ok,
    size_t *group_count)
{
    PACKET tmp = *pkt, group;

    *group_count = 0;
    if (PACKET_remaining(&tmp) == 0)
        return 1;
    for (;;) {
        if (!packet_get_until_byte(&tmp, ':', &group))
            return 0;
        if (ipv4_ok && PACKET_remaining(&tmp) == 0
            && packet_is_ipv4(&group)) {
            *group_count += 2;
            return 1;
        }
        if (!packet_is_h16(&group))
            return 0;
        (*group_count)++;
        if (PACKET_remaining(&tmp) == 0)
            return 1;
        if (!packet_skip_byte(&tmp, ':') || PACKET_remaining(&tmp) == 0)
            return 0;
    }
}

/*-
 * IPv6address is eight 16-bit groups written as h16 separated by ":",
 * where the last two groups may be written as an IPv4address, and one
 * run of one or more groups may be elided as "::" (RFC 3986 section
 * 3.2.2).
 */
static int packet_is_ipv6(const PACKET *pkt)
{
    const uint8_t *data = PACKET_data(pkt);
    size_t len = PACKET_remaining(pkt);
    size_t i, left_count, right_count;
    PACKET left, right;

    for (i = 0; i + 1 < len; i++) {
        if (data[i] == ':' && data[i + 1] == ':')
            break;
    }
    if (i + 1 >= len)
        return packet_ipv6_groups(pkt, 1, &right_count) && right_count == 8;

    if (!PACKET_buf_init(&left, data, i)
        || !PACKET_buf_init(&right, data + i + 2, len - i - 2))
        return 0;
    return packet_ipv6_groups(&left, 0, &left_count)
        && packet_ipv6_groups(&right, 1, &right_count)
        && left_count + right_count <= 7;
}

/*-
 * port = *DIGIT, limited here to at most 65535. *port_num is -1 for an
 * empty port.
 */
static int packet_get_port(const PACKET *pkt, int *port_num)
{
    PACKET tmp = *pkt;
    unsigned int c;
    int value = 0;

    *port_num = -1;
    if (PACKET_remaining(&tmp) == 0)
        return 1;
    while (PACKET_get_1(&tmp, &c)) {
        if (!is_digit(c))
            return 0;
        value = value * 10 + (int)(c - '0');
        if (value > 65535)
            return 0;
    }
    *port_num = value;
    return 1;
}

/*-
 * Parse an authority into its userinfo, host and port.
 * authority = [ userinfo "@" ] host [ ":" port ]
 * host      = IP-literal / IPv4address / reg-name
 * IP-literal = "[" IPv6address "]"
 */
static int uri_parse_authority(PACKET *pkt, OSSL_URI *uri)
{
    PACKET rest = *pkt, userinfo;

    /* userinfo does not contain "@", so the first "@" ends it */
    if (!packet_get_until_byte(&rest, '@', &userinfo))
        return 0;
    if (packet_skip_byte(&rest, '@')) {
        if (!packet_is_pct_valid(&userinfo, is_userinfo_char))
            return 0;
        uri->has_userinfo = 1;
        uri->userinfo = userinfo;
        *pkt = rest;
    }

    if (packet_skip_byte(pkt, '[')) {
        if (!packet_get_until_byte(pkt, ']', &uri->host)
            || !packet_skip_byte(pkt, ']'))
            return 0;
        if (!packet_is_ipv6(&uri->host))
            return 0;
        uri->host_type = OSSL_URI_HOST_IPV6;
    } else {
        if (!packet_get_until_byte(pkt, ':', &uri->host)
            || !packet_is_pct_valid(&uri->host, is_reg_name_char))
            return 0;
        if (packet_is_ipv4(&uri->host))
            uri->host_type = OSSL_URI_HOST_IPV4;
        else
            uri->host_type = OSSL_URI_HOST_REG_NAME;
    }

    if (packet_skip_byte(pkt, ':')) {
        uri->has_port = 1;
        if (!PACKET_get_sub_packet(pkt, &uri->port, PACKET_remaining(pkt))
            || !packet_get_port(&uri->port, &uri->port_num))
            return 0;
    }

    return PACKET_remaining(pkt) == 0;
}

int ossl_uri_parse(const uint8_t *buf, size_t buf_len, OSSL_URI *uri)
{
    PACKET pkt, after_slashes, authority;

    memset(uri, 0, sizeof(*uri));
    uri->port_num = -1;

    if (!PACKET_buf_init(&pkt, buf, buf_len))
        return 0;

    /* scheme ":" */
    if (!packet_get_until(&pkt, is_scheme_end, &uri->scheme)
        || !packet_is_scheme(&uri->scheme)
        || !packet_skip_byte(&pkt, ':'))
        return 0;

    /* [ "//" authority ] */
    after_slashes = pkt;
    if (packet_skip_byte(&after_slashes, '/')
        && packet_skip_byte(&after_slashes, '/')) {
        pkt = after_slashes;
        if (!packet_get_until(&pkt, is_authority_end, &authority)
            || !uri_parse_authority(&authority, uri))
            return 0;
        uri->has_authority = 1;
    }

    /* path */
    if (!packet_get_until(&pkt, is_path_end, &uri->path)
        || !packet_is_pct_valid(&uri->path, is_path_char))
        return 0;

    /* [ "?" query ] */
    if (packet_skip_byte(&pkt, '?')) {
        uri->has_query = 1;
        if (!packet_get_until_byte(&pkt, '#', &uri->query)
            || !packet_is_pct_valid(&uri->query, is_query_char))
            return 0;
    }

    /* [ "#" fragment ] */
    if (packet_skip_byte(&pkt, '#')) {
        uri->has_fragment = 1;
        if (!PACKET_get_sub_packet(&pkt, &uri->fragment,
                PACKET_remaining(&pkt))
            || !packet_is_pct_valid(&uri->fragment, is_query_char))
            return 0;
    }

    return PACKET_remaining(&pkt) == 0;
}

char *ossl_uri_strdup(const PACKET *parts, size_t count)
{
    size_t i, len = 0;
    char *str, *p;

    for (i = 0; i < count; i++) {
        if (PACKET_remaining(&parts[i]) > SIZE_MAX - 1 - len)
            return NULL;
        len += PACKET_remaining(&parts[i]);
    }
    if ((str = OPENSSL_malloc(len + 1)) == NULL)
        return NULL;
    for (p = str, i = 0; i < count; i++) {
        if (PACKET_remaining(&parts[i]) > 0) {
            memcpy(p, PACKET_data(&parts[i]), PACKET_remaining(&parts[i]));
            p += PACKET_remaining(&parts[i]);
        }
    }
    *p = '\0';
    return str;
}
