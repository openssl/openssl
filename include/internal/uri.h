/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file uri.h
 * Parsing of URIs as specified in RFC 3986.
 *
 * The parser neither copies nor allocates: each component of a parsed URI
 * is a PACKET referring to the bytes of the input. Percent-encoded octets
 * are validated but not decoded.
 *
 * This file is compiled into both libcrypto and libapps, so it uses only
 * the public libcrypto API and the inline PACKET functions.
 */

#if !defined(OSSL_INTERNAL_URI_H)
#define OSSL_INTERNAL_URI_H

#include <stddef.h>
#include <stdint.h>
#include "internal/packet.h"

/** Host kinds, per RFC 3986 section 3.2.2. */
enum {
    OSSL_URI_HOST_REG_NAME, /**< reg-name, possibly empty */
    OSSL_URI_HOST_IPV4, /**< IPv4address */
    OSSL_URI_HOST_IPV6 /**< IPv6address, from within an IP-literal */
};

/**
 * @struct ossl_uri_st
 * @brief The components of a URI.
 *
 * Each PACKET covers its component without the delimiters that introduce
 * or enclose it. A component whose has_ flag is 0 is absent, and its
 * PACKET is empty.
 */
typedef struct ossl_uri_st {
    PACKET scheme; /**< scheme, without the trailing ":" */
    int has_authority; /**< 1 if a "//" authority is present */
    int has_userinfo; /**< 1 if a userinfo "@" is present */
    PACKET userinfo; /**< userinfo, without the trailing "@" */
    PACKET host; /**< host, without the "[" and "]" of an IPv6 address */
    int host_type; /**< one of the OSSL_URI_HOST_ values */
    int has_port; /**< 1 if a ":" port is present */
    PACKET port; /**< port digits, possibly empty */
    int port_num; /**< port number, or -1 if the port is absent or empty */
    PACKET path; /**< path, possibly empty */
    int has_query; /**< 1 if a "?" query is present */
    PACKET query; /**< query, without the leading "?" */
    int has_fragment; /**< 1 if a "#" fragment is present */
    PACKET fragment; /**< fragment, without the leading "#" */
} OSSL_URI;

/**
 * @brief Parse a URI as specified in RFC 3986 section 3.
 *
 * The input must be an absolute URI, with a scheme. A port must be at most
 * 65535. No error is raised on failure; the caller decides what to report.
 *
 * @param buf the URI to parse, which need not be NUL-terminated
 * @param buf_len the length of the URI in bytes
 * @param uri receives the components of the URI, which refer to buf
 * @returns 1 if buf is a valid URI, 0 otherwise
 * @see https://www.rfc-editor.org/rfc/rfc3986#section-3
 */
int ossl_uri_parse(const uint8_t *buf, size_t buf_len, OSSL_URI *uri);

#endif /* !defined(OSSL_INTERNAL_URI_H) */
