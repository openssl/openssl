/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file http_url.h
 * Parsing of http and https URLs for HTTP clients.
 *
 * This file is compiled into both libcrypto and libapps, so it uses only
 * the public libcrypto API and the inline PACKET functions.
 */

#if !defined(OSSL_INTERNAL_HTTP_URL_H)
#define OSSL_INTERNAL_HTTP_URL_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Parse an http or https URL for an HTTP client.
 *
 * The URL is parsed with ossl_uri_parse(). When allow_no_scheme is set, a
 * url that does not start with scheme "://" is parsed with "http://"
 * prepended, which accepts host[:port][/path] and a bare path. Any
 * userinfo and fragment are ignored. On failure an ERR_LIB_HTTP error is
 * raised and no output is allocated.
 *
 * @param url the URL, which need not be NUL-terminated
 * @param url_len the length of the URL in bytes
 * @param allow_no_scheme 1 to accept a url without scheme "://"
 * @param allow_empty_host 1 to accept an empty host
 * @param use_ssl if not NULL, receives 1 for https and 0 for http
 * @param host receives the host, an IPv6 address within "[" and "]"
 * @param port receives the port, or the default port of the scheme
 * @param port_num if not NULL, receives the number of *port
 * @param path if not NULL, receives the path, or "/" if it is empty,
 * followed by any "?" query
 * @returns 1 on success, 0 on failure
 */
int ossl_http_parse_url(const uint8_t *url, size_t url_len,
    int allow_no_scheme, int allow_empty_host, int *use_ssl,
    char **host, char **port, int *port_num, char **path);

#endif /* !defined(OSSL_INTERNAL_HTTP_URL_H) */
