/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Parsing of http and https URLs for HTTP clients.
 *
 * This file is compiled into both libcrypto and libapps, so it uses only
 * the public libcrypto API and the inline PACKET functions.
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/http.h>
#include <openssl/httperr.h>
#include "internal/http_url.h"
#include "internal/uri.h"

static int is_alpha(unsigned int c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static int packet_has_scheme_prefix(const PACKET *pkt)
{
    PACKET tmp = *pkt;
    unsigned int c;

    if (!PACKET_get_1(&tmp, &c) || !is_alpha(c))
        return 0;
    do {
        if (!PACKET_get_1(&tmp, &c))
            return 0;
    } while (is_alpha(c) || (c >= '0' && c <= '9') || c == '+' || c == '-'
        || c == '.');
    return c == ':'
        && PACKET_get_1(&tmp, &c) && c == '/'
        && PACKET_get_1(&tmp, &c) && c == '/';
}

/* Whether scheme equals the lowercase name, ignoring case */
static int packet_is_scheme_name(const PACKET *scheme, const char *name,
    size_t name_len)
{
    PACKET tmp = *scheme;
    unsigned int c;
    size_t i;

    if (PACKET_remaining(scheme) != name_len)
        return 0;
    for (i = 0; PACKET_get_1(&tmp, &c); i++) {
        if ((c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c)
            != (unsigned char)name[i])
            return 0;
    }
    return 1;
}

int ossl_http_uri_parse(const uint8_t *url, size_t url_len,
    int allow_no_scheme, OSSL_URI *uri, uint8_t **copy, int *prepended)
{
    static const uint8_t http_prefix[] = OSSL_HTTP_PREFIX;
    size_t prefix_len = sizeof(http_prefix) - 1;
    PACKET pkt;

    *copy = NULL;
    *prepended = 0;
    if (!PACKET_buf_init(&pkt, url, url_len))
        return 0;
    if (!packet_has_scheme_prefix(&pkt)) {
        if (!allow_no_scheme || url_len > SIZE_MAX - prefix_len)
            return 0;
        if ((*copy = OPENSSL_malloc(prefix_len + url_len)) == NULL)
            return 0;
        memcpy(*copy, http_prefix, prefix_len);
        if (url_len > 0)
            memcpy(*copy + prefix_len, url, url_len);
        url = *copy;
        url_len += prefix_len;
        *prepended = 1;
    }
    return ossl_uri_parse(url, url_len, uri) && uri->has_authority;
}

char *ossl_http_uri_host(const OSSL_URI *uri)
{
    PACKET parts[3];

    if (uri->host_type != OSSL_URI_HOST_IPV6)
        return ossl_uri_strdup(&uri->host, 1);
    if (!PACKET_buf_init(&parts[0], (const uint8_t *)"[", 1)
        || !PACKET_buf_init(&parts[2], (const uint8_t *)"]", 1))
        return NULL;
    parts[1] = uri->host;
    return ossl_uri_strdup(parts, 3);
}

int ossl_http_uri_is_http(const OSSL_URI *uri, int *is_https)
{
    if (packet_is_scheme_name(&uri->scheme, OSSL_HTTPS_NAME,
            sizeof(OSSL_HTTPS_NAME) - 1)) {
        *is_https = 1;
        return 1;
    }
    *is_https = 0;
    return packet_is_scheme_name(&uri->scheme, OSSL_HTTP_NAME,
        sizeof(OSSL_HTTP_NAME) - 1);
}

int ossl_http_parse_url(const uint8_t *url, size_t url_len,
    int allow_no_scheme, int allow_empty_host, int *use_ssl,
    char **host, char **port, int *port_num, char **path)
{
    uint8_t *copy = NULL;
    PACKET parts[3];
    OSSL_URI uri;
    int prepended, is_https, ret = 0;

    *host = *port = NULL;
    if (path != NULL)
        *path = NULL;

    if (!ossl_http_uri_parse(url, url_len, allow_no_scheme, &uri, &copy,
            &prepended))
        goto parse_err;

    if (!ossl_http_uri_is_http(&uri, &is_https)) {
        ERR_raise(ERR_LIB_HTTP, HTTP_R_INVALID_URL_SCHEME);
        goto end;
    }
    if (!allow_empty_host && PACKET_remaining(&uri.host) == 0)
        goto parse_err;
    if (uri.port_num == 0) {
        ERR_raise(ERR_LIB_HTTP, HTTP_R_INVALID_PORT_NUMBER);
        goto end;
    }

    if ((*host = ossl_http_uri_host(&uri)) == NULL)
        goto end;

    if (uri.port_num > 0) {
        parts[0] = uri.port;
    } else if (is_https) {
        if (!PACKET_buf_init(&parts[0], (const uint8_t *)OSSL_HTTPS_PORT,
                sizeof(OSSL_HTTPS_PORT) - 1))
            goto end;
    } else if (!PACKET_buf_init(&parts[0], (const uint8_t *)OSSL_HTTP_PORT,
                   sizeof(OSSL_HTTP_PORT) - 1)) {
        goto end;
    }
    if ((*port = ossl_uri_strdup(parts, 1)) == NULL)
        goto end;
    if (port_num != NULL && uri.port_num > 0)
        *port_num = uri.port_num;
    else if (port_num != NULL)
        *port_num = is_https ? 443 : 80;

    if (path != NULL) {
        parts[0] = uri.path;
        if (PACKET_remaining(&uri.path) == 0
            && !PACKET_buf_init(&parts[0], (const uint8_t *)"/", 1))
            goto end;
        PACKET_null_init(&parts[1]);
        if (uri.has_query
            && !PACKET_buf_init(&parts[1], (const uint8_t *)"?", 1))
            goto end;
        parts[2] = uri.query;
        if ((*path = ossl_uri_strdup(parts, 3)) == NULL)
            goto end;
    }

    if (use_ssl != NULL)
        *use_ssl = is_https;
    ret = 1;
    goto end;

parse_err:
    ERR_raise(ERR_LIB_HTTP, HTTP_R_ERROR_PARSING_URL);
end:
    if (!ret) {
        OPENSSL_free(*host);
        OPENSSL_free(*port);
        *host = *port = NULL;
    }
    OPENSSL_free(copy);
    return ret;
}
