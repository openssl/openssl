/*
 * Copyright 2001-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Suppress deprecation warnings for OSSL_parse_url() and
 * OSSL_HTTP_parse_url(), which are kept until removal.
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <string.h>
#include <openssl/http.h>
#include <openssl/httperr.h>
#include <openssl/err.h>
#include "internal/cryptlib.h" /* for ossl_assert() */
#include "internal/http_url.h"
#include "internal/nelem.h"
#ifndef OPENSSL_NO_SOCK
#include "internal/bio_addr.h" /* for NI_MAXHOST */
#endif
#ifndef NI_MAXHOST
#define NI_MAXHOST 255
#endif
#include "crypto/ctype.h" /* for ossl_isspace() */

#ifndef OPENSSL_NO_DEPRECATED_4_2

static int pstrdup(char **out, const PACKET *parts, size_t count)
{
    return out == NULL || (*out = ossl_uri_strdup(parts, count)) != NULL;
}

/*-
 * The implementation of OSSL_parse_url() and, with http_only set,
 * OSSL_HTTP_parse_url(). A url without scheme "://" is parsed as if
 * "http://" were prepended, and its scheme is reported as empty.
 */
static int parse_url(const char *url, int http_only, int *pssl,
    char **pscheme, char **puser, char **phost, char **pport,
    int *pport_num, char **ppath, char **pquery, char **pfrag)
{
    char **outputs[] = { pscheme, puser, phost, pport, ppath, pquery, pfrag };
    uint8_t *copy = NULL;
    OSSL_URI uri;
    PACKET parts[3], default_port;
    int default_port_num = 0, prepended, is_https = 0, ret = 0;
    size_t i;

    for (i = 0; i < OSSL_NELEM(outputs); i++)
        if (outputs[i] != NULL)
            *outputs[i] = NULL;
    if (pport_num != NULL)
        *pport_num = 0;
    if (pssl != NULL)
        *pssl = 0;

    if (url == NULL) {
        ERR_raise(ERR_LIB_HTTP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (!PACKET_buf_init(&default_port, (const uint8_t *)"0", 1))
        return 0;
    if (!ossl_http_uri_parse((const uint8_t *)url, strlen(url),
            /*allow_no_scheme=*/1, &uri, &copy, &prepended)) {
        ERR_raise(ERR_LIB_HTTP, HTTP_R_ERROR_PARSING_URL);
        goto end;
    }
    if (uri.has_port && uri.port_num < 0) {
        ERR_raise(ERR_LIB_HTTP, HTTP_R_INVALID_PORT_NUMBER);
        goto end;
    }
    if (http_only) {
        if (!ossl_http_uri_is_http(&uri, &is_https)) {
            ERR_raise(ERR_LIB_HTTP, HTTP_R_INVALID_URL_SCHEME);
            goto end;
        }
        if (uri.port_num == 0) {
            ERR_raise(ERR_LIB_HTTP, HTTP_R_INVALID_PORT_NUMBER);
            goto end;
        }
        if (is_https
            && !PACKET_buf_init(&default_port,
                (const uint8_t *)OSSL_HTTPS_PORT, sizeof(OSSL_HTTPS_PORT) - 1))
            goto end;
        if (!is_https
            && !PACKET_buf_init(&default_port,
                (const uint8_t *)OSSL_HTTP_PORT, sizeof(OSSL_HTTP_PORT) - 1))
            goto end;
        default_port_num = is_https ? 443 : 80;
    }

    if (prepended)
        PACKET_null_init(&uri.scheme);
    if (!uri.has_port)
        uri.port = default_port;
    if (!pstrdup(pscheme, &uri.scheme, 1)
        || !pstrdup(puser, &uri.userinfo, 1)
        || !pstrdup(pport, &uri.port, 1)
        || !pstrdup(pquery, &uri.query, 1)
        || !pstrdup(pfrag, &uri.fragment, 1))
        goto end;
    if (phost != NULL && (*phost = ossl_http_uri_host(&uri)) == NULL)
        goto end;
    if (pport_num != NULL)
        *pport_num = uri.has_port ? uri.port_num : default_port_num;

    /* The path starts with "/" and, if pquery is NULL, includes any query */
    parts[0] = uri.path;
    if (PACKET_remaining(&uri.path) == 0
        && !PACKET_buf_init(&parts[0], (const uint8_t *)"/", 1))
        goto end;
    PACKET_null_init(&parts[1]);
    PACKET_null_init(&parts[2]);
    if (pquery == NULL && uri.has_query) {
        if (!PACKET_buf_init(&parts[1], (const uint8_t *)"?", 1))
            goto end;
        parts[2] = uri.query;
    }
    if (!pstrdup(ppath, parts, 3))
        goto end;

    if (pssl != NULL)
        *pssl = is_https;
    ret = 1;

end:
    if (!ret) {
        for (i = 0; i < OSSL_NELEM(outputs); i++) {
            if (outputs[i] != NULL) {
                OPENSSL_free(*outputs[i]);
                *outputs[i] = NULL;
            }
        }
    }
    OPENSSL_free(copy);
    return ret;
}

int OSSL_parse_url(const char *url, char **pscheme, char **puser, char **phost,
    char **pport, int *pport_num,
    char **ppath, char **pquery, char **pfrag)
{
    return parse_url(url, /*http_only=*/0, /*pssl=*/NULL, pscheme, puser,
        phost, pport, pport_num, ppath, pquery, pfrag);
}

#ifndef OPENSSL_NO_HTTP
int OSSL_HTTP_parse_url(const char *url, int *pssl, char **puser, char **phost,
    char **pport, int *pport_num,
    char **ppath, char **pquery, char **pfrag)
{
    return parse_url(url, /*http_only=*/1, pssl, /*pscheme=*/NULL, puser,
        phost, pport, pport_num, ppath, pquery, pfrag);
}
#endif /* !defined(OPENSSL_NO_HTTP) */

#endif /* !defined(OPENSSL_NO_DEPRECATED_4_2) */

#ifndef OPENSSL_NO_HTTP

/* Respect no_proxy, taking default value from environment variable(s) */
static int use_proxy(const char *no_proxy, const char *server)
{
    size_t sl;
    const char *found = NULL;
    char host[NI_MAXHOST];

    if (!ossl_assert(server != NULL))
        return 0;
    sl = strlen(server);
    if (sl >= 2 && sl < sizeof(host) + 2 && server[0] == '[' && server[sl - 1] == ']') {
        /* strip leading '[' and trailing ']' from escaped IPv6 address */
        sl -= 2;
        strncpy(host, server + 1, sl);
        host[sl] = '\0';
        server = host;
    }

    if (sl == 0)
        return 1;

    /*
     * using environment variable names, both lowercase and uppercase variants,
     * compatible with other HTTP client implementations like wget, curl and git
     */
    if (no_proxy == NULL)
        no_proxy = ossl_safe_getenv("no_proxy");
    if (no_proxy == NULL)
        no_proxy = ossl_safe_getenv(OPENSSL_NO_PROXY);

    if (no_proxy != NULL)
        found = strstr(no_proxy, server);
    while (found != NULL
        && ((found != no_proxy && !ossl_isspace(found[-1]) && found[-1] != ',')
            || (found[sl] != '\0' && !ossl_isspace(found[sl]) && found[sl] != ',')))
        found = strstr(found + 1, server);
    return found == NULL;
}

/* Take default value from environment variable(s), respect no_proxy */
const char *OSSL_HTTP_adapt_proxy(const char *proxy, const char *no_proxy,
    const char *server, int use_ssl)
{
    /*
     * using environment variable names, both lowercase and uppercase variants,
     * compatible with other HTTP client implementations like wget, curl and git
     */
    if (proxy == NULL)
        proxy = ossl_safe_getenv(use_ssl ? "https_proxy" : "http_proxy");
    if (proxy == NULL)
        proxy = ossl_safe_getenv(use_ssl ? OPENSSL_HTTPS_PROXY : OPENSSL_HTTP_PROXY);

    if (proxy == NULL || *proxy == '\0' || !use_proxy(no_proxy, server))
        return NULL;
    return proxy;
}

#endif /* !defined(OPENSSL_NO_HTTP) */
