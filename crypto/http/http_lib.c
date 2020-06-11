/*
 * Copyright 2001-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/http.h>
#include <openssl/httperr.h>
#include <openssl/err.h>
#include <string.h>
#include "internal/cryptlib.h" /* for ossl_assert() */

#include "http_local.h"

/*
 * Parse a URL and split it up into host, port and path components and
 * whether it indicates SSL/TLS. Return 1 on success, 0 on error.
 */

int OSSL_HTTP_parse_url(const char *url, char **phost, char **pport,
                        char **ppath, int *pssl)
{
    char *p, *buf;
    char *host;
    const char *port = OSSL_HTTP_PORT;
    size_t https_len = strlen(OSSL_HTTPS_NAME);

    if (!ossl_assert(https_len >= strlen(OSSL_HTTP_NAME)))
        return 0;
    if (url == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (phost != NULL)
        *phost = NULL;
    if (pport != NULL)
        *pport = NULL;
    if (ppath != NULL)
        *ppath = NULL;
    if (pssl != NULL)
        *pssl = 0;

    /* dup the buffer since we are going to mess with it */
    if ((buf = OPENSSL_strdup(url)) == NULL)
        goto err;

    /* Check for initial colon */
    p = strchr(buf, ':');
    if (p == NULL || (size_t)(p - buf) > https_len) {
        p = buf;
    } else {
        *(p++) = '\0';

        if (strcmp(buf, OSSL_HTTPS_NAME) == 0) {
            if (pssl != NULL)
                *pssl = 1;
            port = OSSL_HTTPS_PORT;
        } else if (strcmp(buf, OSSL_HTTP_NAME) != 0) {
            goto parse_err;
        }

        /* Check for double slash */
        if ((p[0] != '/') || (p[1] != '/'))
            goto parse_err;
        p += 2;
    }
    host = p;

    /* Check for trailing part of path */
    p = strchr(p, '/');
    if (ppath != NULL && (*ppath = OPENSSL_strdup(p == NULL ? "/" : p)) == NULL)
        goto err;
    if (p != NULL)
        *p = '\0'; /* Set start of path to 0 so hostname[:port] is valid */

    p = host;
    if (host[0] == '[') {
        /* ipv6 literal */
        host++;
        p = strchr(host, ']');
        if (p == NULL)
            goto parse_err;
        *p = '\0';
        p++;
    }

    /* Look for optional ':' for port number */
    if ((p = strchr(p, ':'))) {
        *p = '\0';
        port = p + 1;
    }
    if (phost != NULL && (*phost = OPENSSL_strdup(host)) == NULL)
        goto err;
    if (pport != NULL && (*pport = OPENSSL_strdup(port)) == NULL)
        goto err;

    OPENSSL_free(buf);
    return 1;

 parse_err:
    HTTPerr(0, HTTP_R_ERROR_PARSING_URL);

 err:
    if (ppath != NULL) {
        OPENSSL_free(*ppath);
        *ppath = NULL;
    }
    if (pport != NULL) {
        OPENSSL_free(*pport);
        *pport = NULL;
    }
    if (phost != NULL) {
        OPENSSL_free(*phost);
        *phost = NULL;
    }
    OPENSSL_free(buf);
    return 0;
}

int http_use_proxy(const char *no_proxy, const char *server)
{
    size_t sl;
    const char *found = NULL;

    if (!ossl_assert(server != NULL))
        return 0;
    sl = strlen(server);

    /*
     * using environment variable names, both lowercase and uppercase variants,
     * compatible with other HTTP client implementations like wget, curl and git
     */
    if (no_proxy == NULL)
        no_proxy = getenv("no_proxy");
    if (no_proxy == NULL)
        no_proxy = getenv(OPENSSL_NO_PROXY);
    if (no_proxy != NULL)
        found = strstr(no_proxy, server);
    while (found != NULL
           && ((found != no_proxy && found[-1] != ' ' && found[-1] != ',')
               || (found[sl] != '\0' && found[sl] != ' ' && found[sl] != ',')))
        found = strstr(found + 1, server);
    return found == NULL;
}

const char *http_adapt_proxy(const char *proxy, const char *no_proxy,
                             const char *server, int use_ssl)
{
    const int http_len = strlen(OSSL_HTTP_PREFIX);
    const int https_len = strlen(OSSL_HTTPS_PREFIX);

    /*
     * using environment variable names, both lowercase and uppercase variants,
     * compatible with other HTTP client implementations like wget, curl and git
     */
    if (proxy == NULL)
        proxy = getenv(use_ssl ? "https_proxy" : "http_proxy");
    if (proxy == NULL)
        proxy = getenv(use_ssl ? OPENSSL_HTTP_PROXY :
                       OPENSSL_HTTPS_PROXY);
    if (proxy == NULL)
        return NULL;

    /* skip any leading "http://" or "https://" */
    if (strncmp(proxy, OSSL_HTTP_PREFIX, http_len) == 0)
        proxy += http_len;
    else if (strncmp(proxy, OSSL_HTTPS_PREFIX, https_len) == 0)
        proxy += https_len;

    if (*proxy == '\0' || !http_use_proxy(no_proxy, server))
        return NULL;
    return proxy;
}
