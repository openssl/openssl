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
                        int *pport_num, char **ppath, int *pssl)
{
    char *p, *buf;
    char *host, *host_end;
    const char *path, *port = OSSL_HTTP_PORT;
    long portnum = 80;

    if (phost != NULL)
        *phost = NULL;
    if (pport != NULL)
        *pport = NULL;
    if (ppath != NULL)
        *ppath = NULL;
    if (pssl != NULL)
        *pssl = 0;

    if (url == NULL) {
        ERR_raise(ERR_LIB_HTTP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* dup the buffer since we are going to mess with it */
    if ((buf = OPENSSL_strdup(url)) == NULL)
        goto err;

    /* check for optional prefix "http[s]://" */
    p = strstr(buf, "://");
    if (p == NULL) {
        p = buf;
    } else {
        *p = '\0'; /* p points to end of scheme name */
        if (strcmp(buf, OSSL_HTTPS_NAME) == 0) {
            if (pssl != NULL)
                *pssl = 1;
            port = OSSL_HTTPS_PORT;
            portnum = 443;
        } else if (strcmp(buf, OSSL_HTTP_NAME) != 0) {
            ERR_raise(ERR_LIB_HTTP, HTTP_R_INVALID_URL_PREFIX);
            goto err;
        }
        p += 3;
    }
    host = p;

    /* parse host name/address as far as needed here */
    if (host[0] == '[') {
        /* ipv6 literal, which may include ':' */
        host++;
        host_end = strchr(host, ']');
        if (host_end == NULL)
            goto parse_err;
        *host_end++ = '\0';
    } else {
        host_end = strchr(host, ':'); /* look for start of optional port */
        if (host_end == NULL)
            host_end = strchr(host, '/'); /* look for start of optional path */
        if (host_end == NULL)
            /* the remaining string is just the hostname */
            host_end = host + strlen(host);
    }

    /* parse optional port specification starting with ':' */
    p = host_end;
    if (*p == ':') {
        port = ++p;
        if (pport_num == NULL) {
            p = strchr(port, '/');
            if (p == NULL)
                p = host_end + 1 + strlen(port);
        } else { /* make sure a numerical port value is given */
            portnum = strtol(port, &p, 10);
            if (p == port || (*p != '\0' && *p != '/'))
                goto parse_err;
            if (portnum <= 0 || portnum >= 65536) {
                ERR_raise(ERR_LIB_HTTP, HTTP_R_INVALID_PORT_NUMBER);
                goto err;
            }
        }
    }
    *host_end = '\0';
    *p = '\0'; /* terminate port string */

    /* check for optional path at end of url starting with '/' */
    path = url + (p - buf);
    /* cannot use p + 1 because *p is '\0' and path must start with '/' */
    if (*path == '\0') {
        path = "/";
    } else if (*path != '/') {
        ERR_raise(ERR_LIB_HTTP, HTTP_R_INVALID_URL_PATH);
        goto parse_err;
    }

    if (phost != NULL && (*phost = OPENSSL_strdup(host)) == NULL)
        goto err;
    if (pport != NULL && (*pport = OPENSSL_strdup(port)) == NULL)
        goto err;
    if (pport_num != NULL)
        *pport_num = (int)portnum;
    if (ppath != NULL && (*ppath = OPENSSL_strdup(path)) == NULL)
        goto err;

    OPENSSL_free(buf);
    return 1;

 parse_err:
    ERR_raise(ERR_LIB_HTTP, HTTP_R_ERROR_PARSING_URL);

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
