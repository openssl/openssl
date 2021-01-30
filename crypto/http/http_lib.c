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

static int copy_substring(char **dest, const char *start, const char *end)
{
    return dest == NULL
        || (*dest = OPENSSL_strndup(start, end - start)) != NULL;
}

static void free_pstring(char **pstr)
{
    if (pstr != NULL) {
        OPENSSL_free(*pstr);
        *pstr = NULL;
    }
}

int OSSL_HTTP_parse_url(const char *url, int *pssl, char **puser, char **phost,
                        char **pport, int *pport_num,
                        char **ppath, char **pquery, char **pfrag)
{
    char *p, *buf;
    char *host, *host_end;
    char *user, *user_end;
    char *path, *path_end, *tmp;
    char *port = OSSL_HTTP_PORT, *port_end = port + strlen(port);
    long portnum = 80;
    char *frag, *frag_end;
    char *query, *query_end;

    if (pssl != NULL)
        *pssl = 0;
    if (puser != NULL)
        *puser = NULL;
    if (phost != NULL)
        *phost = NULL;
    if (pport != NULL)
        *pport = NULL;
    if (ppath != NULL)
        *ppath = NULL;
    if (pfrag != NULL)
        *pfrag = NULL;
    if (pquery != NULL)
        *pquery = NULL;

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
            port_end = port + strlen(port);
            portnum = 443;
        } else if (strcmp(buf, OSSL_HTTP_NAME) != 0) {
            ERR_raise(ERR_LIB_HTTP, HTTP_R_INVALID_URL_PREFIX);
            goto err;
        }
        p += 3;
    }

    /* parse optional "userinfo@" */
    user = user_end = host = p;
    host = strchr(p, '@');
    if (host != NULL)
        user_end = host++;
    else
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
        /* look for start of optional port, path, query, or fragment */
        host_end = strchr(host, ':');
        if (host_end == NULL)
            host_end = strchr(host, '/');
        if (host_end == NULL)
            host_end = strchr(host, '?');
        if (host_end == NULL)
            host_end = strchr(host, '#');
        if (host_end == NULL)
            /* the remaining string is just the hostname */
            host_end = host + strlen(host);
    }

    /* parse optional port specification starting with ':' */
    p = host_end;
    if (*p == ':') {
        port = ++p;
        /* make sure a decimal port number is given */
        portnum = strtol(port, &p, 10);
        if (p == port)
            goto parse_err;
        if (portnum <= 0 || portnum >= 65536) {
            ERR_raise(ERR_LIB_HTTP, HTTP_R_INVALID_PORT_NUMBER);
            goto err;
        }
        port_end = p;
    }

    /* check for optional path starting with '/' or '?'. Else must start '#' */
    path = p;
    if (*path != '\0' && *path != '/' && *path != '?' && *path != '#') {
        ERR_raise(ERR_LIB_HTTP, HTTP_R_INVALID_URL_PATH);
        goto parse_err;
    }
    path_end = query = query_end = frag = frag_end = path + strlen(path);

    /* parse optional "?query" */
    tmp = strchr(path, '?');
    if (pquery != NULL && tmp != NULL) {
        path_end = tmp;
        query = path_end + 1;
    }

    /* parse optional "#fragment" */
    tmp = strchr(path, '#');
    if (tmp != NULL) {
        if (query == path_end) /* we did not record a query component */
            path_end = tmp;
        query_end = tmp;
        frag = query_end + 1;
    }

    if (!copy_substring(phost, host, host_end)
            || !copy_substring(pport, port, port_end)
            || !copy_substring(puser, user, user_end))
        goto err;
    if (*path != '/')
        *--path = '/';
    if (!copy_substring(ppath, path, path_end)
            || !copy_substring(pquery, query, query_end)
            || !copy_substring(pfrag, frag, frag_end))
        goto err;
    if (pport_num != NULL)
        *pport_num = (int)portnum;

    OPENSSL_free(buf);
    return 1;

 parse_err:
    ERR_raise(ERR_LIB_HTTP, HTTP_R_ERROR_PARSING_URL);

 err:
    free_pstring(phost);
    free_pstring(pport);
    free_pstring(ppath);
    free_pstring(pquery);
    free_pstring(pfrag);
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
