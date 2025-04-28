/*
 * Copyright 2016-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/store.h>
#include "internal/cryptlib.h"

#ifdef _WIN32
# define OSSL_is_drive_letter(c) (((c) >= 'A' && (c) <= 'Z') || ((c) >= 'a' && (c) <= 'z'))
#endif

const char *ossl_file_stat(const char *uri, struct stat *st)
{
    const char *path = uri, *q;
    struct stat local_st;

    if (st == NULL)
        st = &local_st;

    /*
     * First, unless the URI starts with "file://",
     * try and see if the full URI can be taken as a local file path name.
     */
    if (!HAS_CASE_PREFIX(uri, "file://")) {
        if (stat(path, st) == 0)
            return uri;
        ERR_raise_data(ERR_LIB_SYS, errno, "calling stat(%s)", path);
    }

    /* Do a second attempt only if the URI appears to start with the "file" scheme. */
    if (!CHECK_AND_SKIP_CASE_PREFIX(path, "file:"))
        return NULL;

    /*
     * Extract the alternative path to check.
     * There's a special case if the URI also contains an authority,
     * then the full URI shouldn't be used as a path anywhere.
     */
    q = path;
    if (CHECK_AND_SKIP_CASE_PREFIX(q, "//")) {
        if (CHECK_AND_SKIP_CASE_PREFIX(q, "localhost/")
            || CHECK_AND_SKIP_CASE_PREFIX(q, "/")) {
            /*
             * In these cases, we step back one char to ensure that the
             * first slash is preserved, making the path always absolute
             */
            path = q - 1;
#ifdef _WIN32
        } else if (OSSL_is_drive_letter(path[2]) && path[3] == ':' && path[4] == '/') {
            /* Support also Windows "file://" URIs starting with a drive letter before a '/' */
            path = q;
#endif
        } else {
            const char *p = strchr(q, '/');
            size_t len = p == NULL ? strlen(q) : (size_t)(p - q);

            ERR_raise_data(ERR_LIB_OSSL_STORE, OSSL_STORE_R_URI_AUTHORITY_UNSUPPORTED,
                           "%.*s", len, q);
            return NULL;
        }
    }
#ifdef _WIN32
    /* Windows "file:" URIs with a drive letter are required to start with a '/' */
    if (path[0] == '/' && OSSL_is_drive_letter(path[1]) && path[2] == ':' && path[3] == '/')
        path++; /* Skip past the slash, making the path a normal Windows path */
#endif

    if (stat(path, st) == 0)
        return path;
    ERR_raise_data(ERR_LIB_SYS, errno, "calling stat(%s)", path);
    return NULL;
}
