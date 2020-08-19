/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdlib.h>
#include "internal/cryptlib.h"
#include "e_os.h"

char *ossl_safe_getenv(const char *name)
{
#if defined(_WIN32) && defined(CP_UTF8) && !defined(_WIN32_WCE)
    if (GetEnvironmentVariableW(L"OPENSSL_WIN32_UTF8", NULL, 0) != 0) {

        char *val = NULL;
        WCHAR *namew = NULL;
        WCHAR *valw = NULL;
        DWORD envlen = 0;
        int rsize, fsize;

        /* query for buffer len */
        rsize = mbstowcs(NULL, name, 0) + 1;
        namew = _malloca(rsize * sizeof(WCHAR));

        if (NULL != namew) {
            /* convert name to wide string */
            fsize = mbstowcs(namew, name, rsize);
            /* if conversion is ok, then determine value string size in wchars */
            if (fsize > 0)
                envlen = GetEnvironmentVariableW(namew, NULL, 0);
        }

        if (envlen > 0)
            valw = _malloca(envlen * sizeof(WCHAR));

        if (NULL != valw) {
            if (GetEnvironmentVariableW(namew, valw, envlen) < envlen) {
                /* determine value string size in utf-8 */
                int sz = WideCharToMultiByte(CP_UTF8, 0, valw, -1,
                                             NULL, 0, NULL, NULL);

                if (sz != 0) {
                    val = OPENSSL_malloc(sz);
                    /* convert value string from wide to utf-8 */
                    if (WideCharToMultiByte(CP_UTF8, 0, valw, -1,
                                            val, sz, NULL, NULL) == 0) {
                        OPENSSL_free(val);
                        val = NULL;
                    }
                }
            }
        }

        if (NULL != namew)
            _freea(namew);

        if (NULL != valw)
            _freea(valw);

        return val;
    }
#endif

#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
# if __GLIBC_PREREQ(2, 17)
#  define SECURE_GETENV
    return secure_getenv(name);
# endif
#endif

#ifndef SECURE_GETENV
    if (OPENSSL_issetugid())
        return NULL;
    return getenv(name);
#endif
}
