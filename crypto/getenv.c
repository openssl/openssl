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
#if (defined(OPENSSL_SYS_WINDOWS)) && defined(CP_UTF8) && !defined(_WIN32_WCE)

    if (GetEnvironmentVariableW(L"OPENSSL_WIN32_UTF8", NULL, 0) == 0)
        return getenv(name);

    /* convert name to wide string */
    int rsize = mbstowcs(NULL, name, 0) + 1;
    WCHAR * namew = _alloca(rsize * sizeof(WCHAR));
    int fsize = mbstowcs(namew, name, rsize);

    char *val = NULL;

    /* determine value string size in wchars */
    DWORD envlen = GetEnvironmentVariableW(namew, NULL, 0);    

    if (envlen != 0) {
        WCHAR *valw = _alloca(envlen * sizeof(WCHAR));
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
    return val;
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
