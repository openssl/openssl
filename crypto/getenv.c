/*
 * Copyright 2018-2022 The OpenSSL Project Authors. All Rights Reserved.
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
#include "internal/e_os.h"

/*
 * Additional checks for securely allowing access to selected environment variables
 */
#if defined (OPENSSL_NETCAP_ALLOW_ENV) && defined(__linux__)

/*
 * Utility function to check if a string is in an array of strings. returns true if found
 */
int str_in_list(const char *candidate, const char *list[], int n)
{
  if ( (candidate!=NULL) && (list!=NULL))
  {
    int len = n;
    if (len>=1)
    {
        int i;
        for ( i=0; i<len; i++)
        {
            if (strcmp(candidate,list[i])==0)
              // found
              return 1;
        }
    }
  }
  // drop-through case -- not found (or invalid parameters)
  return 0;
}

char *restricted_getenv(const char *name)
{
    /* Environment variables to permit in secure mode (subject to conditions). Extend as needed */
    const char * permitted_env [ ] = { "OPENSSL_MODULES", "OPENSSL_CONF" };
    if(name!=NULL && (!OPENSSL_issetugid()))
    {
      if (str_in_list(name,permitted_env,sizeof(permitted_env)/sizeof(char *)))
      {
        return getenv(name);
      }
    }
    return(secure_getenv(name));
}

#endif

char *ossl_safe_getenv(const char *name)
{
#if defined(_WIN32) && defined(CP_UTF8) && !defined(_WIN32_WCE)
    if (GetEnvironmentVariableW(L"OPENSSL_WIN32_UTF8", NULL, 0) != 0) {
        char *val = NULL;
        int vallen = 0;
        WCHAR *namew = NULL;
        WCHAR *valw = NULL;
        DWORD envlen = 0;
        DWORD dwFlags = MB_ERR_INVALID_CHARS;
        int rsize, fsize;
        UINT curacp;

        curacp = GetACP();

        /*
         * For the code pages listed below, dwFlags must be set to 0.
         * Otherwise, the function fails with ERROR_INVALID_FLAGS.
         */
        if (curacp == 50220 || curacp == 50221 || curacp == 50222 ||
            curacp == 50225 || curacp == 50227 || curacp == 50229 ||
            (57002 <= curacp && curacp <=57011) || curacp == 65000 ||
            curacp == 42)
            dwFlags = 0;

        /* query for buffer len */
        rsize = MultiByteToWideChar(curacp, dwFlags, name, -1, NULL, 0);
        /* if name is valid string and can be converted to wide string */
        if (rsize > 0)
            namew = _malloca(rsize * sizeof(WCHAR));

        if (NULL != namew) {
            /* convert name to wide string */
            fsize = MultiByteToWideChar(curacp, dwFlags, name, -1, namew, rsize);
            /* if conversion is ok, then determine value string size in wchars */
            if (fsize > 0)
                envlen = GetEnvironmentVariableW(namew, NULL, 0);
        }

        if (envlen > 0)
            valw = _malloca(envlen * sizeof(WCHAR));

        if (NULL != valw) {
            /* if can get env value as wide string */
            if (GetEnvironmentVariableW(namew, valw, envlen) < envlen) {
                /* determine value string size in utf-8 */
                vallen = WideCharToMultiByte(CP_UTF8, 0, valw, -1, NULL, 0,
                                             NULL, NULL);
            }
        }

        if (vallen > 0)
            val = OPENSSL_malloc(vallen);

        if (NULL != val) {
            /* convert value string from wide to utf-8 */
            if (WideCharToMultiByte(CP_UTF8, 0, valw, -1, val, vallen,
                                    NULL, NULL) == 0) {
                OPENSSL_free(val);
                val = NULL;
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
#   /* 
     * Non-default option to permit selected additional variables to be read where 
     * only the netcap capability is added, rather than follow the standard
     * priviliged default of disallowing access. (libc > 2.17, linux only)
     */
#   if defined(OPENSSL_NETCAP_ALLOW_ENV) && defined(__linux__)
     /* Use alternate implementation which allows some exceptions if in a secure environment */
       return(restricted_getenv(name));
#   else
     /* Default to secure retrieval (std library) */
     return secure_getenv(name);
#   endif
# endif
#endif

#ifndef SECURE_GETENV
    if (OPENSSL_issetugid())
        return NULL;
    return getenv(name);
#endif
}
