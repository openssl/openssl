/*
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/opensslv.h>
#include "internal/thread_once.h"
#include "internal/cryptlib.h"
#include "internal/e_os.h"

#if defined(_WIN32)

# define TOSTR(x) #x
# define MAKESTR(x) TOSTR(x)
# define NOQUOTE(x) x
#if defined(OSSL_WINCTX)
# define REGISTRY_KEY "SOFTWARE\\WOW6432Node\\OpenSSL" ##"-"## NOQUOTE(OPENSSL_VERSION_STR) ##"-"## MAKESTR(OSSL_WINCTX)
#else
# define REGISTRY_KEY "NONE"
#endif

/**
 * @brief The directory where OpenSSL is installed.
 */
static char openssldir[MAX_PATH + 1];

/**
 * @brief The directory where OpenSSL engines are located.
 */

static char enginesdir[MAX_PATH + 1];

/**
 * @brief The directory where OpenSSL modules are located.
 */
static char modulesdir[MAX_PATH + 1];

/**
 * @brief Get the list of Windows registry directories.
 *
 * This function retrieves a list of Windows registry directories.
 *
 * @return A pointer to a char array containing the registry directories.
 */
static char *get_windows_regdirs(char *dst, LPCTSTR valuename)
{
    DWORD keysize;
    DWORD ktype;
    HKEY hkey;
    LSTATUS ret;
    DWORD index = 0;
    LPCTCH tempstr = NULL;
    char *retval = NULL;

    ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                       TEXT(REGISTRY_KEY), KEY_WOW64_32KEY,
                       KEY_QUERY_VALUE, &hkey);
    if (ret != ERROR_SUCCESS)
        goto out;

    ret = RegQueryValueEx(hkey, valuename, NULL, &ktype, NULL,
                          &keysize);
    if (ret != ERROR_SUCCESS)
        goto out;
    if (ktype != REG_EXPAND_SZ)
        goto out;
    if (keysize > MAX_PATH)
        goto out;

    keysize++;
    tempstr = OPENSSL_zalloc(keysize * sizeof(TCHAR));

    if (tempstr == NULL)
        goto out;

    if (RegQueryValueEx(hkey, valuename,
                        NULL, &ktype, tempstr, &keysize) != ERROR_SUCCESS)
        goto out;

    if (!WideCharToMultiByte(CP_UTF8, 0, tempstr, -1, dst, keysize,
                             NULL, NULL)) 
        goto out;

    retval = dst;
out:
    OPENSSL_free(tempstr);
    RegCloseKey(hkey);
    return retval;
}

static CRYPTO_ONCE defaults_setup_init = CRYPTO_ONCE_STATIC_INIT;

/**
 * @brief Function to setup default values to run once.
 * Only used in Windows environments.  Does run time initalization
 * of openssldir/modulesdir/enginesdir from the registry
 */
DEFINE_RUN_ONCE_STATIC(do_defaults_setup)
{
    get_windows_regdirs(openssldir, TEXT("OPENSSLDIR"));
    get_windows_regdirs(enginesdir, TEXT("ENGINESDIR"));
    get_windows_regdirs(modulesdir, TEXT("MODULESDIR"));
    return 1;
}
#endif

/**
 * @brief Get the directory where OpenSSL is installed.
 *
 * @return A pointer to a string containing the OpenSSL directory path.
 */
const char *ossl_get_openssldir(void)
{
#if defined(_WIN32)
# if defined(OSSL_WINCTX)
    if (!RUN_ONCE(&defaults_setup_init, do_defaults_setup))
        return NULL;
    return (const char *)openssldir;
# else
    return "UNDEFINED";
# endif
#else
# ifdef OPENSSLDIR
    return OPENSSLDIR;
# else
    return "";
# endif
#endif
}

/**
 * @brief Get the directory where OpenSSL engines are located.
 *
 * @return A pointer to a string containing the engines directory path.
 */
const char *ossl_get_enginesdir(void)
{
#if defined(_WIN32)
# if defined(OSSL_WINCTX)
    if (!RUN_ONCE(&defaults_setup_init, do_defaults_setup))
        return NULL;
    return (const char *)enginesdir;
# else
    return "UNDEFINED";
# endif
#else
# ifdef OPENSSLDIR
    return ENGINESDIR;
# else
    return "";
# endif
#endif
}

/**
 * @brief Get the directory where OpenSSL modules are located.
 *
 * @return A pointer to a string containing the modules directory path.
 */
const char *ossl_get_modulesdir(void)
{
#if defined(_WIN32)
# if definied (OSSL_WINCTX)
    if (!RUN_ONCE(&defaults_setup_init, do_defaults_setup))
        return NULL;
    return (const char *)modulesdir;
# else
    return "UNDEFINED";
# endif
#else
# ifdef MODULESDIR
    return MODULESDIR;
# else
    return "";
# endif
#endif
}

/**
 * @brief Get the build time defined windows installer context
 *
 * @return A char pointer to a string representing the windows install context
 */
const char *ossl_get_wininstallcontext(void)
{
#if defined(_WIN32) && defined (OSSL_WINCTX)
	return MAKESTR(OSSL_WINCTX);
#else
	return "";
#endif
}
