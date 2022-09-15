/*
 * Copyright 2018-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../testutil.h"
#include <ctype.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <string.h>

int test_get_libctx(OSSL_LIB_CTX **libctx, OSSL_PROVIDER **default_null_prov,
                    const char *config_file,
                    OSSL_PROVIDER **provider, const char *module_name)
{
    OSSL_LIB_CTX *new_libctx = NULL;

    if (libctx != NULL) {
        if ((new_libctx = *libctx = OSSL_LIB_CTX_new()) == NULL) {
            opt_printf_stderr("Failed to create libctx\n");
            goto err;
        }
    }

    if (default_null_prov != NULL
        && (*default_null_prov = OSSL_PROVIDER_load(NULL, "null")) == NULL) {
        opt_printf_stderr("Failed to load null provider into default libctx\n");
        goto err;
    }

    if (config_file != NULL
            && !OSSL_LIB_CTX_load_config(new_libctx, config_file)) {
        opt_printf_stderr("Error loading config from file %s\n", config_file);
        goto err;
    }

    if (module_name != NULL
            && (*provider = OSSL_PROVIDER_load(new_libctx, module_name)) == NULL) {
        opt_printf_stderr("Failed to load provider %s\n", module_name);
        goto err;
    }
    return 1;

 err:
    ERR_print_errors_fp(stderr);
    return 0;
}

int test_arg_libctx(OSSL_LIB_CTX **libctx, OSSL_PROVIDER **default_null_prov,
                    OSSL_PROVIDER **provider, int argn, const char *usage)
{
    const char *module_name;

    if (!TEST_ptr(module_name = test_get_argument(argn))) {
        TEST_error("usage: <prog> %s", usage);
        return 0;
    }
    if (strcmp(module_name, "none") == 0)
        return 1;
    return test_get_libctx(libctx, default_null_prov,
                           test_get_argument(argn + 1), provider, module_name);
}

typedef struct {
    int major, minor, patch;
} PROV_VERSION;

/*
 * Query the provider to determine it's version number.
 * Returns 1 if the version is retrieved correctly, 0 if the provider isn't
 * loaded and -1 on error.
 */
static int get_provider_version(OSSL_LIB_CTX *libctx, const char *prov_name,
                                PROV_VERSION *vers)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    OSSL_PROVIDER *prov;
    char *vs;

    if (!OSSL_PROVIDER_available(libctx, prov_name))
        return 0;
    *params = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, &vs, 0);
    if ((prov = OSSL_PROVIDER_load(libctx, prov_name)) == NULL)
        return -1;
    if (!OSSL_PROVIDER_get_params(prov, params)
            || sscanf(vs, "%d.%d.%d", &vers->major, &vers->minor, &vers->patch) != 3)
        goto err;
    if (!OSSL_PROVIDER_unload(prov))
        return -1;
    return 1;
 err:
    OSSL_PROVIDER_unload(prov);
    return -1;
}

int provider_version_eq(OSSL_LIB_CTX *libctx, const char *prov_name,
                        int major, int minor, int patch)
{
    PROV_VERSION prov;
    int res;

    if ((res = get_provider_version(libctx, prov_name, &prov)) <= 0)
        return res == 0;
    return major == prov.major && minor == prov.minor && patch == prov.patch;
}

int provider_version_ne(OSSL_LIB_CTX *libctx, const char *prov_name,
                        int major, int minor, int patch)
{
    PROV_VERSION prov;
    int res;

    if ((res = get_provider_version(libctx, prov_name, &prov)) <= 0)
        return res == 0;
    return major != prov.major || minor != prov.minor || patch != prov.patch;
}

int provider_version_lt(OSSL_LIB_CTX *libctx, const char *prov_name,
                        int major, int minor, int patch)
{
    PROV_VERSION prov;
    int res;

    if ((res = get_provider_version(libctx, prov_name, &prov)) <= 0)
        return res == 0;
    return prov.major < major
           || (prov.major == major
               && (prov.minor < minor
                   || (prov.minor == minor && prov.patch < patch)));
}

int provider_version_le(OSSL_LIB_CTX *libctx, const char *prov_name,
                        int major, int minor, int patch)
{
    PROV_VERSION prov;
    int res;

    if ((res = get_provider_version(libctx, prov_name, &prov)) <= 0)
        return res == 0;
    return prov.major < major
           || (prov.major == major
               && (prov.minor < minor
                   || (prov.minor == minor && prov.patch <= patch)));
}

int provider_version_ge(OSSL_LIB_CTX *libctx, const char *prov_name,
                        int major, int minor, int patch)
{
    PROV_VERSION prov;
    int res;

    if ((res = get_provider_version(libctx, prov_name, &prov)) <= 0)
        return res == 0;
    return prov.major > major
           || (prov.major == major
               && (prov.minor > minor
                   || (prov.minor == minor && prov.patch >= patch)));
}

int provider_version_gt(OSSL_LIB_CTX *libctx, const char *prov_name,
                        int major, int minor, int patch)
{
    PROV_VERSION prov;
    int res;

    if ((res = get_provider_version(libctx, prov_name, &prov)) <= 0)
        return res == 0;
    return prov.major > major
           || (prov.major == major
               && (prov.minor > minor
                   || (prov.minor == minor && prov.patch > patch)));
}

int provider_version_match(OSSL_LIB_CTX *libctx, const char *prov_name,
                           const char *versions)
{
    const char *p;
    int major, minor, patch, r;
    enum {
        MODE_EQ, MODE_NE, MODE_LT, MODE_LE, MODE_GE, MODE_GT, MAX_MODE
    } mode;
    static int (*match_funcs[MAX_MODE])(OSSL_LIB_CTX *libctx, const char *prov_name,
                                        int major, int minor, int patch) = {
        provider_version_eq, provider_version_ne,
        provider_version_lt, provider_version_le,
        provider_version_ge, provider_version_gt
    };

    while (*versions != '\0') {
        while (*versions == ',' || isspace(*versions))
            versions++;
        if (*versions == '\0')
            break;
        p = versions;
        while (*versions != '\0' && *versions != ',' && !isspace(*versions))
            versions++;
        if (*p == '!') {
            mode = MODE_NE;
            if (*++p == '=')
                p++;
        } else if (*p == '=') {
            mode = MODE_EQ;
            p++;
        } else if (*p == '<') {
            mode = MODE_LT;
            if (*++p == '=') {
                mode = MODE_LE;
                p++;
            }
        } else if (*p == '>') {
            mode = MODE_GT;
            if (*++p == '=') {
                mode = MODE_GE;
                p++;
            }
        } else if (isdigit(*p)) {
            mode = MODE_EQ;
        } else {
            TEST_info("Error matching provider %s version: mode %s\n", prov_name, p);
            return -1;
        }
        if (sscanf(p, "%d.%d.%d", &major, &minor, &patch) != 3) {
            TEST_info("Error matching provider %s version: version %s\n", prov_name,
                      p);
            return -1;
        }
        r = match_funcs[mode](libctx, prov_name, major, minor, patch);
        if (r < 0) {
            TEST_info("Error matching provider %s version: internal error\n",
                      prov_name);
            return -1;
        }
        if (r == 0)
            return 0;
    }
    return 1;
}
