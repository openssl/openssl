/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "apps.h"
#include <openssl/err.h>
#include <openssl/provider.h>

/*
 * See comments in opt_verify for explanation of this.
 */
enum prov_range { OPT_PROV_ENUM };

static int opt_provider_load(const char *provider)
{
    OSSL_PROVIDER *prov;

    prov = OSSL_PROVIDER_load(NULL, provider);
    if (prov == NULL) {
        opt_printf_stderr("%s: unable to load provider %s\n",
                          opt_getprog(), provider);
        return 0;
    }
    return 1;
}

static int opt_provider_path(const char *path)
{
    if (path != NULL && *path == '\0')
        path = NULL;
    return OSSL_PROVIDER_set_default_search_path(NULL, path);
}

int opt_provider(int opt)
{
    switch ((enum prov_range)opt) {
    case OPT_PROV__FIRST:
    case OPT_PROV__LAST:
        return 1;
    case OPT_PROV_PROVIDER:
        return opt_provider_load(opt_arg());
    case OPT_PROV_PROVIDER_PATH:
        return opt_provider_path(opt_arg());
    }
    return 0;
}
