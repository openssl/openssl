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
#include <openssl/safestack.h>

DEFINE_STACK_OF(OSSL_PROVIDER)

/*
 * See comments in opt_verify for explanation of this.
 */
enum prov_range { OPT_PROV_ENUM };

static STACK_OF(OSSL_PROVIDER) *app_providers = NULL;
static OPENSSL_CTX *libctx = NULL;

/*
 * NOTE: the loaded provider uses a static global libctx which will be NULL by
 * default, but can be set via a call to opt_provider_libctx()
 */
static int opt_provider_load(const char *provider)
{
    OSSL_PROVIDER *prov;

    prov = OSSL_PROVIDER_load(libctx, provider);
    if (prov == NULL) {
        opt_printf_stderr("%s: unable to load provider %s\n",
                          opt_getprog(), provider);
        return 0;
    }
    if (app_providers == NULL)
        app_providers = sk_OSSL_PROVIDER_new_null();
    if (app_providers == NULL
        || !sk_OSSL_PROVIDER_push(app_providers, prov)) {
        app_providers_cleanup();
        return 0;
    }
    return 1;
}

OPENSSL_CTX *opt_provider_libctx(void)
{
    /*
     * Load the NULL provider into the default library context and create a
     * library context which will then be used for any OPT_PROV options.
     */
    if (libctx == NULL) {
        if (!opt_provider_load("null")) {
            BIO_puts(bio_err, "Failed to create null provider\n");
            return NULL;
        }
        libctx = OPENSSL_CTX_new();
    }
    if (libctx == NULL)
        BIO_puts(bio_err, "Failed to create library context\n");
    return libctx;
}

static void provider_free(OSSL_PROVIDER *prov)
{
    OSSL_PROVIDER_unload(prov);
}

void app_providers_cleanup(void)
{
    sk_OSSL_PROVIDER_pop_free(app_providers, provider_free);
    app_providers = NULL;
    OPENSSL_CTX_free(libctx);
    libctx = NULL;
}

static int opt_provider_path(const char *path)
{
    if (path != NULL && *path == '\0')
        path = NULL;
    return OSSL_PROVIDER_set_default_search_path(libctx, path);
}

static int opt_libctx_load_config(const char *config_file)
{
    return OPENSSL_CTX_load_config(libctx, config_file);
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
    case OPT_PROV_LOAD_CONFIG:
        return opt_libctx_load_config(opt_arg());
    }
    return 0;
}
