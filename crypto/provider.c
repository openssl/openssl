/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/cryptoerr.h>
#include <openssl/provider.h>
#include "internal/provider.h"

OSSL_PROVIDER *OSSL_PROVIDER_load(OPENSSL_CTX *libctx, const char *name)
{
    OSSL_PROVIDER *prov = NULL;

    /* Find it or create it */
    if ((prov = ossl_provider_find(libctx, name)) == NULL
        && (prov = ossl_provider_new(libctx, name, NULL)) == NULL)
        return NULL;

    if (!ossl_provider_activate(prov)) {
        ossl_provider_free(prov);
        return NULL;
    }

    return prov;
}

int OSSL_PROVIDER_unload(OSSL_PROVIDER *prov)
{
    ossl_provider_free(prov);
    return 1;
}

const OSSL_ITEM *OSSL_PROVIDER_get_param_types(OSSL_PROVIDER *prov)
{
    return ossl_provider_get_param_types(prov);
}

int OSSL_PROVIDER_get_params(OSSL_PROVIDER *prov, const OSSL_PARAM params[])
{
    return ossl_provider_get_params(prov, params);
}

int OSSL_PROVIDER_add_builtin(OPENSSL_CTX *libctx, const char *name,
                              OSSL_provider_init_fn *init_fn)
{
    OSSL_PROVIDER *prov = NULL;

    if (name == NULL || init_fn == NULL) {
        CRYPTOerr(CRYPTO_F_OSSL_PROVIDER_ADD_BUILTIN,
                  ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* Create it */
    if ((prov = ossl_provider_new(libctx, name, init_fn)) == NULL)
        return 0;

    /*
     * It's safely stored in the internal store at this point,
     * free the returned extra reference
     */
    ossl_provider_free(prov);

    return 1;
}
