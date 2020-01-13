/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/err.h>
#include <opentls/cryptoerr.h>
#include <opentls/provider.h>
#include "internal/provider.h"

Otls_PROVIDER *Otls_PROVIDER_load(OPENtls_CTX *libctx, const char *name)
{
    Otls_PROVIDER *prov = NULL;

    /* Find it or create it */
    if ((prov = otls_provider_find(libctx, name, 0)) == NULL
        && (prov = otls_provider_new(libctx, name, NULL, 0)) == NULL)
        return NULL;

    if (!otls_provider_activate(prov)) {
        otls_provider_free(prov);
        return NULL;
    }

    return prov;
}

int Otls_PROVIDER_unload(Otls_PROVIDER *prov)
{
    otls_provider_free(prov);
    return 1;
}

int Otls_PROVIDER_available(OPENtls_CTX *libctx, const char *name)
{
    Otls_PROVIDER *prov = NULL;
    int available = 0;

    /* Find it or create it */
    prov = otls_provider_find(libctx, name, 0);
    available = otls_provider_available(prov);
    otls_provider_free(prov);
    return available;
}

const Otls_PARAM *Otls_PROVIDER_gettable_params(const Otls_PROVIDER *prov)
{
    return otls_provider_gettable_params(prov);
}

int Otls_PROVIDER_get_params(const Otls_PROVIDER *prov, Otls_PARAM params[])
{
    return otls_provider_get_params(prov, params);
}

int Otls_PROVIDER_add_builtin(OPENtls_CTX *libctx, const char *name,
                              Otls_provider_init_fn *init_fn)
{
    Otls_PROVIDER *prov = NULL;

    if (name == NULL || init_fn == NULL) {
        CRYPTOerr(CRYPTO_F_Otls_PROVIDER_ADD_BUILTIN,
                  ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* Create it */
    if ((prov = otls_provider_new(libctx, name, init_fn, 0)) == NULL)
        return 0;

    /*
     * It's safely stored in the internal store at this point,
     * free the returned extra reference
     */
    otls_provider_free(prov);

    return 1;
}

const char *Otls_PROVIDER_name(const Otls_PROVIDER *prov)
{
    return otls_provider_name(prov);
}
