/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "opentls/err.h"
#include "prov/digestcommon.h"
#include "prov/providercommonerr.h"

int digest_default_get_params(Otls_PARAM params[], size_t blksz, size_t paramsz,
                              unsigned long flags)
{
    Otls_PARAM *p = NULL;

    p = Otls_PARAM_locate(params, Otls_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !Otls_PARAM_set_size_t(p, blksz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = Otls_PARAM_locate(params, Otls_DIGEST_PARAM_SIZE);
    if (p != NULL && !Otls_PARAM_set_size_t(p, paramsz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = Otls_PARAM_locate(params, Otls_DIGEST_PARAM_FLAGS);
    if (p != NULL && !Otls_PARAM_set_ulong(p, flags)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

static const Otls_PARAM digest_default_known_gettable_params[] = {
    Otls_PARAM_size_t(Otls_DIGEST_PARAM_BLOCK_SIZE, NULL),
    Otls_PARAM_size_t(Otls_DIGEST_PARAM_SIZE, NULL),
    Otls_PARAM_ulong(Otls_DIGEST_PARAM_FLAGS, NULL),
    Otls_PARAM_END
};
const Otls_PARAM *digest_default_gettable_params(void)
{
    return digest_default_known_gettable_params;
}
