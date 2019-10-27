/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include "prov/callback.h"

static OSSL_core_generic_callback_fn *c_generic_callback = NULL;

int ossl_prov_callback_from_dispatch(const OSSL_DISPATCH *fns)
{
    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_CORE_GENERIC_CALLBACK:
            c_generic_callback = OSSL_get_core_generic_callback(fns);
            break;
        }
    }

    return 1;
}

int ossl_prov_generic_callback(OSSL_CALLBACK *cb, const OSSL_PARAM *params)
{
    if (c_generic_callback == NULL)
        return 0;
    return c_generic_callback(cb, params);
}
