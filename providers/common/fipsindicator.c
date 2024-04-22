/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/indicator.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "prov/fipsindicator.h"

void ossl_FIPS_INDICATOR_init(ossl_FIPS_INDICATOR *ind)
{
    ind->strict_checks = -1;
    ind->approved = -1;
}

void ossl_FIPS_INDICATOR_set_approved(ossl_FIPS_INDICATOR *ind, int approved)
{
    ind->approved = approved;
}

int ossl_FIPS_INDICATOR_get_approved(const ossl_FIPS_INDICATOR *ind)
{
    return ind->approved;
}

void ossl_FIPS_INDICATOR_set_strict(ossl_FIPS_INDICATOR *ind, int strict)
{
    ind->strict_checks = strict;
}

int ossl_FIPS_INDICATOR_get_strict(const ossl_FIPS_INDICATOR *ind)
{
    return ind->strict_checks;
}

/*
 * Can be used during application testing to log that an indicator was
 * triggered. The callback will return 1 if the application wants an error
 * to occur based on the indicator type and description.
 */
int ossl_FIPS_INDICATOR_callback(OSSL_LIB_CTX *libctx, const char *type,
                                 const char *desc)
{
    OSSL_CALLBACK *cb = NULL;
    void *cbarg = NULL;
    OSSL_PARAM params[3];

    OSSL_INDICATOR_get_callback(libctx, &cb, &cbarg);
    if (cb == NULL)
        return 1;

    params[0] =
        OSSL_PARAM_construct_utf8_string(OSSL_PROV_PARAM_INDICATOR_TYPE,
                                         (char *)type, 0);
    params[1] =
        OSSL_PARAM_construct_utf8_string(OSSL_PROV_PARAM_INDICATOR_DESC,
                                         (char *)desc, 0);
    params[2] = OSSL_PARAM_construct_end();

    return cb(params, cbarg);
}
