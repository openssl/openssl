/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal EVP utility functions */

#include <openssl/core.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/asn1.h>        /* evp_locl.h needs it */
#include <openssl/safestack.h>   /* evp_locl.h needs it */
#include "internal/evp_int.h"    /* evp_locl.h needs it */
#include "evp_locl.h"

int evp_do_ciph_getparams(const EVP_CIPHER *ciph, OSSL_PARAM params[])
{
    if (ciph->prov == NULL)
        return -2;
    if (ciph->get_params == NULL)
        return -1;
    return ciph->get_params(params);
}

int evp_do_ciph_ctx_getparams(const EVP_CIPHER *ciph, void *provctx,
                              OSSL_PARAM params[])
{
    if (ciph->prov == NULL)
        return -2;
    if (ciph->ctx_get_params == NULL)
        return -1;
    return ciph->ctx_get_params(provctx, params);
}

int evp_do_ciph_ctx_setparams(const EVP_CIPHER *ciph, void *provctx,
                              OSSL_PARAM params[])
{
    if (ciph->prov == NULL)
        return -2;
    if (ciph->ctx_set_params == NULL)
        return -1;
    return ciph->ctx_set_params(provctx, params);
}
