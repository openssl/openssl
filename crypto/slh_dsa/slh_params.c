/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stddef.h>
#include <string.h>
#include "slh_params.h"

/*
 * See FIPS 205 Section 11 Table 2
 *                         n  h    d  hm  a   k  m  sc  pk   sig
 */
#define OSSL_SLH_DSA_128S 16, 63,  7, 9, 12, 14, 30, 1, 32,  7856

static const SLH_DSA_PARAMS slh_dsa_params[] = {
    {"SLH-DSA-SHA2-128s",  0, OSSL_SLH_DSA_128S},
    {NULL},
};

/**
 * @brief A getter to convert an algorithm name into a SLH_DSA_PARAMS object
 */
const SLH_DSA_PARAMS *ossl_slh_dsa_params_get(const char *alg)
{
    const SLH_DSA_PARAMS *p;

    for (p = slh_dsa_params; p->alg != NULL; ++p) {
        if (strcmp(p->alg, alg) == 0)
            return p;
    }
    return NULL;
}
