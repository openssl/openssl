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
#define OSSL_SLH_DSA_128F 16, 66, 22, 3,  6, 33, 34, 1, 32, 17088
#define OSSL_SLH_DSA_192S 24, 63,  7, 9, 14, 17, 39, 3, 48, 16224
#define OSSL_SLH_DSA_192F 24, 66, 22, 3,  8, 33, 42, 3, 48, 35664
#define OSSL_SLH_DSA_256S 32, 64,  8, 8, 14, 22, 47, 5, 64, 29792
#define OSSL_SLH_DSA_256F 32, 68, 17, 4,  9, 35, 49, 5, 64, 49856

static const SLH_DSA_PARAMS slh_dsa_params[] = {
    {"SLH-DSA-SHA2-128s",  0, OSSL_SLH_DSA_128S},
    {"SLH-DSA-SHAKE-128s", 1, OSSL_SLH_DSA_128S},
    {"SLH-DSA-SHA2-128f",  0, OSSL_SLH_DSA_128F},
    {"SLH-DSA-SHAKE-128f", 1, OSSL_SLH_DSA_128F},
    {"SLH-DSA-SHA2-192s",  0, OSSL_SLH_DSA_192S},
    {"SLH-DSA-SHAKE-192s", 1, OSSL_SLH_DSA_192S},
    {"SLH-DSA-SHA2-192f",  0, OSSL_SLH_DSA_192F},
    {"SLH-DSA-SHAKE-192f", 1, OSSL_SLH_DSA_192F},
    {"SLH-DSA-SHA2-256s",  0, OSSL_SLH_DSA_256S},
    {"SLH-DSA-SHAKE-256s", 1, OSSL_SLH_DSA_256S},
    {"SLH-DSA-SHA2-256f",  0, OSSL_SLH_DSA_256F},
    {"SLH-DSA-SHAKE-256f", 1, OSSL_SLH_DSA_256F},
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
