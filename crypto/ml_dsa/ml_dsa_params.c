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
#include "ml_dsa_local.h"
#include "ml_dsa_params.h"

/*
 * See FIPS 204 Section 4 Table 1 & Table 2
 *                    tau strength gamma1 k l eta beta omega sc sklen  pklen siglen
 */
#define OSSL_ML_DSA_65  49, 192, 1 << 19, 6, 5, 4, 196, 55, 3, 4032, 1952, 3309

static const ML_DSA_PARAMS ml_dsa_params[] = {
    {"ML-DSA-65", OSSL_ML_DSA_65},
    {NULL},
};

/**
 * @brief A getter to convert an algorithm name into a ML_DSA_PARAMS object
 */
const ML_DSA_PARAMS *ossl_ml_dsa_params_get(const char *alg)
{
    const ML_DSA_PARAMS *p;

    if (alg == NULL)
        return NULL;
    for (p = ml_dsa_params; p->alg != NULL; ++p) {
        if (strcmp(p->alg, alg) == 0)
            return p;
    }
    return NULL;
}
