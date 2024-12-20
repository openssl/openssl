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

/* See FIPS 204 Section 4 Table 1 & Table 2 */
#define ML_DSA_65_TAU 49
#define ML_DSA_65_LAMBDA 192
#define ML_DSA_65_K 6
#define ML_DSA_65_L 5
#define ML_DSA_65_ETA ML_DSA_ETA_4
#define ML_DSA_65_BETA 196
#define ML_DSA_65_OMEGA 55
#define ML_DSA_65_SECURITY_CATEGORY 3
#define ML_DSA_65_PRIV_LEN 4032
#define ML_DSA_65_PUB_LEN 1952
#define ML_DSA_65_SIG_LEN 3309

static const ML_DSA_PARAMS ml_dsa_params[] = {
    { "ML-DSA-65",
      ML_DSA_65_TAU,
      ML_DSA_65_LAMBDA,
      ML_DSA_GAMMA1_TWO_POWER_19,
      ML_DSA_GAMMA2_Q_MINUS1_DIV32,
      ML_DSA_65_K,
      ML_DSA_65_L,
      ML_DSA_65_ETA,
      ML_DSA_65_BETA,
      ML_DSA_65_OMEGA,
      ML_DSA_65_SECURITY_CATEGORY,
      ML_DSA_65_PRIV_LEN,
      ML_DSA_65_PUB_LEN,
      ML_DSA_65_SIG_LEN
    },
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
