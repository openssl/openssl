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
#define ML_DSA_44_TAU 39
#define ML_DSA_44_LAMBDA 128
#define ML_DSA_44_K 4
#define ML_DSA_44_L 4
#define ML_DSA_44_ETA ML_DSA_ETA_2
#define ML_DSA_44_BETA 78
#define ML_DSA_44_OMEGA 80
#define ML_DSA_44_SECURITY_CATEGORY 2
#define ML_DSA_44_PRIV_LEN 2560
#define ML_DSA_44_PUB_LEN 1312
#define ML_DSA_44_SIG_LEN 2420

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

/* See FIPS 204 Section 4 Table 1 & Table 2 */
#define ML_DSA_87_TAU 60
#define ML_DSA_87_LAMBDA 256
#define ML_DSA_87_K 8
#define ML_DSA_87_L 7
#define ML_DSA_87_ETA ML_DSA_ETA_2
#define ML_DSA_87_BETA 120
#define ML_DSA_87_OMEGA 75
#define ML_DSA_87_SECURITY_CATEGORY 5
#define ML_DSA_87_PRIV_LEN 4896
#define ML_DSA_87_PUB_LEN 2592
#define ML_DSA_87_SIG_LEN 4627

static const ML_DSA_PARAMS ml_dsa_params[] = {
    { "ML-DSA-44",
      ML_DSA_44_TAU,
      ML_DSA_44_LAMBDA,
      ML_DSA_GAMMA1_TWO_POWER_17,
      ML_DSA_GAMMA2_Q_MINUS1_DIV88,
      ML_DSA_44_K,
      ML_DSA_44_L,
      ML_DSA_44_ETA,
      ML_DSA_44_BETA,
      ML_DSA_44_OMEGA,
      ML_DSA_44_SECURITY_CATEGORY,
      ML_DSA_44_PRIV_LEN,
      ML_DSA_44_PUB_LEN,
      ML_DSA_44_SIG_LEN
    },
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
    { "ML-DSA-87",
      ML_DSA_87_TAU,
      ML_DSA_87_LAMBDA,
      ML_DSA_GAMMA1_TWO_POWER_19,
      ML_DSA_GAMMA2_Q_MINUS1_DIV32,
      ML_DSA_87_K,
      ML_DSA_87_L,
      ML_DSA_87_ETA,
      ML_DSA_87_BETA,
      ML_DSA_87_OMEGA,
      ML_DSA_87_SECURITY_CATEGORY,
      ML_DSA_87_PRIV_LEN,
      ML_DSA_87_PUB_LEN,
      ML_DSA_87_SIG_LEN
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
