/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Parameter generation follows the updated Appendix 2.2 for FIPS PUB 186,
 * also Appendix 2.2 of FIPS PUB 186-1 (i.e. use SHA as defined in FIPS PUB
 * 180-1)
 */
#define xxxHASH    EVP_sha1()

#include <openssl/opensslconf.h>
#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "dsa_locl.h"

int DSA_generate_ffc_parameters(DSA *dsa, int type, int pbits, int qbits,
                                int gindex, BN_GENCB *cb)
{
    int res;

    if (qbits <= 0) {
        const EVP_MD *evpmd = pbits >= 2048 ? EVP_sha256() : EVP_sha1();

        qbits = EVP_MD_size(evpmd) * 8;
    }
    FFC_PARAMS_set0_gindex(&dsa->params, gindex);
#ifndef FIPS_MODE
    if (type == 1)
        return FFC_PARAMS_FIPS186_2_generate(&dsa->params, FFC_PARAM_TYPE_DSA,
                                             pbits, qbits, NULL, &res, cb);
    else
#endif
        return FFC_PARAMS_FIPS186_4_generate(&dsa->params, FFC_PARAM_TYPE_DSA,
                                             pbits, qbits, NULL, &res, cb);
}

int DSA_generate_parameters_ex(DSA *dsa, int bits,
                               const unsigned char *seed_in, int seed_len,
                               int *counter_ret, unsigned long *h_ret,
                               BN_GENCB *cb)
{
#ifndef FIPS_MODE
    if (dsa->meth->dsa_paramgen)
        return dsa->meth->dsa_paramgen(dsa, bits, seed_in, seed_len,
                                       counter_ret, h_ret, cb);
    else
#endif
    {
        if (seed_in != NULL
                && !DSA_set0_validate_params(dsa, seed_in, seed_len, -1, -1))
            return 0;

        if (!DSA_generate_ffc_parameters(dsa, 2, bits, -1, -1, cb))
            return 0;

        if (counter_ret != NULL || h_ret != NULL)
            DSA_get0_validate_params(dsa, NULL, NULL, counter_ret, NULL, h_ret);
        return 1;
    }
}
