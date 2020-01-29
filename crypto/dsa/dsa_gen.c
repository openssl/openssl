/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/opensslconf.h>
#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "crypto/dsa.h"
#include "dsa_local.h"

int dsa_generate_ffc_parameters(OPENSSL_CTX *libctx, DSA *dsa, int type,
                                int pbits, int qbits, int gindex,
                                BN_GENCB *cb)
{
    int ret = 0, res;

    if (qbits <= 0) {
        const EVP_MD *evpmd = pbits >= 2048 ? EVP_sha256() : EVP_sha1();

        qbits = EVP_MD_size(evpmd) * 8;
    }
    dsa->params.gindex = gindex;
#ifndef FIPS_MODE
    if (type == DSA_PARAMGEN_TYPE_FIPS_186_2)
        ret = ffc_params_FIPS186_2_generate(libctx, &dsa->params,
                                            FFC_PARAM_TYPE_DSA,
                                            pbits, qbits, NULL, &res, cb);
    else
#endif
        ret = ffc_params_FIPS186_4_generate(libctx, &dsa->params,
                                            FFC_PARAM_TYPE_DSA,
                                            pbits, qbits, NULL, &res, cb);
    if (ret > 0)
        dsa->dirty_cnt++;
    return ret;
}

int dsa_generate_parameters_ctx(OPENSSL_CTX *libctx, DSA *dsa, int bits,
                                const unsigned char *seed_in, int seed_len,
                                int *counter_ret, unsigned long *h_ret,
                                BN_GENCB *cb)
{
#ifndef FIPS_MODE
    if (dsa->meth->dsa_paramgen)
        return dsa->meth->dsa_paramgen(dsa, bits, seed_in, seed_len,
                                       counter_ret, h_ret, cb);
#endif
    if (seed_in != NULL
        && !ffc_params_set_validate_params(&dsa->params, seed_in, seed_len, -1))
        return 0;

#ifndef FIPS_MODE
    /* The old code used FIPS 186-2 DSA Parameter generation */
    if (bits <= 1024 && seed_len == 20) {
        if (!dsa_generate_ffc_parameters(libctx, dsa,
                                         DSA_PARAMGEN_TYPE_FIPS_186_2,
                                         bits, 160, -1, cb))
            return 0;
    } else
#endif
    {
        if (!dsa_generate_ffc_parameters(libctx, dsa,
                                         DSA_PARAMGEN_TYPE_FIPS_186_4,
                                         bits, -1, -1, cb))
            return 0;
    }

    if (counter_ret != NULL)
        *counter_ret = dsa->params.pcounter;
    if (h_ret != NULL)
        *h_ret = dsa->params.h;
    return 1;
}

int DSA_generate_parameters_ex(DSA *dsa, int bits,
                               const unsigned char *seed_in, int seed_len,
                               int *counter_ret, unsigned long *h_ret,
                               BN_GENCB *cb)
{
    return dsa_generate_parameters_ctx(NULL, dsa, bits,
                                       seed_in, seed_len,
                                       counter_ret, h_ret, cb);
}
