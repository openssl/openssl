/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include <openssl/dsa.h>
#include "internal/ffc.h"

#define DSA_PARAMGEN_TYPE_FIPS_186_4   0   /* Use FIPS186-4 standard */
#define DSA_PARAMGEN_TYPE_FIPS_186_2   1   /* Use legacy FIPS186-2 standard */

DSA *dsa_new_with_ctx(OSSL_LIB_CTX *libctx);
void ossl_dsa_set0_libctx(DSA *d, OSSL_LIB_CTX *libctx);

int dsa_generate_ffc_parameters(DSA *dsa, int type, int pbits, int qbits,
                                BN_GENCB *cb);

int dsa_sign_int(int type, const unsigned char *dgst,
                 int dlen, unsigned char *sig, unsigned int *siglen, DSA *dsa);

FFC_PARAMS *dsa_get0_params(DSA *dsa);
int dsa_ffc_params_fromdata(DSA *dsa, const OSSL_PARAM params[]);
int dsa_key_fromdata(DSA *dsa, const OSSL_PARAM params[]);

int dsa_generate_public_key(BN_CTX *ctx, const DSA *dsa, const BIGNUM *priv_key,
                            BIGNUM *pub_key);
int dsa_check_params(const DSA *dsa, int *ret);
int dsa_check_pub_key(const DSA *dsa, const BIGNUM *pub_key, int *ret);
int dsa_check_pub_key_partial(const DSA *dsa, const BIGNUM *pub_key, int *ret);
int dsa_check_priv_key(const DSA *dsa, const BIGNUM *priv_key, int *ret);
int dsa_check_pairwise(const DSA *dsa);
