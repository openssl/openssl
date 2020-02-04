/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/dsa.h>

#define DSA_PARAMGEN_TYPE_FIPS_186_2   1   /* Use legacy FIPS186-2 standard */
#define DSA_PARAMGEN_TYPE_FIPS_186_4   2   /* Use FIPS186-4 standard */

int dsa_generate_parameters_ctx(OPENSSL_CTX *libctx, DSA *dsa, int bits,
                               const unsigned char *seed_in, int seed_len,
                               int *counter_ret, unsigned long *h_ret,
                               BN_GENCB *cb);

int dsa_generate_ffc_parameters(OPENSSL_CTX *libctx, DSA *dsa, int type,
                                int pbits, int qbits, int gindex,
                                BN_GENCB *cb);

int dsa_sign_int(OPENSSL_CTX *libctx, int type, const unsigned char *dgst,
                 int dlen, unsigned char *sig, unsigned int *siglen, DSA *dsa);
int dsa_generate_key_ctx(OPENSSL_CTX *libctx, DSA *dsa);
const unsigned char *dsa_algorithmidentifier_encoding(int md_nid, size_t *len);
