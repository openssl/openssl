/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_FFC_H
# define OSSL_INTERNAL_FFC_H

# include <openssl/bn.h>

/*
 * Finite field cryptography (FFC) domain parameters are used by DH and DSA.
 * Refer to FIPS186_4 Appendix A & B.
 */
typedef struct ffc_params_st {
    /* Primes */
    BIGNUM *p;
    BIGNUM *q;
    /* Generator */
    BIGNUM *g;
    /* DH X9.42 Optional Subgroup factor j >= 2 where p = j * q + 1 */
    BIGNUM *j;

    /* Required for FIPS186_4 validation of p, q and optionally canonical g */
    unsigned char *seed;
    /* If this value is zero the hash size is used as the seed length */
    size_t seedlen;
    /* Required for FIPS186_4 validation of p and q */
    int pcounter;

} FFC_PARAMS;

void ffc_params_init(FFC_PARAMS *params);
void ffc_params_cleanup(FFC_PARAMS *params);
void ffc_params_set0_pqg(FFC_PARAMS *params, BIGNUM *p, BIGNUM *q, BIGNUM *g);
void ffc_params_get0_pqg(const FFC_PARAMS *params, const BIGNUM **p,
                         const BIGNUM **q, const BIGNUM **g);
void ffc_params_set0_j(FFC_PARAMS *d, BIGNUM *j);
int ffc_params_set_validate_params(FFC_PARAMS *params,
                                   const unsigned char *seed, size_t seedlen,
                                   int counter);
void ffc_params_get_validate_params(const FFC_PARAMS *params,
                                    unsigned char **seed, size_t *seedlen,
                                    int *pcounter);

int ffc_params_copy(FFC_PARAMS *dst, const FFC_PARAMS *src);
int ffc_params_cmp(const FFC_PARAMS *a, const FFC_PARAMS *b, int ignore_q);

#ifndef FIPS_MODE
int ffc_params_print(BIO *bp, const FFC_PARAMS *ffc, int indent);
#endif /* FIPS_MODE */

#endif /* OSSL_INTERNAL_FFC_H */
