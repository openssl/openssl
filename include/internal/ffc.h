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
# include <openssl/evp.h>
# include <openssl/dh.h> /* Uses Error codes from DH */

/* Default value for gindex when canonical generation of g is not used */
# define FFC_UNVERIFIABLE_GINDEX -1

/* The different types of FFC keys */
# define FFC_PARAM_TYPE_DSA  0
# define FFC_PARAM_TYPE_DH   1

/* Return codes for generation and validation of FFC parameters */
#define FFC_PARAMS_RET_STATUS_FAILED         0
#define FFC_PARAMS_RET_STATUS_SUCCESS        1
/* Returned if validating and g is only partially verifiable */
#define FFC_PARAMS_RET_STATUS_UNVERIFIABLE_G 2

/* Validation flags */
# define FFC_PARAMS_GENERATE     0x00
# define FFC_PARAMS_VALIDATE_PQ  0x01
# define FFC_PARAMS_VALIDATE_G   0x02
# define FFC_PARAMS_VALIDATE_ALL (FFC_PARAMS_VALIDATE_PQ | FFC_PARAMS_VALIDATE_G)

/*
 * NB: These values must align with the equivalently named macros in
 * openssl/dh.h. We cannot use those macros here in case DH has been disabled.
 */
# define FFC_CHECK_P_NOT_PRIME                0x00001
# define FFC_CHECK_P_NOT_SAFE_PRIME           0x00002
# define FFC_CHECK_UNKNOWN_GENERATOR          0x00004
# define FFC_CHECK_NOT_SUITABLE_GENERATOR     0x00008
# define FFC_CHECK_Q_NOT_PRIME                0x00010
# define FFC_CHECK_INVALID_Q_VALUE            0x00020
# define FFC_CHECK_INVALID_J_VALUE            0x00040

# define FFC_CHECK_BAD_LN_PAIR                0x00080
# define FFC_CHECK_INVALID_SEED_SIZE          0x00100
# define FFC_CHECK_MISSING_SEED_OR_COUNTER    0x00200
# define FFC_CHECK_INVALID_G                  0x00400
# define FFC_CHECK_INVALID_PQ                 0x00800
# define FFC_CHECK_INVALID_COUNTER            0x01000
# define FFC_CHECK_P_MISMATCH                 0x02000
# define FFC_CHECK_Q_MISMATCH                 0x04000
# define FFC_CHECK_G_MISMATCH                 0x08000
# define FFC_CHECK_COUNTER_MISMATCH           0x10000

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
    int nid; /* The identity of a named group */

    /*
     * Required for FIPS186_4 generation & validation of canonical g.
     * It uses unverifiable g if this value is -1.
     */
    int gindex;
    int h; /* loop counter for unverifiable g */
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


int ffc_params_FIPS186_4_generate(OPENSSL_CTX *libctx, FFC_PARAMS *params,
                                  int type, size_t L, size_t N,
                                  const EVP_MD *evpmd, int *res, BN_GENCB *cb);
int ffc_params_FIPS186_2_generate(OPENSSL_CTX *libctx, FFC_PARAMS *params,
                                  int type, size_t L, size_t N,
                                  const EVP_MD *evpmd, int *res, BN_GENCB *cb);

int ffc_param_FIPS186_4_gen_verify(OPENSSL_CTX *libctx, FFC_PARAMS *params,
                                   int type, size_t L, size_t N,
                                   const EVP_MD *evpmd, int validate_flags,
                                   int *res, BN_GENCB *cb);
int ffc_param_FIPS186_2_gen_verify(OPENSSL_CTX *libctx, FFC_PARAMS *params,
                                   int type, size_t L, size_t N,
                                   const EVP_MD *evpmd, int validate_flags,
                                   int *res, BN_GENCB *cb);

int ffc_generate_private_key(BN_CTX *ctx, const FFC_PARAMS *params,
                             int N, int s, BIGNUM *priv);

int ffc_params_validate_unverifiable_g(BN_CTX *ctx, BN_MONT_CTX *mont,
                                       const BIGNUM *p, const BIGNUM *q,
                                       const BIGNUM *g, BIGNUM *tmp, int *ret);

#endif /* OSSL_INTERNAL_FFC_H */
