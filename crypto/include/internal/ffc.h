/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef HEADER_FFC_H
# define HEADER_FFC_H

# include <openssl/ossl_typ.h>
# include <openssl/bn.h>
# include <openssl/evp.h>
# include <openssl/dh.h>


/* Default value for gindex when canonical generation of g is not used */
# define FFC_UNVERIFIABLE_GINDEX -1

/* The different types of FFC keys */
# define FFC_PARAM_TYPE_DSA  0
# define FFC_PARAM_TYPE_DH   1


/* Return codes for generation and validation of FFC parameters */
#define FFC_PARAMS_RET_STATUS_FAILED  0
#define FFC_PARAMS_RET_STATUS_SUCCESS 1
/* Returned if validating and g is only partially verifiable */
#define FFC_PARAMS_RET_STATUS_UNVERIFIABLE_G 2

/* Validation flags */
# define FFC_PARAMS_GENERATE      0x00
# define FFC_PARAMS_VALIDATE_PQ   0x01
# define FFC_PARAMS_VALIDATE_G    0x02
# define FFC_PARAMS_VALIDATE_ALL  \
    (FFC_PARAMS_VALIDATE_PQ | FFC_PARAMS_VALIDATE_G)


/* Return codes */
# define FFC_ERROR_PUBKEY_TOO_SMALL       0x01
# define FFC_ERROR_PUBKEY_TOO_LARGE       0x02
# define FFC_ERROR_PUBKEY_INVALID         0x04
# define FFC_ERROR_NOT_SUITABLE_GENERATOR 0x08
# define FFC_ERROR_PRIVKEY_TOO_SMALL      0x10
# define FFC_ERROR_PRIVKEY_TOO_LARGE      0x20

# define FFC_CHECK_P_NOT_PRIME                DH_CHECK_P_NOT_PRIME
# define FFC_CHECK_P_NOT_SAFE_PRIME           DH_CHECK_P_NOT_SAFE_PRIME
# define FFC_CHECK_UNKNOWN_GENERATOR          DH_UNABLE_TO_CHECK_GENERATOR
# define FFC_CHECK_NOT_SUITABLE_GENERATOR     DH_NOT_SUITABLE_GENERATOR
# define FFC_CHECK_Q_NOT_PRIME                DH_CHECK_Q_NOT_PRIME
# define FFC_CHECK_INVALID_Q_VALUE            DH_CHECK_INVALID_Q_VALUE
# define FFC_CHECK_INVALID_J_VALUE            DH_CHECK_INVALID_J_VALUE
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

typedef struct ffc_params_st {
    /* Primes */
    BIGNUM *p;
    BIGNUM *q;
    /* Generator */
    BIGNUM *g;
    /* DH X9.42 Optional Subgroup factor j >= 2 where p = jq+ 1 */
    BIGNUM *j;

    /* Required for FIPS186_4 validation of p,q, and optionally canonical g */
    unsigned char *seed;
    /* If this value is zero the hash size is used as the seed length */
    size_t seedlen;
    /* Required for FIPS186_4 validation of p,q */
    int pcounter;
    /*
     * Required for FIPS186_4 generation & validation of canonical g.
     * It uses unverifiable g if this value is -1.
     */
    int gindex;
    int h; /* loop counter for unverifiable g */
} FFC_PARAMS;

void FFC_PARAMS_init(FFC_PARAMS *params);
void FFC_PARAMS_cleanup(FFC_PARAMS *params);
void FFC_PARAMS_set0_pqg(FFC_PARAMS *params, BIGNUM *p, BIGNUM *q, BIGNUM *g);
void FFC_PARAMS_set0_j(FFC_PARAMS *params, BIGNUM *j);
void FFC_PARAMS_set0_gindex(FFC_PARAMS *params, int gindex);
int FFC_PARAMS_set_validate_params(FFC_PARAMS *params, const unsigned char *seed,
                                   size_t seedlen, int pcounter);

void FFC_PARAMS_get0_pqg(const FFC_PARAMS *params, const BIGNUM **p,
                         const BIGNUM **q, const BIGNUM **g);
const BIGNUM *FFC_PARAMS_get0_p(const FFC_PARAMS *params);
const BIGNUM *FFC_PARAMS_get0_q(const FFC_PARAMS *params);
const BIGNUM *FFC_PARAMS_get0_g(const FFC_PARAMS *params);
const BIGNUM *FFC_PARAMS_get0_j(const FFC_PARAMS *params);
int FFC_PARAMS_get0_gindex(const FFC_PARAMS *params);
int FFC_PARAMS_get0_h(const FFC_PARAMS *params);

void FFC_PARAMS_get_validate_params(const FFC_PARAMS *params,
                                    unsigned char **seed, size_t *seedlen,
                                    int *pcounter);
int FFC_PARAMS_copy(FFC_PARAMS *dst, const FFC_PARAMS *src);
int FFC_PARAMS_cmp(const FFC_PARAMS *a, const FFC_PARAMS *b);
int FFC_PARAMS_print(BIO *bp, const FFC_PARAMS *ffc, int indent);

int FFC_PARAMS_FIPS186_4_generate(FFC_PARAMS *params, int type, size_t L,
                                  size_t N, const EVP_MD *evpmd, int *res,
                                  BN_GENCB *cb);
int FFC_PARAMS_FIPS186_2_generate(FFC_PARAMS *params, int type, size_t L,
                                  size_t N, const EVP_MD *evpmd, int *res,
                                  BN_GENCB *cb);
int FFC_PARAMS_FIPS186_4_validate(const FFC_PARAMS *params, int type,
                                  const EVP_MD *evpmd, int validate_flags,
                                  int *res, BN_GENCB *cb);
int FFC_PARAMS_FIPS186_2_validate(const FFC_PARAMS *params, int type,
                                  const EVP_MD *evpmd, int validate_flags,
                                  int *res, BN_GENCB *cb);
int FFC_generate_priv_key(const FFC_PARAMS *params, int N, int s,
                          BIGNUM *priv_key);

int FFC_validate_pub_key(const FFC_PARAMS *params, const BIGNUM *pub_key,
                         int *ret);
int FFC_validate_pub_key_partial(const FFC_PARAMS *params,
                                 const BIGNUM *pub_key, int *ret);
int FFC_validate_priv_key(const BIGNUM *upper, const BIGNUM *priv_key, int *ret);

#endif

