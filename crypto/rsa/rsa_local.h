/*
 * Copyright 2006-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_RSA_LOCAL_H
#define OSSL_CRYPTO_RSA_LOCAL_H

#include <openssl/rsa.h>
#include "internal/refcount.h"

#define RSA_MAX_PRIME_NUM       5
#define RSA_MIN_MODULUS_BITS    512

typedef struct rsa_prime_info_st {
    BIGNUM *r;
    BIGNUM *d;
    BIGNUM *t;
    /* save product of primes prior to this one */
    BIGNUM *pp;
    BN_MONT_CTX *m;
} RSA_PRIME_INFO;

DECLARE_ASN1_ITEM(RSA_PRIME_INFO)
DEFINE_STACK_OF(RSA_PRIME_INFO)

struct rsa_st {
    /*
     * The first parameter is used to pickup errors where this is passed
     * instead of an EVP_PKEY, it is set to 0
     */
    int pad;
    int32_t version;
    const RSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;
    /* for multi-prime RSA, defined in RFC 8017 */
    STACK_OF(RSA_PRIME_INFO) *prime_infos;
    /* If a PSS only key this contains the parameter restrictions */
    RSA_PSS_PARAMS *pss;
    /* be careful using this if the RSA structure is shared */
    CRYPTO_EX_DATA ex_data;
    CRYPTO_REF_COUNT references;
    int flags;
    /* Used to cache montgomery values */
    BN_MONT_CTX *_method_mod_n;
    BN_MONT_CTX *_method_mod_p;
    BN_MONT_CTX *_method_mod_q;
    /*
     * all BIGNUM values are actually in the following data, if it is not
     * NULL
     */
    char *bignum_data;
    BN_BLINDING *blinding;
    BN_BLINDING *mt_blinding;
    CRYPTO_RWLOCK *lock;

    int dirty_cnt;
};

struct rsa_meth_st {
    char *name;
    int (*rsa_pub_enc) (int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
    int (*rsa_pub_dec) (int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
    int (*rsa_priv_enc) (int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding);
    int (*rsa_priv_dec) (int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding);
    /* Can be null */
    int (*rsa_mod_exp) (BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);
    /* Can be null */
    int (*bn_mod_exp) (BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
    /* called at new */
    int (*init) (RSA *rsa);
    /* called at free */
    int (*finish) (RSA *rsa);
    /* RSA_METHOD_FLAG_* things */
    int flags;
    /* may be needed! */
    char *app_data;
    /*
     * New sign and verify functions: some libraries don't allow arbitrary
     * data to be signed/verified: this allows them to be used. Note: for
     * this to work the RSA_public_decrypt() and RSA_private_encrypt() should
     * *NOT* be used RSA_sign(), RSA_verify() should be used instead.
     */
    int (*rsa_sign) (int type,
                     const unsigned char *m, unsigned int m_length,
                     unsigned char *sigret, unsigned int *siglen,
                     const RSA *rsa);
    int (*rsa_verify) (int dtype, const unsigned char *m,
                       unsigned int m_length, const unsigned char *sigbuf,
                       unsigned int siglen, const RSA *rsa);
    /*
     * If this callback is NULL, the builtin software RSA key-gen will be
     * used. This is for behavioural compatibility whilst the code gets
     * rewired, but one day it would be nice to assume there are no such
     * things as "builtin software" implementations.
     */
    int (*rsa_keygen) (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
    int (*rsa_multi_prime_keygen) (RSA *rsa, int bits, int primes,
                                   BIGNUM *e, BN_GENCB *cb);
};

extern int int_rsa_verify(int dtype, const unsigned char *m,
                          unsigned int m_len, unsigned char *rm,
                          size_t *prm_len, const unsigned char *sigbuf,
                          size_t siglen, RSA *rsa);
/* Macros to test if a pkey or ctx is for a PSS key */
#define pkey_is_pss(pkey) (pkey->ameth->pkey_id == EVP_PKEY_RSA_PSS)
#define pkey_ctx_is_pss(ctx) (ctx->pmeth->pkey_id == EVP_PKEY_RSA_PSS)

RSA_PSS_PARAMS *rsa_pss_params_create(const EVP_MD *sigmd,
                                      const EVP_MD *mgf1md, int saltlen);
int rsa_pss_get_param(const RSA_PSS_PARAMS *pss, const EVP_MD **pmd,
                      const EVP_MD **pmgf1md, int *psaltlen);
/* internal function to clear and free multi-prime parameters */
void rsa_multip_info_free_ex(RSA_PRIME_INFO *pinfo);
void rsa_multip_info_free(RSA_PRIME_INFO *pinfo);
RSA_PRIME_INFO *rsa_multip_info_new(void);
int rsa_multip_calc_product(RSA *rsa);
int rsa_multip_cap(int bits);

uint16_t rsa_compute_security_bits(int n);

int rsa_sp800_56b_validate_strength(int nbits, int strength);
int rsa_check_pminusq_diff(BIGNUM *diff, const BIGNUM *p, const BIGNUM *q,
                           int nbits);
int rsa_get_lcm(BN_CTX *ctx, const BIGNUM *p, const BIGNUM *q,
                BIGNUM *lcm, BIGNUM *gcd, BIGNUM *p1, BIGNUM *q1,
                BIGNUM *p1q1);

int rsa_check_public_exponent(const BIGNUM *e);
int rsa_check_private_exponent(const RSA *rsa, int nbits, BN_CTX *ctx);
int rsa_check_prime_factor(BIGNUM *p, BIGNUM *e, int nbits, BN_CTX *ctx);
int rsa_check_prime_factor_range(const BIGNUM *p, int nbits, BN_CTX *ctx);
int rsa_check_crt_components(const RSA *rsa, BN_CTX *ctx);

int rsa_sp800_56b_pairwise_test(RSA *rsa, BN_CTX *ctx);
int rsa_sp800_56b_check_public(const RSA *rsa);
int rsa_sp800_56b_check_private(const RSA *rsa);
int rsa_sp800_56b_check_keypair(const RSA *rsa, const BIGNUM *efixed,
                                int strength, int nbits);
int rsa_sp800_56b_generate_key(RSA *rsa, int nbits, const BIGNUM *efixed,
                               BN_GENCB *cb);

int rsa_sp800_56b_derive_params_from_pq(RSA *rsa, int nbits,
                                        const BIGNUM *e, BN_CTX *ctx);
int rsa_fips186_4_gen_prob_primes(RSA *rsa, BIGNUM *p1, BIGNUM *p2,
                                  BIGNUM *Xpout, const BIGNUM *Xp,
                                  const BIGNUM *Xp1, const BIGNUM *Xp2,
                                  BIGNUM *q1, BIGNUM *q2, BIGNUM *Xqout,
                                  const BIGNUM *Xq, const BIGNUM *Xq1,
                                  const BIGNUM *Xq2, int nbits,
                                  const BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb);

#endif /* OSSL_CRYPTO_RSA_LOCAL_H */
