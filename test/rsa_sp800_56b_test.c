/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include "internal/nelem.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include "testutil.h"
#include "rsa_locl.h"

#ifdef OPENSSL_NO_RSA
int setup_tests(void)
{
    /* No tests */
    return 1;
}
#else
# include <openssl/rsa.h>

/* taken from RSA2 cavs data */
static const char *cav_e = "010001";
static const char *cav_Xp =
    "cf721b9afd0d221a7450972276d8c0c2fd088105dd18219996d65c79e30281d70e3f3b34da"
    "61c92d8486621e3d5dbf922ecd353d6eb95916c9825041304567aab7beecea4b9ea0c305b3"
    "88d44cacebe403c6cacbd9d34ef67f2c271e086cc2d6451f84e43c9719deb855af0ecf9eb0"
    "9c20d31fa8d752c2951c8015424d4f1916";
static const char *cav_Xp1 =
    "ac5f7f6e333e973ab31744a90f7a5470270693d549de9183bc8a7b95";
const char *cav_Xp2 =
     "0bf6e8795a81ae901da438749c0e6fe003cfc453163217f7095fd9";
const char *cav_Xq =
    "feabf27c164af08d31c60a82e2aebb037e7b204e64b016ad3c011ad354bf2ba4029ec30d60"
    "3d1fb9c00de69768bb8c81d5c154960f99f0a8a2f3c68eecbc3117709824a33651a854bd9a"
    "89996e575ed03986c3a31bc7cfc44f47259e2c79e12ccce463f40284f8f6a15c9314f2685f"
    "3a902f4e5ef91605cf2163cafab00802c0";
const char *cav_Xq1 =
    "9b02d4baf0aa14996dc0b7a5e1d370b65aa29b59d58c1e9f3f9adeeb9e9c61d65ae1";
const char *cav_Xq2 = "068153fda87ba38590152c97b2a01748b07f0a016d";

/* expected values */
const char *cav_p1 = "ac5f7f6e333e973ab31744a90f7a5470270693d549de9183bc8a7bc3";
const char *cav_p2 = "0bf6e8795a81ae901da438749c0e6fe003cfc453163217f7095fd9";
const char *cav_q1 =
    "9b02d4baf0aa14996dc0b7a5e1d370b65aa29b59d58c1e9f3f9adeeb9e9c61d65d47";
const char *cav_q2 = "068153fda87ba38590152c97b2a01748b07f0a018f";
const char *cav_p =
    "cf721b9afd0d221a7450972276d8c0c2fd088105dd18219996d65c79e30281d70e3f3b34da"
    "61c92d8486621e3d5dbf922ecd353d6eb95916c9825041304567aab7beecea4b9ea0c305bc"
    "4c01a54bbda420b520d5596f825c8f4fe03a4e7efe44f33cc00e142b32e6288b638700c353"
    "4a5b717a5b2840c418b6770bab59a4967d";
const char *cav_q =
    "feabf27c164af08d31c60a82e2aebb037e7b204e64b016ad3c011ad354bf2ba4029ec30d60"
    "3d1fb9c00de69768bb8c81d5c154960f99f0a8a2f3c68eecbc3117709824a33651a854c444"
    "ddf77eda474a67445d4e75f04d0068e14aec1f45f9e6ca3895486fdc9d1ba34bfd084b54cd"
    "eb3def33116ecee45defa9585c874dc8cf";
const char *cav_n =
    "ce5e8d1aa3087a2db44948f006b6feba2f397c7be05d092d574e54609ce5084be11a73c15e"
    "2fb646d781cabc98d2f9ef1c928c8d99852852d6d5ab707e9ea98782c89564ebf06c0f3fe9"
    "02292e6da1ecbfdc23df824fab398dccac215114f8efec738086a3cf8fd5cf221fcc232fba"
    "cbf617cd3a1fd984b988a7780faac9040120725d2afe5bdd165aed83029639463730c10d87"
    "c2c83338ed3572e529f81f2360e12a5b1d6b533f07c4d9bb040c5c3f0bc4d4619694f10f4a"
    "49acded2e842b34a0b647a325f2b5b0f8b8be033233464f8b57f6960b871e9ff9242b1f723"
    "a8a792043d6bfff7abbb141f4c1097d56b7112fd93a04a3b757240961c5f40405713";

const char *cav_d =
    "4747491d662a4b68f5d84a24fd6cbf56b770f79a21c8809ef484cd880128ea50ab1363dfea"
    "1438b50742812fdae924027eafef74090e80fafbd11941e5ba0f7c0aa41555a2588c3a482c"
    "c6de4a76fb72b661e6d210444c33b8d274b19d3bcd2fb14fc398bd83b77e75e8a76aeecc51"
    "8c9917677f27f90d6ab7d4801789399cf3d70fdfb055801daf572ed0f04f426955bc83d697"
    "837ae6c6306d3db521a7c4620a20ce5e5a1798b36f6b9aeb6ba3c475d82bdc5c6fec5d49ac"
    "a8a42fb88c4f2e4621ee726a0e228071c87640446116bfa5f889c7e987dfbd2e4b4ec29753"
    "e9491c05b00b9b9f211941e9f561d7332e2c94b8a89a3acc6a248d1913eeb9b04861";


/* helper function */
static BIGNUM *bn_load_new(const char *str)
{
    BIGNUM *ret = BN_new();
    if (ret != NULL) {
        BN_hex2bn(&ret, str);
    }
    return ret;
}

/* helper function */
static BIGNUM *bn_load(BN_CTX *ctx, const char *str)
{
    BIGNUM *ret = BN_CTX_get(ctx);
    if (ret != NULL) {
        BN_hex2bn(&ret, str);
    }
    return ret;
}

static int test_check_public_exponent(void)
{
    int ret = 0;
    BIGNUM *e = NULL;

    ret = TEST_ptr(e = BN_new())
          /* e is too small */
          && TEST_true(BN_set_word(e, 65535))
          && TEST_false(rsa_check_public_exponent(e))
          /* e is even will fail */
          && TEST_true(BN_set_word(e, 65536))
          && TEST_false(rsa_check_public_exponent(e))
          /* e is ok */
          && TEST_true(BN_set_word(e, 65537))
          && TEST_true(rsa_check_public_exponent(e))
          /* e = 2^256 is too big */
          && TEST_true(BN_lshift(e, BN_value_one(), 256))
          && TEST_false(rsa_check_public_exponent(e))
          /* e = 2^256-1 is odd and in range */
          && TEST_true(BN_sub(e, e, BN_value_one()))
          && TEST_true(rsa_check_public_exponent(e));
    BN_free(e);
    return ret;
}

static int test_check_prime_factor_range(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL;

    /* (√2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2) - 1
     * For 8 bits:   0xB.504F <= p <= 0xF
     * for 72 bits:  0xB504F333F. <= p <= 0xF_FFFF_FFFF
     */
    ret = TEST_ptr(p = BN_new())
          && TEST_ptr(ctx = BN_CTX_new())
          && TEST_true(BN_set_word(p, 0xA))
          && TEST_false(rsa_check_prime_factor_range(p, 8, ctx))
          && TEST_true(BN_set_word(p, 0x10))
          && TEST_false(rsa_check_prime_factor_range(p, 8, ctx))
          && TEST_true(BN_set_word(p, 0xB))
          && TEST_true(rsa_check_prime_factor_range(p, 8, ctx))
          && TEST_true(BN_set_word(p, 0xF))
          && TEST_true(rsa_check_prime_factor_range(p, 8, ctx))

          && TEST_true(BN_set_word(p, 0xB504F333F))
          && TEST_false(rsa_check_prime_factor_range(p, 72, ctx))
          && TEST_true(BN_set_word(p, 0x1000000000))
          && TEST_false(rsa_check_prime_factor_range(p, 72, ctx))
          && TEST_true(BN_set_word(p, 0xB504F3340))
          && TEST_true(rsa_check_prime_factor_range(p, 72, ctx))
          && TEST_true(BN_set_word(p, 0xFFFFFFFFF))
          && TEST_true(rsa_check_prime_factor_range(p, 72, ctx));

    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_prime_factor(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *e = NULL;

    ret = TEST_ptr(p = BN_new())
          && TEST_ptr(e = BN_new())
          && TEST_ptr(ctx = BN_CTX_new())
          /* Fails the prime test */
          && TEST_true(BN_set_word(p, 0xb504f3373))
          && TEST_true(BN_set_word(e, 0x1))
          && TEST_false(rsa_check_prime_factor(p, e, 72, ctx))
          /* p is prime and in range and gcd(p-1, e) = 1 */
          && TEST_true(BN_set_word(p, 0xb504f3375))
          && TEST_true(rsa_check_prime_factor(p, e, 72, ctx))
          /* gcd(p-1,e) = 1 test fails */
          && TEST_true(BN_set_word(e, 0x2))
          && TEST_false(rsa_check_prime_factor(p, e, 72, ctx))
          /* p fails the range check */
          && TEST_true(BN_set_word(p, 0xb50000375))
          && TEST_true(BN_set_word(e, 0x1))
          && TEST_false(rsa_check_prime_factor(p, e, 72, ctx));

    BN_free(e);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_private_exponent(void)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL, *d = NULL, *n = NULL;

    ret = TEST_ptr(key = RSA_new())
          && TEST_ptr(ctx = BN_CTX_new())
          && TEST_ptr(p = BN_new())
          && TEST_ptr(q = BN_new())
          && TEST_ptr(e = BN_new())
          && TEST_ptr(d = BN_new())
          && TEST_ptr(n = BN_new())
          /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
          && TEST_true(BN_set_word(p, 15))
          && TEST_true(BN_set_word(q, 17))
          && TEST_true(BN_set_word(e, 5))
          && TEST_true(BN_set_word(d, 157))
          && TEST_true(BN_set_word(n, 15*17))
          && TEST_true(RSA_set0_factors(key, p, q))
          && TEST_true(RSA_set0_key(key, n, e, d))
          /* fails since d >= lcm(p-1, q-1) */
          && TEST_false(rsa_check_private_exponent(key, 8, ctx))
          && TEST_true(BN_set_word(d, 45))
          /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
          && TEST_true(rsa_check_private_exponent(key, 8, ctx))
          /* d is too small compared to nbits */
          && TEST_false(rsa_check_private_exponent(key, 16, ctx))
          /* d is too small compared to nbits */
          && TEST_true(BN_set_word(d, 16))
          && TEST_false(rsa_check_private_exponent(key, 8, ctx))
          /* fail if 1 != e.d mod lcm(p-1, q-1) */
          && TEST_true(BN_set_word(d, 46))
          && TEST_false(rsa_check_private_exponent(key, 8, ctx));

    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_crt_components(void)
{
    const int P = 15;
    const int Q = 17;
    const int E = 5;
    const int N = P*Q;
    const int DP = 3;
    const int DQ = 13;
    const int QINV = 8;

    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
          && TEST_ptr(ctx = BN_CTX_new())
          && TEST_ptr(p = BN_new())
          && TEST_ptr(q = BN_new())
          && TEST_ptr(e = BN_new())
          && TEST_true(BN_set_word(p, P))
          && TEST_true(BN_set_word(q, Q))
          && TEST_true(BN_set_word(e, E))
          && TEST_true(RSA_set0_factors(key, p, q))
          && TEST_true(rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx))
          && TEST_BN_eq_word(key->n, N)
          && TEST_BN_eq_word(key->dmp1, DP)
          && TEST_BN_eq_word(key->dmq1, DQ)
          && TEST_BN_eq_word(key->iqmp, QINV)
          && TEST_true(rsa_check_crt_components(key, ctx))
          /* (a) 1 < dP < (p – 1). */
          && TEST_true(BN_set_word(key->dmp1, 1))
          && TEST_false(rsa_check_crt_components(key, ctx))
          && TEST_true(BN_set_word(key->dmp1, P-1))
          && TEST_false(rsa_check_crt_components(key, ctx))
          && TEST_true(BN_set_word(key->dmp1, DP))
          /* (b) 1 < dQ < (q - 1). */
          && TEST_true(BN_set_word(key->dmq1, 1))
          && TEST_false(rsa_check_crt_components(key, ctx))
          && TEST_true(BN_set_word(key->dmq1, Q-1))
          && TEST_false(rsa_check_crt_components(key, ctx))
          && TEST_true(BN_set_word(key->dmq1, DQ))
          /* (c) 1 < qInv < p */
          && TEST_true(BN_set_word(key->iqmp, 1))
          && TEST_false(rsa_check_crt_components(key, ctx))
          && TEST_true(BN_set_word(key->iqmp, P))
          && TEST_false(rsa_check_crt_components(key, ctx))
          && TEST_true(BN_set_word(key->iqmp, QINV))
          /* (d) 1 = (dP . e) mod (p - 1)*/
          && TEST_true(BN_set_word(key->dmp1, DP+1))
          && TEST_false(rsa_check_crt_components(key, ctx))
          && TEST_true(BN_set_word(key->dmp1, DP))
          /* (e) 1 = (dQ . e) mod (q - 1) */
          && TEST_true(BN_set_word(key->dmq1, DQ-1))
          && TEST_false(rsa_check_crt_components(key, ctx))
          && TEST_true(BN_set_word(key->dmq1, DQ))
          /* (f) 1 = (qInv . q) mod p */
          && TEST_true(BN_set_word(key->iqmp, QINV+1))
          && TEST_false(rsa_check_crt_components(key, ctx))
          && TEST_true(BN_set_word(key->iqmp, QINV))
          /* check defaults are still valid */
          && TEST_true(rsa_check_crt_components(key, ctx));

    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_pq_diff(void)
{
    int ret = 0;
    BIGNUM *tmp = NULL, *p = NULL, *q = NULL;

    ret = TEST_ptr(tmp = BN_new())
          && TEST_ptr(p = BN_new())
          && TEST_ptr(q = BN_new())
          /* |1-(2+1)| > 2^1 */
          && TEST_true(BN_set_word(p, 1))
          && TEST_true(BN_set_word(q, 1+2))
          && TEST_false(rsa_check_pminusq_diff(tmp, p, q, 202))
          /* Check |p - q| > 2^(nbits/2 - 100) */
          && TEST_true(BN_set_word(q, 1+3))
          && TEST_true(rsa_check_pminusq_diff(tmp, p, q, 202))
          && TEST_true(BN_set_word(p, 1+3))
          && TEST_true(BN_set_word(q, 1))
          && TEST_true(rsa_check_pminusq_diff(tmp, p, q, 202));
    BN_free(p);
    BN_free(q);
    BN_free(tmp);
    return ret;
}

static int test_invalid_keypair(void)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *n = NULL, *e = NULL, *d = NULL;

    ret = TEST_ptr(key = RSA_new())
          && TEST_ptr(ctx = BN_CTX_new())
          /* NULL parameters */
          && TEST_false(rsa_sp800_56b_check_keypair(key, NULL, -1, 2048))
          /* load key */
          && TEST_ptr(p = bn_load_new(cav_p))
          && TEST_ptr(q = bn_load_new(cav_q))
          && TEST_ptr(e = bn_load_new(cav_e))
          && TEST_ptr(n = bn_load_new(cav_n))
          && TEST_ptr(d = bn_load_new(cav_d))
          && TEST_true(RSA_set0_key(key, n, e, d))
          && TEST_true(RSA_set0_factors(key, p, q))

          /* bad strength/key size */
          && TEST_false(rsa_sp800_56b_check_keypair(key, NULL, 100, 2048))
          && TEST_false(rsa_sp800_56b_check_keypair(key, NULL, 112, 1024))
          && TEST_false(rsa_sp800_56b_check_keypair(key, NULL, 128, 2048))
          && TEST_false(rsa_sp800_56b_check_keypair(key, NULL, 140, 3072))
          /* mismatching exponent */
          && TEST_false(rsa_sp800_56b_check_keypair(key, BN_value_one(), -1,
                        2048))
          /* bad exponent */
          && TEST_true(BN_add_word(e, 1))
          && TEST_false(rsa_sp800_56b_check_keypair(key, NULL, -1,
                                                    2048))
          && TEST_true(BN_sub_word(e, 1))

          /* mismatch between bits and modulus */
          && TEST_false(rsa_sp800_56b_check_keypair(key, NULL, -1, 3072))
          && TEST_true(rsa_sp800_56b_check_keypair(key, e, 112, 2048))
          /* check n == pq failure */
          && TEST_true(BN_add_word(n, 1))
          && TEST_false(rsa_sp800_56b_check_keypair(key, NULL, -1, 2048))
          && TEST_true(BN_sub_word(n, 1))
          /* check p  */
          && TEST_true(BN_sub_word(p, 2))
          && TEST_true(BN_mul(n, p, q, ctx))
          && TEST_false(rsa_sp800_56b_check_keypair(key, NULL, -1, 2048))
          && TEST_true(BN_add_word(p, 2))
          && TEST_true(BN_mul(n, p, q, ctx))
          /* check q  */
          && TEST_true(BN_sub_word(q, 2))
          && TEST_true(BN_mul(n, p, q, ctx))
          && TEST_false(rsa_sp800_56b_check_keypair(key, NULL, -1, 2048))
          && TEST_true(BN_add_word(q, 2))
          && TEST_true(BN_mul(n, p, q, ctx));

    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_fips1864_keygen_kat(void)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *e, *Xp, *Xp1, *Xp2, *Xq, *Xq1, *Xq2;
    BIGNUM *p1, *p2, *q1, *q2;
    BIGNUM *p1_exp, *p2_exp, *q1_exp, *q2_exp;
    BIGNUM *p_exp, *q_exp, *n_exp, *d_exp;
    const BIGNUM *p, *q, *n, *d, *e2;

    if (!(TEST_ptr(key = RSA_new()) && TEST_ptr(ctx = BN_CTX_new())))
        goto err;
    BN_CTX_start(ctx);

    e = bn_load(ctx, cav_e);
    Xp = bn_load(ctx, cav_Xp);
    Xp1 = bn_load(ctx, cav_Xp1);
    Xp2 = bn_load(ctx, cav_Xp2);
    Xq = bn_load(ctx, cav_Xq);
    Xq1 = bn_load(ctx, cav_Xq1);
    Xq2 = bn_load(ctx, cav_Xq2);
    p1_exp = bn_load(ctx, cav_p1);
    p2_exp = bn_load(ctx, cav_p2);
    q1_exp = bn_load(ctx, cav_q1);
    q2_exp = bn_load(ctx, cav_q2);
    p_exp = bn_load(ctx, cav_p);
    q_exp = bn_load(ctx, cav_q);
    n_exp = bn_load(ctx, cav_n);
    d_exp = bn_load(ctx, cav_d);
    p1 = BN_CTX_get(ctx);
    p2 = BN_CTX_get(ctx);
    q1 = BN_CTX_get(ctx);
    q2 = BN_CTX_get(ctx);
    ret = TEST_ptr(q2)
          && TEST_true(rsa_fips186_4_gen_prob_primes(key, p1, p2, NULL, Xp, Xp1,
                                                     Xp2, q1, q2, NULL, Xq, Xq1,
                                                     Xq2, 2048, e, ctx, NULL))
          && TEST_true(rsa_sp800_56b_derive_params_from_pq(key, 2048, e, ctx))
          && TEST_BN_eq(p1_exp, p1)
          && TEST_BN_eq(p2_exp, p2)
          && TEST_BN_eq(q1_exp, q1)
          && TEST_BN_eq(q2_exp, q2);
    if (!ret)
        goto err;

    RSA_get0_key(key, &n, &e2, &d);
    RSA_get0_factors(key, &p, &q);
    ret = TEST_BN_eq(e, e2)
          && TEST_BN_eq(p_exp, p)
          && TEST_BN_eq(q_exp, q)
          && TEST_BN_eq(n_exp, n)
          && TEST_BN_eq(d_exp, d);
err:
    RSA_free(key);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}


static int keygen_size[] =
{
    2048, 3072
};

static int test_sp80056b_keygen(int id)
{
    RSA *key = NULL;
    int ret;
    int sz = keygen_size[id];

    ret = TEST_ptr(key = RSA_new())
          && TEST_true(rsa_sp800_56b_generate_key(key, sz, NULL, NULL))
          && TEST_true(rsa_sp800_56b_check_public(key))
          && TEST_true(rsa_sp800_56b_check_private(key))
          && TEST_true(rsa_sp800_56b_check_keypair(key, NULL, -1, sz));

    RSA_free(key);
    return ret;
}

static int test_check_private_key(void)
{
    int ret = 0;
    BIGNUM *n = NULL, *d = NULL, *e = NULL;
    RSA *key = NULL;

    ret = TEST_ptr(key = RSA_new())
          /* check NULL pointers fail */
          && TEST_false(rsa_sp800_56b_check_private(key))
          /* load private key */
          && TEST_ptr(n = bn_load_new(cav_n))
          && TEST_ptr(d = bn_load_new(cav_d))
          && TEST_ptr(e = bn_load_new(cav_e))
          && TEST_true(RSA_set0_key(key, n, e, d))
          /* check d is in range */
          && TEST_true(rsa_sp800_56b_check_private(key))
          /* check d is too low */
          && TEST_true(BN_set_word(d, 0))
          && TEST_false(rsa_sp800_56b_check_private(key))
          /* check d is too high */
          && TEST_ptr(BN_copy(d, n))
          && TEST_false(rsa_sp800_56b_check_private(key));

    RSA_free(key);
    return ret;
}

static int test_check_public_key(void)
{
    int ret = 0;
    BIGNUM *n = NULL, *e = NULL;
    RSA *key = NULL;

    ret = TEST_ptr(key = RSA_new())
          /* check NULL pointers fail */
          && TEST_false(rsa_sp800_56b_check_public(key))
          /* load public key */
          && TEST_ptr(e = bn_load_new(cav_e))
          && TEST_ptr(n = bn_load_new(cav_n))
          && TEST_true(RSA_set0_key(key, n, e, NULL))
          /* check public key is valid */
          && TEST_true(rsa_sp800_56b_check_public(key))
          /* check fail if n is even */
          && TEST_true(BN_add_word(n, 1))
          && TEST_false(rsa_sp800_56b_check_public(key))
          && TEST_true(BN_sub_word(n, 1))
          /* check fail if n is wrong number of bits */
          && TEST_true(BN_lshift1(n, n))
          && TEST_false(rsa_sp800_56b_check_public(key))
          && TEST_true(BN_rshift1(n, n))
          /* test odd exponent fails */
          && TEST_true(BN_add_word(e, 1))
          && TEST_false(rsa_sp800_56b_check_public(key))
          && TEST_true(BN_sub_word(e, 1))
          /* modulus fails composite check */
          && TEST_true(BN_add_word(n, 2))
          && TEST_false(rsa_sp800_56b_check_public(key));

    RSA_free(key);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_check_public_exponent);
    ADD_TEST(test_check_prime_factor_range);
    ADD_TEST(test_check_prime_factor);
    ADD_TEST(test_check_private_exponent);
    ADD_TEST(test_check_crt_components);
    ADD_TEST(test_check_private_key);
    ADD_TEST(test_check_public_key);
    ADD_TEST(test_invalid_keypair);
    ADD_TEST(test_pq_diff);
    ADD_TEST(test_fips1864_keygen_kat);
    ADD_ALL_TESTS(test_sp80056b_keygen, (int)OSSL_NELEM(keygen_size));
    return 1;
}
#endif
