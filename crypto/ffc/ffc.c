/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Finite Field cryptography (FFC) is used for DSA and DH.
 * This file contains methods for generation and validation of
 * FFC Domain Parameters, and some helper functions for generation and
 * validation of FFC keys.
 *
 * The implementations are defined in FIPS 186-4 Appendix A (for use with DSA).
 * SP800-56Ar3 also refers to using FFC (for DH key agreement).
 * The DH case is only used for backwards compatibility (approved safe primes
 * should be used for new applications).
 *
 * NOTES:
 *   The DSA and DH standards are complex. i.e.
 *   The FIPS186-4 DSA/FFC Domain Parameters require p,q,seed and counter to
 *   validate. However the ASN1 for DSA consists of just p,q,g.
 *   The ASN1 for DH is either
 *     (1) p,g,[qlength] (which is completely unverifiable)
 *     (2) p,q,g, [j] [seed counter] (which is only verifiable if the optional
 *     [seed counter] is specified]. ((2) is defined in X9.42).
 *
 *  Note that the gindex used for canonical g verification is not saved in ASN1.
 *  This means that in order to verify FFC params correctly - values for
 *  seed, counter and gindex need to be stored in order to verify p,q,g.
 *
 * Currently in OPENSSL dsa param generation calculates the seed and counter
 * (but it can't save it via ASN1). DH on the other hand currently uses a non
 * FIPS safe prime generator (so it does not have a seed & counter).
 * The app dhparam also has an option to generate using dsa param generation
 * which it then converts from DSA to DH.
 */

#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/dsa.h>   /* uses DSS_prime_checks */
#include "internal/ffc.h"

void FFC_PARAMS_init(FFC_PARAMS *params)
{
    memset(params, 0, sizeof(FFC_PARAMS));
    params->gindex = FFC_UNVERIFIABLE_GINDEX;
    params->pcounter = -1;
}

void FFC_PARAMS_cleanup(FFC_PARAMS *params)
{
    BN_free(params->p);
    BN_free(params->q);
    BN_free(params->g);
    BN_free(params->j);
    OPENSSL_free(params->seed);
    FFC_PARAMS_init(params);
}

void FFC_PARAMS_set0_pqg(FFC_PARAMS *d, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    if (p != NULL && p != d->p) {
        BN_free(d->p);
        d->p = p;
    }
    if (q != NULL && q != d->q) {
        BN_free(d->q);
        d->q = q;
    }
    if (g != NULL && g != d->g) {
        BN_free(d->g);
        d->g = g;
    }
}

/* j is the fairly pointless 'cofactor' that is optionally output for ASN1. */
void FFC_PARAMS_set0_j(FFC_PARAMS *d, BIGNUM *j)
{
    BN_free(d->j);
    d->j = NULL;
    if (j != NULL)
        d->j = j;
}

/* gindex is used for canonical generation and verification of generator g */
void FFC_PARAMS_set0_gindex(FFC_PARAMS *d, int gindex)
{
    d->gindex = gindex;
}

void FFC_PARAMS_get0_pqg(const FFC_PARAMS *d, const BIGNUM **p,
                         const BIGNUM **q, const BIGNUM **g)
{
    if (p != NULL)
        *p = d->p;
    if (q != NULL)
        *q = d->q;
    if (g != NULL)
        *g = d->g;
}

const BIGNUM *FFC_PARAMS_get0_p(const FFC_PARAMS *d)
{
    return d->p;
}

const BIGNUM *FFC_PARAMS_get0_q(const FFC_PARAMS *d)
{
    return d->q;
}

const BIGNUM *FFC_PARAMS_get0_g(const FFC_PARAMS *d)
{
    return d->g;
}

const BIGNUM *FFC_PARAMS_get0_j(const FFC_PARAMS *d)
{
    return d->j;
}

int FFC_PARAMS_get0_gindex(const FFC_PARAMS *d)
{
    return d->gindex;
}
int FFC_PARAMS_get0_h(const FFC_PARAMS *d)
{
    return d->h;
}

int FFC_PARAMS_set_validate_params(FFC_PARAMS *params,
                                   const unsigned char *seed, size_t seedlen,
                                   int counter)
{
    if (params == NULL)
        return 0;

    if (params->seed != NULL)
        OPENSSL_free(params->seed);

    if (seed != NULL && seedlen > 0) {
        params->seed = OPENSSL_memdup(seed, seedlen);
        if (params->seed == NULL)
            return 0;
        params->seedlen = seedlen;
    } else {
        params->seed = NULL;
        params->seedlen = 0;
    }
    params->pcounter = counter;
    return 1;
}

void FFC_PARAMS_get_validate_params(const FFC_PARAMS *params,
                                    unsigned char **seed, size_t *seedlen,
                                    int *pcounter)
{
    if (seed != NULL)
        *seed = params->seed;
    if (seedlen != NULL)
        *seedlen = params->seedlen;
    if (pcounter != NULL)
        *pcounter = params->pcounter;
}

/* FIPS186-4 A.2.1 Unverifiable Generation of Generator g */
static int generate_unverifiable_g(BN_CTX *ctx, BN_MONT_CTX *mont, BIGNUM *g,
                                   BIGNUM *hbn, const BIGNUM *p,
                                   const BIGNUM *e,const BIGNUM *pm1,
                                   int *hret)
{
    int h = 2;

    /* Step (2): choose h (where 1 < h)*/
    if (!BN_set_word(hbn, h))
        return 0;

    for (;;) {
        /* Step (3): g = h^e % p */
        if (!BN_mod_exp_mont(g, hbn, e, p, ctx, mont))
            return 0;
        /* Step (4): Finish if g > 1 */
        if (BN_cmp(g, BN_value_one()) > 0)
            break;

        /* Step (2) Choose any h in the range 1 < h < (p-1) */
        if (!BN_add_word(hbn, 1) || BN_cmp(hbn, pm1) >= 0)
            return 0;
        ++h;
    }
    *hret = h;
    return 1;
}

/* FIPS186-4 A.2.2 Unverifiable partial validation of Generator g */
static int validate_unverifiable_g(BN_CTX *ctx, BN_MONT_CTX *mont,
                                   const BIGNUM *p, const BIGNUM *q,
                                   const BIGNUM *g, BIGNUM *tmp,
                                   int *ret)
{
    /*
     * A.2.2 Step (1) AND
     * A.2.4 Step (2)
     * Verify that 2 <= g <= (p - 1)
     */
    if (BN_cmp(g, BN_value_one()) <= 0 || BN_cmp(g, p) >= 0) {
        *ret |= FFC_ERROR_NOT_SUITABLE_GENERATOR;
        return 0;
    }

    /*
     * A.2.2 Step (2) AND
     * A.2.4 Step (3)
     * Check g^q mod p = 1
     */
    if (!BN_mod_exp_mont(tmp, g, q, p, ctx, mont))
        return 0;
    if (BN_cmp(tmp, BN_value_one()) != 0) {
        *ret |= FFC_ERROR_NOT_SUITABLE_GENERATOR;
        return 0;
    }
    return 1;
}

/*
 * FIPS186-4 A.2 Generation of canonical generator g.
 *
 * It requires the following values as input:
 *   'evpmd' digest, 'p' prime, 'e' cofactor, gindex and seed.
 * tmp is a passed in temporary BIGNUM.
 * mont is used in a BN_mod_exp_mont() with a modulus of p.
 * Returns a value in g.
 */
static int generate_canonical_g(BN_CTX *ctx, BN_MONT_CTX *mont,
                                const EVP_MD *evpmd, BIGNUM *g, BIGNUM *tmp,
                                const BIGNUM *p, const BIGNUM *e,
                                int gindex, unsigned char *seed, size_t seedlen)
{
    int ret = 0;
    int counter = 1;
    unsigned char md[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *mctx = NULL;
    int mdsize;

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto err;

    mdsize = EVP_MD_size(evpmd);
    if (mdsize <= 0)
        goto err;
   /*
    * A.2.3 Step (4) & (5)
    * A.2.4 Step (6) & (7)
    * counter = 0; counter += 1
    */
    for (counter = 1; counter <= 0xFFFF; ++counter) {
        /*
         * A.2.3 Step (7) & (8) & (9)
         * A.2.4 Step (9) & (10) & (11)
         * W = Hash(seed || "ggen" || index || counter)
         * g = W^e % p
         */
        static const unsigned char ggen[4] = { 0x67, 0x67, 0x65, 0x6e };

        md[0] = (unsigned char)(gindex & 0xff);
        md[1] = (unsigned char)((counter >> 8) & 0xff);
        md[2] = (unsigned char)(counter & 0xff);
        if (!(EVP_DigestInit_ex(mctx, evpmd, NULL)
                && EVP_DigestUpdate(mctx, seed, seedlen)
                && EVP_DigestUpdate(mctx, ggen, sizeof(ggen))
                && EVP_DigestUpdate(mctx, md, 3)
                && EVP_DigestFinal_ex(mctx, md, NULL)
                && (BN_bin2bn(md, mdsize, tmp) != NULL)
                && BN_mod_exp_mont(g, tmp, e, p, ctx, mont)))
                    return 0;
        /*
         * A.2.3 Step (10)
         * A.2.4 Step (12)
         * Found a value for g if (g >= 2)
         */
        if (BN_cmp(g, BN_value_one()) > 0) {
            ret = 1;
            break; /* found g */
        }
    }
err:
    EVP_MD_CTX_free(mctx);
    return ret;
}

/* Generation of p is the same for FIPS 186-4 & FIPS 186-2 */
static int generate_p(BN_CTX *ctx, const EVP_MD *evpmd, int max_counter, int n,
                      unsigned char *buf, size_t buf_len, const BIGNUM *q,
                      BIGNUM *p, int L, int checks, BN_GENCB *cb, int *counter,
                      int *res)
{
    int ret = -1;
    int i, j, k, r;
    unsigned char md[EVP_MAX_MD_SIZE];
    int mdsize;
    BIGNUM *W, *X, *tmp, *c, *test;

    BN_CTX_start(ctx);
    W = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    c = BN_CTX_get(ctx);
    test = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL)
        goto err;

    if (!BN_lshift(test, BN_value_one(), L - 1))
        goto err;

    mdsize = EVP_MD_size(evpmd);
    if (mdsize <= 0)
        goto err;

    /* A.1.1.2 Step (10) AND
     * A.1.1.2 Step (12)
     * offset = 1 (this is handled below)
     */
    /*
     * A.1.1.2 Step (11) AND
     * A.1.1.3 Step (13)
     */
    for (i = 0; i <= max_counter; i++) {
        if ((i != 0) && !BN_GENCB_call(cb, 0, i))
            goto err;

        BN_zero(W);
        /* seed_tmp buffer contains "seed + offset - 1" */
        for (j = 0; j <= n; j++) {
            /* obtain "seed + offset + j" by incrementing by 1: */
            for (k = (int)buf_len - 1; k >= 0; k--) {
                buf[k]++;
                if (buf[k] != 0)
                    break;
            }
            /*
             * A.1.1.2 Step (11.1) AND
             * A.1.1.3 Step (13.1)
             * tmp = V(j) = Hash((seed + offset + j) % 2^seedlen)
             */
            if (!(EVP_Digest(buf, buf_len, md, NULL, evpmd, NULL)
                    && (BN_bin2bn(md, mdsize, tmp) != NULL)
                    /*
                     * A.1.1.2 Step (11.2)
                     * A.1.1.3 Step (13.2)
                     * W += V(j) * 2^(outlen * j)
                     */
                    && BN_lshift(tmp, tmp, (mdsize << 3) * j)
                    && BN_add(W, W, tmp)))
                goto err;
        }

        /*
         * A.1.1.2 Step (11.3) AND
         * A.1.1.3 Step (13.3)
         * X = W + 2^(L-1) where W < 2^(L-1)
         */
        if (!(BN_mask_bits(W, L - 1)
                && BN_copy(X, W)
                && BN_add(X, X, test)
                /*
                 * A.1.1.2 Step (11.4) AND
                 * A.1.1.3 Step (13.4)
                 * c = X mod 2q
                 */
                && BN_lshift1(tmp, q)
                && BN_mod(c, X, tmp, ctx)
                /*
                 * A.1.1.2 Step (11.5) AND
                 * A.1.1.3 Step (13.5)
                 * p = X - (c - 1)
                 */
                && BN_sub(tmp, c, BN_value_one())
                && BN_sub(p, X, tmp)))
            goto err;

        /*
         * A.1.1.2 Step (11.6) AND
         * A.1.1.3 Step (13.6)
         * if (p < 2 ^ (L-1)) continue
         * This makes sure the top bit is set.
         */
        if (BN_cmp(p, test) >= 0) {
            /*
             * A.1.1.2 Step (11.7) AND
             * A.1.1.3 Step (13.7)
             * Test if p is prime
             * (This also makes sure the bottom bit is set)
             */
            r = BN_is_prime_fasttest_ex(p, checks, ctx, 1, cb);
            /* A.1.1.2 Step (11.8) : Return if p is prime */
            if (r > 0)
                goto found;
            if (r != 0)
                goto err;
        }
        /* Step (11.9) : offset = offset + n + 1 is done automagically */
    }
    /* No prime P found */
    ret = 0;
    *res |= FFC_CHECK_P_NOT_PRIME;
    goto err;
found:
    *counter = i;
    ret = 1;
    goto err;
err:
    BN_CTX_end(ctx);
    return ret;
}

static int generate_q_fips186_4(BN_CTX *ctx, BIGNUM *q, const EVP_MD *evpmd,
                                int qsize, int checks,
                                unsigned char *seed, size_t seedlen,
                                int generate_seed, int *retm, int *res,
                                BN_GENCB *cb)
{
    int ret = 0, r;
    int m = *retm;
    unsigned char md[EVP_MAX_MD_SIZE];
    int mdsize = EVP_MD_size(evpmd);
    unsigned char *pmd;

    /* find q */
    for (;;) {
        if(!BN_GENCB_call(cb, 0, m++))
            goto err;

        /* A.1.1.2 Step (5) : generate seed with size seed_len */
        if (generate_seed && RAND_bytes(seed, (int)seedlen) < 0)
            goto err;
        /*
         * A.1.1.2 Step (6) AND
         * A.1.1.3 Step (7)
         * U = Hash(seed) % (2^(N-1))
         */
        if (!EVP_Digest(seed, seedlen, md, NULL, evpmd, NULL))
            goto err;
        /* Take least significant bits of md */
        if (mdsize > qsize)
            pmd = md + mdsize - qsize;
        else
            pmd = md;
        if (mdsize < qsize)
            memset(md + mdsize, 0, qsize - mdsize);

        /*
         * A.1.1.2 Step (7) AND
         * A.1.1.3 Step (8)
         * q = U + 2^(N-1) + (1 - U %2) (This sets top and bottom bits)
         */
        pmd[0] |= 0x80;
        pmd[qsize-1] |= 0x01;
        if (!BN_bin2bn(pmd, qsize, q))
            goto err;

        /*
         * A.1.1.2 Step (8) AND
         * A.1.1.3 Step (9)
         * Test if q is prime
         */
        r = BN_is_prime_fasttest_ex(q, checks, ctx, 1, cb);
        if (r > 0) {
            ret = 1;
            goto err;
        }
        /*
         * A.1.1.3 Step (9) : If the provided seed didn't produce a prime q
         * return an error.
         */
        if (!generate_seed) {
            *res |= FFC_CHECK_Q_NOT_PRIME;
            goto err;
        }
        if (r != 0)
            goto err;
        /* A.1.1.2 Step (9) : if q is not prime, try another q */
    }
err:
    *retm = m;
    return ret;
}

static int generate_q_fips186_2(BN_CTX *ctx, BIGNUM *q, const EVP_MD *evpmd,
                                int checks,
                                unsigned char *buf,
                                unsigned char *seed, size_t qsize,
                                int generate_seed, int *retm, int *res,
                                BN_GENCB *cb)
{
    unsigned char buf2[EVP_MAX_MD_SIZE];
    unsigned char md[EVP_MAX_MD_SIZE];
    int i, r, ret = 0, m = *retm;

    /* find q */
    for (;;) {
        /* step 1 */
        if (!BN_GENCB_call(cb, 0, m++))
            goto err;

        if (generate_seed && RAND_bytes(seed, (int)qsize) <= 0)
            goto err;

        memcpy(buf, seed, qsize);
        memcpy(buf2, seed, qsize);

        /* precompute "SEED + 1" for step 7: */
        for (i = (int)qsize - 1; i >= 0; i--) {
            buf[i]++;
            if (buf[i] != 0)
                break;
        }

        /* step 2 */
        if (!EVP_Digest(seed, qsize, md, NULL, evpmd, NULL))
            goto err;
        if (!EVP_Digest(buf, qsize, buf2, NULL, evpmd, NULL))
            goto err;
        for (i = 0; i < (int)qsize; i++)
            md[i] ^= buf2[i];

        /* step 3 */
        md[0] |= 0x80;
        md[qsize - 1] |= 0x01;
        if (!BN_bin2bn(md, (int)qsize, q))
            goto err;

        /* step 4 */
        r = BN_is_prime_fasttest_ex(q, checks, ctx, generate_seed, cb);
        if (r > 0) {
            /* Found a prime */
            ret = 1;
            goto err;
        }
        if (r != 0)
            goto err; /* Exit if error */
        /* Try another iteration if it wasnt prime - was in old code.. */
        generate_seed = 1;
    }
err:
    *retm = m;
    return ret;
}

/*
 * Verify that the passed in L,N pair for DH or DSA is valid.
 * Returns 0 if invalid, otherwise it returns the security strength.
 */
static int ffc_validate_LN(size_t L, size_t N, int type)
{
    if (type == FFC_PARAM_TYPE_DH) {
        /* Valid DH L,N parameters from SP800-56Ar3 5.5.1 Table 1 */
        if (L == 2048 && (N == 224 || N == 256))
            return 112;
    } else if (type == FFC_PARAM_TYPE_DSA) {
        /* Valid DSA L,N parameters from FIPS 186-4 Section 4.2 */
        if (L == 1024 && N == 160)
            return 80;
        if (L == 2048 && (N == 224 || N == 256))
            return 112;
        if (L == 2048 && N == 256)
            return 112;
        if (L == 3072 && N == 256)
            return 128;
    }
    return 0;
}

/*
 * FIPS 186-4 Section C.3 Table C.1
 * Returns the minimum number of Miller Rabin iterations for a L, N pair
 * (where L = len(p), N = len(q))
 */
static int ffc_min_MillerRabin_iterations(size_t L, size_t N)
{
    if (L == 1024 && N == 160)
        return 40;
    if (L == 2048 && (N == 224 || N == 256))
        return 56;
    if (L == 3072 && N == 256)
        return 64;
    return 0;
}

/*
 * FIPS 186-4 FFC parameter generation (as defined in Appendix A).
 * The same code is used for validation (when validate_flags != 0)
 *
 * The primes p & q are generated/validated using:
 *   A.1.1.2 Generation or probable primes p & q using approved hash.
 *   A.1.1.3 Validation of generated probable primes
 *
 * Generator 'g' has 2 types in FIPS 186-4:
 *   (1) A.2.1 unverifiable generation of generator g.
 *       A.2.2 Assurance of the validity of unverifiable generator g.
 *   (2) A.2.3 Verifiable Canonical Generation of the generator g.
 *       A.2.4 Validation for Canonical Generation of the generator g.
 *
 * Notes:
 * (1) is only a partial validation of g, The validation of (2) requires
 * the seed and index used during generation as input.
 *
 * params: used to pass in values for generation and validation.
 *  For generation of p & q:
 *   - This is skipped if p & q are passed in.
 *   - If the seed is passed in then generation of p & q uses this seed (and if
 *     this fails an error will occur).
 *   - Otherwise the seed is generated, and values of p & q are generated and
 *     the value of seed and counter are optionally returned.
 *  For the generation of g (after the generation of p, q):
 *   - If the seed has been generated or passed in and a valid gindex is passed
 *     in then canonical generation of g is used otherwise unverifiable
 *     generation of g is chosen.
 *  For validation of p & q:
 *   - p, q, and the seed and counter used for generation must be passed in.
 *  For validation of g:
 *   - For a partial validation : p, q and g are required.
 *   - For a canonical validation : the gindex and seed used for generation are
 *     also required.
 * type: The key type - FFC_PARAM_TYPE_DSA or FFC_PARAM_TYPE_DH.
 * L: is the size of the prime p in bits (e.g 2048)
 * N: is the size of the prime q in bits (e.g 256)
 * evpmd: is the digest to use, If this value is NULL, then the digest is chosen
 *        using the value of N.
 * validate_flags:
 *  or generation: FFC_PARAMS_GENERATE.
 *  For validation one of:
 *   -FFC_PARAMS_VALIDATE_PQ
 *   -FFC_PARAMS_VALIDATE_G
 *   -FFC_PARAMS_VALIDATE_ALL
 * res: A returned failure reason (One of FFC_CHECK_???),
 *      or 0 for general failures.
 * cb: A callback (can be NULL) that is called during different phases
 *
 * Returns:
 *   - FFC_PARAMS_RET_STATUS_FAILED: if there was an error, or validation failed.
 *   - FFC_PARAMS_RET_STATUS_SUCCESS if the generation or validation succeeded.
 *   - FFC_PARAMS_RET_STATUS_UNVERIFIABLE_G if the validation of G succeeded,
 *     but G is unverifiable.
 */
static int ffc_param_FIPS186_4_gen_verify(FFC_PARAMS *params, int type,
                                          size_t L, size_t N,
                                          const EVP_MD *evpmd,
                                          int validate_flags, int *res,
                                          BN_GENCB *cb)
{
    int ok = FFC_PARAMS_RET_STATUS_FAILED;
    unsigned char *seed = NULL, *seed_tmp = NULL;
    int mdsize, checks, counter = 0, pcounter = 0, r = 0;
    size_t seedlen = 0;
    BIGNUM *tmp, *pm1, *e, *test;
    BIGNUM *g = NULL, *q = NULL, *p = NULL;
    BN_MONT_CTX *mont = NULL;
    int n = 0, m = 0, qsize = N >> 3;
    int canonical_g = 0, hret = -1;
    BN_CTX *ctx = NULL;
    EVP_MD_CTX *mctx = NULL;
    int generate = (validate_flags == 0);

    *res = 0;

    /*
     * A.1.1.2 Step (1) AND
     * A.1.1.3 Step (3)
     * Check that the L,N pair is an acceptable pair.
     */
    if (L <= N || !ffc_validate_LN(L, N, type)) {
        *res = FFC_CHECK_BAD_LN_PAIR;
        goto err;
    }

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto err;

    if (evpmd == NULL) {
        if (N == 160)
            evpmd = EVP_sha1();
        else if (N == 224)
            evpmd = EVP_sha224();
        else if (N == 256)
            evpmd = EVP_sha256();
    }

    mdsize = EVP_MD_size(evpmd);
    if (mdsize <= 0)
        goto err;

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    BN_CTX_start(ctx);
    g = BN_CTX_get(ctx);
    pm1 = BN_CTX_get(ctx);
    e = BN_CTX_get(ctx);
    test = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL)
        goto err;

    seedlen = params->seedlen;
    if (seedlen == 0)
        seedlen = (size_t)mdsize;
    /* If the seed was passed in - use this value as the seed */
    if (params->seed != NULL)
        seed = params->seed;

    if (generate) {
        /* For generation: p & q must both be NULL or NON-NULL */
        if ((params->p == NULL) != (params->q == NULL)) {
            *res = FFC_CHECK_INVALID_PQ;
            goto err;
        }
    } else {
        /* Validation of p,q requires seed and counter to be valid */
        if ((validate_flags & FFC_PARAMS_VALIDATE_PQ) != 0) {
            if (seed == NULL || params->pcounter < 0) {
                *res = FFC_CHECK_MISSING_SEED_OR_COUNTER;
                goto err;
            }
        }
        if ((validate_flags & FFC_PARAMS_VALIDATE_G) != 0) {
            /* validation of g also requires g to be set */
            if (params->g == NULL) {
                *res = FFC_CHECK_INVALID_G;
                goto err;
            }
        }
    }

    /*
     * If p & q are passed in and
     *   validate_flags = 0 then skip the generation of PQ.
     *   validate_flags = VALIDATE_G then also skip the validation of PQ.
     */
    if (params->p != NULL && ((validate_flags & FFC_PARAMS_VALIDATE_PQ) == 0)) {
        /* p and q already exists so only generate g */
        p = params->p;
        q = params->q;
        goto g_only;
        /* otherwise fall thru to validate p & q */
    }

    /* p & q will be used for generation and validation */
    p = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    if (q == NULL)
        goto err;

    /*
     * A.1.1.2 Step (2) AND
     * A.1.1.3 Step (6)
     * Return invalid if seedlen  < N
     */
    if ((seedlen * 8) < N) {
        *res = FFC_CHECK_INVALID_SEED_SIZE;
        goto err;
    }

    seed_tmp = OPENSSL_malloc(seedlen);
    if (seed_tmp == NULL)
        goto err;

    if (seed == NULL) {
        /* Validation requires the seed to be supplied */
        if (validate_flags) {
            *res = FFC_CHECK_MISSING_SEED_OR_COUNTER;
            goto err;
        }
        /* if the seed is not supplied then alloc a seed buffer */
        seed = OPENSSL_malloc(seedlen);
        if (seed == NULL)
            goto err;
    }

    /* A.1.1.2 Step (11): max loop count = 4L - 1 */
    counter = 4 * L - 1;
    /* Validation requires the counter to be supplied */
    if (validate_flags) {
        /* A.1.1.3 Step (4) : if (counter > (4L -1)) return INVALID */
        if (params->pcounter > counter) {
            *res = FFC_CHECK_INVALID_COUNTER;
            goto err;
        }
        counter = params->pcounter;
    }

    /*
     * A.1.1.2 Step (3) AND
     * A.1.1.3 Step (10)
     * n = floor(L / hash_outlen) - 1
     */
    n = (L - 1 ) / (mdsize << 3);

    /* Minimum number of iterations for MillerRabin Prime test */
    checks = ffc_min_MillerRabin_iterations(L, N);
    /* Calculate 2^(L-1): Used in step A.1.1.2 Step (11.3) */
    if (!BN_lshift(test, BN_value_one(), L - 1))
        goto err;

    for (;;) {
        if (!generate_q_fips186_4(ctx, q, evpmd, qsize, checks, seed,
                                  seedlen, seed != params->seed, &m, res, cb))
            goto err;
        /* A.1.1.3 Step (9): Verify that q matches the expected value */
        if (validate_flags && (BN_cmp(q, params->q) != 0)) {
            *res = FFC_CHECK_Q_MISMATCH;
            goto err;
        }
        if(!BN_GENCB_call(cb, 2, 0))
            goto err;
        if(!BN_GENCB_call(cb, 3, 0))
            goto err;

        memcpy(seed_tmp, seed, seedlen);
        r = generate_p(ctx, evpmd, counter, n, seed_tmp, seedlen, q, p, L,
                       checks, cb, &pcounter, res);
        if (r > 0)
            break; /* found p */
        if (r < 0)
            goto err;
        /*
         * A.1.1.3 Step (14):
         * If we get here we failed to get a p for the given seed. If the
         * seed is not random then it needs to fail (as it will always fail).
         */
        if (seed == params->seed) {
            *res = FFC_CHECK_P_NOT_PRIME;
            goto err;
        }
    }
    if(!BN_GENCB_call(cb, 2, 1))
        goto err;
    /*
     * Gets here if we found p.
     * A.1.1.3 Step (14): return error if i != counter OR computed_p != known_p.
     */
    if (validate_flags && (pcounter != counter || (BN_cmp(p, params->p) != 0)))
        goto err;

    /* If validating p & q only then skip the g validation test */
    if ((validate_flags & FFC_PARAMS_VALIDATE_ALL) == FFC_PARAMS_VALIDATE_PQ)
        goto pass;
g_only:
    if ((mont = BN_MONT_CTX_new()) == NULL)
        goto err;
    if (!BN_MONT_CTX_set(mont, p, ctx))
        goto err;

    if (((validate_flags & FFC_PARAMS_VALIDATE_G) != 0)
            && !validate_unverifiable_g(ctx, mont, p, q, params->g, tmp, res))
        goto err;

    /*
     * A.2.1 Step (1) AND
     * A.2.3 Step (3) AND
     * A.2.4 Step (5)
     * e = (p - 1) / q (i.e- Cofactor 'e' is given by p = q * e + 1)
     */
    if (!(BN_sub(pm1, p, BN_value_one()) && BN_div(e, NULL, pm1, q, ctx)))
        goto err;

    /* Canonical g requires a seed and index to be set */
    if ((seed != NULL) && (params->gindex != FFC_UNVERIFIABLE_GINDEX)) {
        canonical_g = 1;
        if (!generate_canonical_g(ctx, mont, evpmd, g, tmp, p, e,
                                  params->gindex, seed, seedlen)) {
            *res = FFC_CHECK_INVALID_G;
            goto err;
        }
        /* A.2.4 Step (13): Return valid if computed_g == g */
        if (validate_flags && BN_cmp(g, params->g) != 0) {
            *res = FFC_CHECK_G_MISMATCH;
            goto err;
        }
    } else if (generate) {
        if (!generate_unverifiable_g(ctx, mont, g, tmp, p, e, pm1, &hret))
            goto err;
    }

    if (!BN_GENCB_call(cb, 3, 1))
        goto err;

    if (generate) {
        if (p != params->p) {
            BN_free(params->p);
            params->p = BN_dup(p);
        }
        if (q != params->q) {
            BN_free(params->q);
            params->q = BN_dup(q);
        }
        if (g != params->g) {
            BN_free(params->g);
            params->g = BN_dup(g);
        }
        if (params->p == NULL || params->q == NULL || params->g == NULL)
            goto err;
        if (!FFC_PARAMS_set_validate_params(params, seed, seedlen, pcounter))
            goto err;
        params->h = hret;
    }
pass:
    if ((validate_flags & FFC_PARAMS_VALIDATE_G) != 0 && (canonical_g == 0))
        /* Return for the case where g is partially valid */
        ok = FFC_PARAMS_RET_STATUS_UNVERIFIABLE_G;
    else
        ok = FFC_PARAMS_RET_STATUS_SUCCESS;
err:
    if (seed != params->seed)
        OPENSSL_free(seed);
    OPENSSL_free(seed_tmp);
    if (ctx)
        BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_MONT_CTX_free(mont);
    EVP_MD_CTX_free(mctx);
    return ok;
}

int FFC_PARAMS_FIPS186_4_generate(FFC_PARAMS *params, int type, size_t L,
                                  size_t N, const EVP_MD *evpmd, int *res,
                                  BN_GENCB *cb)
{
    return ffc_param_FIPS186_4_gen_verify(params, type, L, N, evpmd, 0, res, cb);
}

int FFC_PARAMS_FIPS186_4_validate(const FFC_PARAMS *params, int type,
                                  const EVP_MD *evpmd, int validate_flags,
                                  int *res, BN_GENCB *cb)
{
    size_t L, N;

    if (params == NULL || params->p == NULL || params->q == NULL)
        return FFC_PARAMS_RET_STATUS_FAILED;
    /* A.1.1.3 Step (1..2) : L = len(p), N = len(q) */
    L = BN_num_bits(params->p);
    N = BN_num_bits(params->q);
    return ffc_param_FIPS186_4_gen_verify((FFC_PARAMS *)params, type, L, N,
                                          evpmd, validate_flags, res, cb);
}

static int ffc_param_FIPS186_2_gen_verify(FFC_PARAMS *params, int type,
                                          size_t L, size_t N,
                                          const EVP_MD *evpmd,
                                          int validate_flags, int *res,
                                          BN_GENCB *cb)
{
    int ok = FFC_PARAMS_RET_STATUS_FAILED;
    unsigned char seed[SHA256_DIGEST_LENGTH];
    unsigned char buf[SHA256_DIGEST_LENGTH];
    BIGNUM *r0, *test, *tmp, *g = NULL, *q = NULL, *p = NULL;
    BN_MONT_CTX *mont = NULL;
    size_t qsize = N >> 3;
    int n = 0, m = 0;
    int counter = 0, pcounter = 0, use_random_seed;
    int rv;
    BN_CTX *ctx = NULL;
    int hret = -1;
    int generate = (validate_flags == 0);
    unsigned char *seed_in = params->seed;
    size_t seed_len = params->seedlen;

    *res = 0;
#ifdef FIPS_MODE
    /*
     * FIPS 186-4 states that validation can only be done for this pair.
     * (Even though the original spec allowed L = 512 + 64*j (j = 0.. 8))
     */
    if (L != 1024 || N != 160) {
        *res = FFC_CHECK_BAD_LN_PAIR;
        return FFC_PARAMS_RET_STATUS_FAILED;
    }
#endif
    if (qsize != SHA_DIGEST_LENGTH
            && qsize != SHA224_DIGEST_LENGTH
            && qsize != SHA256_DIGEST_LENGTH) {
        /* invalid q size */
        *res = FFC_CHECK_INVALID_Q_VALUE;
        return FFC_PARAMS_RET_STATUS_FAILED;
    }

    if (evpmd == NULL) {
        if (qsize == SHA_DIGEST_LENGTH)
            evpmd = EVP_sha1();
        else if (qsize == SHA224_DIGEST_LENGTH)
            evpmd = EVP_sha224();
        else
            evpmd = EVP_sha256();
    } else {
        rv = EVP_MD_size(evpmd);
        if (rv <= 0)
            return 0;
        qsize = (size_t)rv;
    }

    if (L < 512)
        L = 512;

    L = (L + 63) / 64 * 64;

    if (seed_in != NULL) {
        if (seed_len < qsize) {
            *res = FFC_CHECK_INVALID_SEED_SIZE;
            return 0;
        }
        if (seed_len > qsize) {
            /* Only consume as much seed as is expected. */
            seed_len = qsize;
        }
        memcpy(seed, seed_in, seed_len);
    }

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;

    BN_CTX_start(ctx);

    r0 = BN_CTX_get(ctx);
    g = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    test = BN_CTX_get(ctx);
    if (test == NULL)
        goto err;

    if (!BN_lshift(test, BN_value_one(), L - 1))
        goto err;

    if (generate) {
        /* For generation: p & q must both be NULL or NON-NULL */
        if ((params->p != NULL) != (params->q != NULL)) {
            *res = FFC_CHECK_INVALID_PQ;
            goto err;
        }
    } else {
        if ((validate_flags & FFC_PARAMS_VALIDATE_PQ) != 0) {
            /* Validation of p,q requires seed and counter to be valid */
            if (seed_in == NULL || params->pcounter < 0) {
                *res = FFC_CHECK_MISSING_SEED_OR_COUNTER;
                goto err;
            }
        }
        if ((validate_flags & FFC_PARAMS_VALIDATE_G) != 0) {
            /* validation of g also requires g to be set */
            if (params->g == NULL) {
                *res = FFC_CHECK_INVALID_G;
                goto err;
            }
        }
    }

    if (params->p != NULL && ((validate_flags & FFC_PARAMS_VALIDATE_PQ) == 0)) {
        /* p and q already exists so only generate g */
        p = params->p;
        q = params->q;
        goto g_only;
        /* otherwise fall thru to validate p & q */
    }

    use_random_seed = (seed_in == NULL);
    for (;;) {
        if (!generate_q_fips186_2(ctx, q, evpmd, DSS_prime_checks, buf, seed,
                                  qsize, use_random_seed, &m, res, cb))
            goto err;

        if (!BN_GENCB_call(cb, 2, 0))
            goto err;
        if (!BN_GENCB_call(cb, 3, 0))
            goto err;

        /* step 6 */
        n = (L - 1) / 160;
        counter = 4 * L - 1; /* Was 4096 */
        /* Validation requires the counter to be supplied */
        if (validate_flags) {
            if (params->pcounter > counter) {
                *res = FFC_CHECK_INVALID_COUNTER;
                goto err;
            }
            counter = params->pcounter;
        }

        rv = generate_p(ctx, evpmd, counter, n, buf, qsize, q, p, L,
                        DSS_prime_checks, cb, &pcounter, res);
        if (rv > 0)
            break; /* found it */
        if (rv == -1)
            goto err;
        /* This is what the old code did - probably not a good idea! */
        use_random_seed = 1;
    }

    if (!BN_GENCB_call(cb, 2, 1))
        goto err;

    if (validate_flags) {
        if (pcounter != counter) {
            *res = FFC_CHECK_COUNTER_MISMATCH;
            goto err;
        }
        if (BN_cmp(p, params->p) != 0) {
            *res = FFC_CHECK_P_MISMATCH;
            goto err;
        }
    }
    /* If validating p & q only then skip the g validation test */
    if ((validate_flags & FFC_PARAMS_VALIDATE_ALL) == FFC_PARAMS_VALIDATE_PQ)
        goto pass;
g_only:
    if ((mont = BN_MONT_CTX_new()) == NULL)
        goto err;
    if (!BN_MONT_CTX_set(mont, p, ctx))
        goto err;

    if (generate) {
        /* We now need to generate g */
        /* set test = p - 1 */
        if (!BN_sub(test, p, BN_value_one()))
            goto err;
        /* Set r0 = (p - 1) / q */
        if (!BN_div(r0, NULL, test, q, ctx))
            goto err;
        if (!generate_unverifiable_g(ctx, mont, g, tmp, p, r0, test, &hret))
            goto err;
    } else if (((validate_flags & FFC_PARAMS_VALIDATE_G) != 0)
                && !validate_unverifiable_g(ctx, mont, p, q, params->g, tmp,
                                            res)) {
        goto err;
    }

    if (!BN_GENCB_call(cb, 3, 1))
        goto err;

    if (generate) {
        if (p != params->p) {
            BN_free(params->p);
            params->p = BN_dup(p);
        }
        if (q != params->q) {
            BN_free(params->q);
            params->q = BN_dup(q);
        }
        if (g != params->g) {
            BN_free(params->g);
            params->g = BN_dup(g);
        }
        if (params->p == NULL || params->q == NULL || params->g == NULL)
            goto err;
        if (!FFC_PARAMS_set_validate_params(params, seed, qsize, pcounter))
            goto err;
        params->h = hret;
    }
pass:
    if ((validate_flags & FFC_PARAMS_VALIDATE_G) != 0)
        ok = FFC_PARAMS_RET_STATUS_UNVERIFIABLE_G;
    else
        ok = FFC_PARAMS_RET_STATUS_SUCCESS;
err:
    if (ctx)
        BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_MONT_CTX_free(mont);
    return ok;
}

/* This should no longer be used in FIPS mode */
int FFC_PARAMS_FIPS186_2_generate(FFC_PARAMS *params, int type,
                                  size_t L, size_t N,
                                  const EVP_MD *evpmd, int *res, BN_GENCB *cb)
{
    return ffc_param_FIPS186_2_gen_verify(params, type, L, N, evpmd, 0, res, cb);
}

/* This may be used in FIPS mode to validate deprecated FIPS-186-2 Params */
int FFC_PARAMS_FIPS186_2_validate(const FFC_PARAMS *params, int type,
                                  const EVP_MD *evpmd, int validate_flags,
                                  int *res, BN_GENCB *cb)
{
    size_t L, N;

    if (params->p == NULL || params->q == NULL) {
        *res = FFC_CHECK_INVALID_PQ;
        return FFC_PARAMS_RET_STATUS_FAILED;
    }
    /* A.1.1.3 Step (1..2) : L = len(p), N = len(q) */
    L = BN_num_bits(params->p);
    N = BN_num_bits(params->q);
    return ffc_param_FIPS186_2_gen_verify((FFC_PARAMS *)params, type, L, N,
                                          evpmd, validate_flags, res, cb);
}

/*
 * See SP800-56Ar3 Section 5.6.2.3.1 : FFC Partial public key validation.
 * To only be used with ephemeral FFC public keys generated using the approved
 * safe-prime groups. (Checks that the public key is in the range [2, p-1]
 *
 * ret contains 0 on success, or error flags (see FFC_ERROR_PUBKEY_TOO_SMALL)
 */
int FFC_validate_pub_key_partial(const FFC_PARAMS *params,
                                 const BIGNUM *pub_key, int *ret)
{
    int ok = 0;
    BIGNUM *tmp = NULL;
    BN_CTX *ctx = NULL;

    *ret = 0;
    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    /* Step(1): Verify pub_key >= 2 */
    if (tmp == NULL || !BN_set_word(tmp, 1))
        goto err;
    if (BN_cmp(pub_key, tmp) <= 0) {
        *ret |= FFC_ERROR_PUBKEY_TOO_SMALL;
        goto err;
    }
    /* Step(1): Verify pub_key <=  p-2 */
    if (BN_copy(tmp, params->p) == NULL || !BN_sub_word(tmp, 1))
        goto err;
    if (BN_cmp(pub_key, tmp) >= 0) {
        *ret |= FFC_ERROR_PUBKEY_TOO_LARGE;
        goto err;
    }
    ok = 1;
 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ok;
}

/*
 * See SP800-56Ar3 Section 5.6.2.3.1 : FFC Full public key validation.
 */
int FFC_validate_pub_key(const FFC_PARAMS *params, const BIGNUM *pub_key,
                         int *ret)
{
    int ok = 0;
    BIGNUM *tmp = NULL;
    BN_CTX *ctx = NULL;

    if (!FFC_validate_pub_key_partial(params, pub_key, ret))
        return 0;

    if (params->q != NULL) {
        ctx = BN_CTX_new();
        if (ctx == NULL)
            goto err;
        BN_CTX_start(ctx);
        tmp = BN_CTX_get(ctx);

        /* Check pub_key^q == 1 mod p */
        if (tmp == NULL || !BN_mod_exp(tmp, pub_key, params->q, params->p, ctx))
            goto err;
        if (!BN_is_one(tmp)) {
            *ret |= FFC_ERROR_PUBKEY_INVALID;
            goto err;
        }
    }

    ok = 1;
 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ok;
}

/*
 * SP800-56A r3 5.6.1.1.4 Key pair generation by testing candidates.
 * Generates a private key in the interval [1, min(2^N - 1, q - 1)].
 *
 * params contains the FFC domain parameters p,q,g (for DH or DSA).
 * N is the maximum bit length of the generated private key,
 * s is the security strength.
 * priv_key is the returned private key,
 */
int FFC_generate_priv_key(const FFC_PARAMS *params, int N, int s,
                          BIGNUM *priv_key)
{
#ifdef FIPS_MODE
    int ret = 0;
    BIGNUM *m, *two_powN = NULL;

    /* Step (2) : check range of N */
    if (N < 2 * s || N > BN_num_bits(params->q))
        return 0;

    two_powN = BN_new();
    /* 2^N */
    if (two_powN == NULL || !BN_lshift(two_powN, BN_value_one(), N))
        goto err;

    /* Step (5) : M = min(2^N, q) */
    m = (BN_cmp(two_powN, params->q) > 0) ? params->q : two_powN;
    do {
        /* Steps (3, 4 & 7) c + 1 = 1 + random[0..2^N -1] */
        if (!BN_priv_rand_range(priv_key, two_powN)
                || !BN_add_word(priv_key, 1))
            goto err;
        /* Step (6) loop if c > M-2 (i.e. c+1 >= M) */
        if (BN_cmp(priv_key, m) < 0)
            break;
    } while (1);

    ret = 1;
err:
    BN_free(two_powN);
    return ret;
#else
    do {
        if (!BN_priv_rand_range(priv_key, params->q))
            return 0;
    } while (BN_is_zero(priv_key));
    return 1;
#endif
}

/*
 * See SP800-56Ar3 Section 5.6.2.1.2: Owner assurance of Private key validity.
 * Verifies priv_key is in the range [1..upper-1]. The passed in value of upper
 * is normally params->q but can be 2^N for approved safe prime groups.
 * Note: This assumes that the domain parameters are valid.
 */
int FFC_validate_priv_key(const BIGNUM *upper, const BIGNUM *priv_key, int *ret)
{
    int ok = 0;

    *ret = 0;

    if (BN_cmp(priv_key, BN_value_one()) < 0) {
        *ret |= FFC_ERROR_PRIVKEY_TOO_SMALL;
        goto err;
    }
    if (BN_cmp(priv_key, upper) >= 0) {
        *ret |= FFC_ERROR_PRIVKEY_TOO_LARGE;
        goto err;
    }
    ok = 1;
err:
    return ok;
}

static int ffc_bn_cpy(BIGNUM **dst, const BIGNUM *src)
{
    BIGNUM *a;

    /*
     * If source is read only just copy the pointer, so
     * we don't have to reallocate it.
     */
    if (src == NULL)
        a = NULL;
    else if (BN_get_flags(src, BN_FLG_STATIC_DATA)
                && !BN_get_flags(src, BN_FLG_MALLOCED))
        a = (BIGNUM *)src;
    else if ((a = BN_dup(src)) == NULL)
        return 0;
    BN_clear_free(*dst);
    *dst = a;
    return 1;
}

int FFC_PARAMS_copy(FFC_PARAMS *dst, const FFC_PARAMS *src)
{
    if (!(ffc_bn_cpy(&dst->p, src->p)
            && ffc_bn_cpy(&dst->g, src->g)
            && ffc_bn_cpy(&dst->q, src->q)
            && ffc_bn_cpy(&dst->j, src->j)))
        return 0;

    OPENSSL_free(dst->seed);
    dst->seedlen = src->seedlen;
    if (src->seed != NULL) {
        dst->seed = OPENSSL_memdup(src->seed, src->seedlen);
        if  (dst->seed == NULL)
            return 0;
    } else {
        dst->seed = NULL;
    }
    dst->pcounter = src->pcounter;
    dst->gindex = src->gindex;
    dst->h = src->h;
    return 1;
}

int FFC_PARAMS_cmp(const FFC_PARAMS *a, const FFC_PARAMS *b)
{
    /* Note: q may be NULL */
    if (BN_cmp(a->p, b->p) || BN_cmp(a->q, b->q) || BN_cmp(a->g, b->g))
        return 0;
    else
        return 1;
}

int FFC_PARAMS_print(BIO *bp, const FFC_PARAMS *ffc, int indent)
{
    if (!ASN1_bn_print(bp, "prime P:", ffc->p, NULL, indent))
        goto err;
    if (!ASN1_bn_print(bp, "generator G:", ffc->g, NULL, indent))
        goto err;
    if (ffc->q != NULL
            && !ASN1_bn_print(bp, "subgroup order Q:", ffc->q, NULL, indent))
        goto err;
    if (ffc->j != NULL
            && !ASN1_bn_print(bp, "subgroup factor:", ffc->j, NULL, indent))
        goto err;
    if (ffc->seed != NULL) {
        size_t i;
        BIO_indent(bp, indent, 128);
        BIO_puts(bp, "seed:");
        for (i = 0; i < ffc->seedlen; i++) {
            if ((i % 15) == 0) {
                if (BIO_puts(bp, "\n") <= 0
                    || !BIO_indent(bp, indent + 4, 128))
                    goto err;
            }
            if (BIO_printf(bp, "%02x%s", ffc->seed[i],
                           ((i + 1) == ffc->seedlen) ? "" : ":") <= 0)
                goto err;
        }
        if (BIO_write(bp, "\n", 1) <= 0)
            return 0;
    }
    if (ffc->pcounter != -1) {
        BIO_indent(bp, indent, 128);
        if (BIO_printf(bp, "counter: %d\n", ffc->pcounter) <= 0)
            goto err;
    }
    if (ffc->gindex != FFC_UNVERIFIABLE_GINDEX) {
        BIO_indent(bp, indent, 128);
        if (BIO_printf(bp, "gindex: %d\n", ffc->gindex) <= 0)
            goto err;
    }
    return 1;
err:
    return 0;
}
