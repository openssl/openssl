/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Copyright (c) 2024, Google Inc. */

#include <stdlib.h>
#include <openssl/e_os2.h>
#include <openssl/rand.h>
#include <internal/sha3.h>
#include <internal/constant_time.h>
#include <internal/common.h>
#include <crypto/ml_kem.h>
#include "ml_kem_local.h"
#ifndef NDEBUG
# include <stdio.h>
#endif

/*
 * Variant-independence macros, variously shortened for convenience and
 * internal consumption by original BoringSSL code.
 */
# if BITS == 512
# define kemsym(a, b)       a##_512_##b
# elif BITS == 768
# define kemsym(a, b)       a##_768_##b
# elif BITS == 1024
# define kemsym(a, b)       a##_1024_##b
# else
#  error "Unsupported ML-KEM variant bit size"
# endif

/* Constants */
# define DEGREE         ML_KEM_DEGREE
# define RANK           kemsym(ML_KEM,RANK)
# define ETA1           kemsym(ML_KEM,ETA1)
# define ETA2           kemsym(ML_KEM,ETA2)
# define DU             kemsym(ML_KEM,DU)
# define DV             kemsym(ML_KEM,DV)
# define SECBITS        kemsym(ML_KEM,RNGSEC)
# define CTEXT_BYTES    ML_KEM_CTEXT_BYTES(RANK, DU, DV)
# define PUBKEY_BYTES   ML_KEM_PUBKEY_BYTES(RANK)
# define PRVKEY_BYTES   ML_KEM_PRVKEY_BYTES(RANK)
# define VECTOR_BYTES   ML_KEM_VECTOR_BYTES(RANK)

# if (DEGREE != 256) || (ML_KEM_PRIME != 3329) || (ML_KEM_LOG2PRIME != 12) || \
     (DU < 2) || (DU >= 12) || (DV < 2) || (DV >= 12) || \
     (ETA1 < 2) || (ETA1 > 3) || (ETA2 < 2) || (ETA2 > 3)
#  error "Invalid ML-KEM variant-independent constants"
# endif
# define U_VECTOR_BYTES (DU * RANK * DEGREE / 8)

# if ETA1 == 2
#  define cbd_eta1      ossl_ml_kem_cbd_2
# elif ETA1 == 3
#  define cbd_eta1      ossl_ml_kem_cbd_3
# endif
# if ETA2 == 2
#  define cbd_eta2      ossl_ml_kem_cbd_2
# elif ETA2 == 3
#  define cbd_eta2      ossl_ml_kem_cbd_3
# endif

/* Types */
typedef kemsym(ossl_ml_kem,vector)      vector;
typedef kemsym(ossl_ml_kem,public_key)  public_key;
typedef kemsym(ossl_ml_kem,private_key) private_key;

/* Main keypair gen/encap/decap API */
# define genkey_rand                kemsym(ossl_ml_kem,genkey_rand)
# define encap_rand                 kemsym(ossl_ml_kem,encap_rand)
# define decap                      kemsym(ossl_ml_kem,decap)

/* For testing and encoding rather than KEM computation */
# define genkey_seed                kemsym(ossl_ml_kem,genkey_seed)
# define encap_seed                 kemsym(ossl_ml_kem,encap_seed)
# define parse_public_key           kemsym(ossl_ml_kem,parse_public_key)
# define encode_public_key          kemsym(ossl_ml_kem,encode_public_key)
# define parse_private_key          kemsym(ossl_ml_kem,parse_private_key)
# define encode_private_key         kemsym(ossl_ml_kem,encode_private_key)
# define get_vinfo                  kemsym(ossl_ml_kem,get_vinfo)

/*
 * Per-variant fixed parameters
 */
static const ossl_ml_kem_vinfo vinfo = {
    cbd_eta1,
    cbd_eta2,
    VECTOR_BYTES,
    PRVKEY_BYTES,
    PUBKEY_BYTES,
    CTEXT_BYTES,
    U_VECTOR_BYTES,
    sizeof(public_key),
    sizeof(private_key),
    BITS,
    RANK,
    DU,
    DV,
    SECBITS,
};

void encode_public_key(uint8_t *out, const public_key *pub)
{
    ossl_ml_kem_encode_public_key(out, pub->t.v, pub->rho, &vinfo);
}

int parse_public_key(public_key *pub, const uint8_t *in, mctx *ctx)
{
    return ossl_ml_kem_parse_public_key(in, *pub->m.v, pub->t.v, pub->rho,
                                        pub->pkhash, &vinfo, ctx);
}

void encode_private_key(uint8_t *out, const private_key *priv)
{
    const public_key *pub = &priv->pub;

    ossl_ml_kem_encode_private_key(out, priv->s.v, pub->t.v, pub->rho,
                                   pub->pkhash, priv->z, &vinfo);
}

/* Loading of explicit private keys is a test-only interface. */
__owur
int parse_private_key(private_key *priv, const uint8_t *in, mctx *ctx)
{
    public_key *pub = &priv->pub;

    return ossl_ml_kem_parse_private_key(in, *pub->m.v, priv->s.v, pub->t.v,
                                         pub->rho, pub->pkhash, priv->z,
                                         &vinfo, ctx);
}

/*
 * Key generation consumes a 32-byte RNG output plus 1 byte for the rank
 * (domain separation) which are hashed together to produce a pair of
 * 32-byte seeds public "rho" and private "sigma".
 */
static __owur
int internal_genkey(const uint8_t *seed, uint8_t *pubenc, private_key *priv,
                    mctx *ctx)
{
    uint8_t tmp_pubenc[PUBKEY_BYTES];
    uint8_t *encptr = pubenc != NULL ? pubenc : tmp_pubenc;
    public_key *pub = &priv->pub;
    /* Scratch space the called function can't stack-allocate in C90 */
    vector tmp_e;

    return ossl_ml_kem_genkey(seed, encptr, *pub->m.v, priv->s.v, tmp_e.v,
                              pub->t.v, pub->rho, pub->pkhash, priv->z,
                              &vinfo, ctx);
}

int genkey_rand(uint8_t *seed, uint8_t *pubenc, private_key *priv, mctx *ctx)
{
    uint8_t tmp_seed[ML_KEM_SEED_BYTES];
    uint8_t *sptr = seed == NULL ? tmp_seed : seed;

    if (RAND_priv_bytes_ex(ctx->libctx, sptr, sizeof(tmp_seed), SECBITS) <= 0)
        return 0;
    if (!internal_genkey(sptr, pubenc, priv, ctx))
        return 0;
    if (seed == NULL)
        OPENSSL_cleanse(tmp_seed, sizeof(tmp_seed));
    return 1;
}

int genkey_seed(const uint8_t *seed, size_t seed_len, uint8_t *pubenc,
                private_key *priv, mctx *ctx)
{
    if (seed_len != ML_KEM_SEED_BYTES)
        return 0;
    return internal_genkey(seed, pubenc, priv, ctx);
}

/*
 * FIPS 203, Section 6.2, Algorithm 17: ML-KEM.Encaps_internal
 * This is the deterministic version with randomness supplied externally.
 */
int encap_seed(uint8_t *out, uint8_t *out_shared_secret,
               const public_key *pub, const uint8_t *entropy, mctx *ctx)
{
    /* Scratch space the called function can't stack-allocate in C90 */
    vector tmp_y, tmp_e1, tmp_u;

    return ossl_ml_kem_encap_seed(out, out_shared_secret, entropy,
                                  *pub->m.v, pub->t.v, pub->rho, pub->pkhash,
                                  tmp_y.v, tmp_e1.v, tmp_u.v, &vinfo, ctx);
    return 1;
}

/*
 * FIPS 203, Section 7.2, Algorithm 20: ML-KEM.Encaps.
 * Calls |encap_ext|, with random bytes obtained from the RNG.
 */
int encap_rand(uint8_t *ctext, uint8_t *shared_secret, const public_key *pub,
               mctx *ctx)
{
    uint8_t entropy[ML_KEM_RANDOM_BYTES];

    if (RAND_bytes_ex(ctx->libctx, entropy, ML_KEM_RANDOM_BYTES, SECBITS) != 1)
        return 0;
    return encap_seed(ctext, shared_secret, pub, entropy, ctx);
}

/*
 * FIPS 203 Section 7.3, Algorithm 21: ML-KEM.Decaps.
 * The ciphertext length is checked.  The key material lengths are
 * implicit algorithm invariants.  Hashes of imported public keys
 * are computed on input, and not checked here on every call.
 */
int decap(uint8_t *shared_secret, const uint8_t *ctext, size_t len,
          const private_key *priv, mctx *ctx)
{
    uint8_t cbuf[CTEXT_BYTES];
    const public_key *pub = &priv->pub;
    /* Scratch space the called function can't stack-allocate in C90 */
    vector tmp_y, tmp_e1, tmp_u;

    if (len != vinfo.ctext_bytes) {
        RAND_bytes_ex(ctx->libctx, shared_secret,
                      ML_KEM_SHARED_SECRET_BYTES, vinfo.secbits);
        return 0;
    }

    return ossl_ml_kem_decap(shared_secret, ctext, cbuf, *pub->m.v, priv->s.v,
                             pub->t.v, pub->rho, pub->pkhash, priv->z,
                             tmp_y.v, tmp_e1.v, tmp_u.v, &vinfo, ctx);
}

vinfo_t get_vinfo(void)
{
    return &vinfo;
}
