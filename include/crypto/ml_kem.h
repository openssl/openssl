/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Copyright (c) 2024, Google Inc. */

#ifndef OPENSSL_HEADER_ML_KEM_H
# define OPENSSL_HEADER_ML_KEM_H

# ifndef OPENSSL_NO_ML_KEM

#  include <openssl/e_os2.h>
#  include <crypto/evp.h>
#  include <crypto/ml_kem_types.h>

typedef struct ossl_ml_kem_ctx_st ossl_ml_kem_ctx;

#  define ML_KEM_DEGREE 256
/*
 * With (q-1) an odd multiple of 256, and 17 ("zeta") as a primitive 256th root
 * of unity, the polynomial (X^256+1) splits in Z_q[X] into 128 irreducible
 * quadratic factors of the form (X^2 - zeta^(2i + 1)).  This is used to
 * implement efficient multiplication in the ring R_q via the "NTT" transform.
 *
 * 12 bits are sufficient to losslessly represent values in [0, q-1].
 * INVERSE_DEGREE is (n/2)^-1 mod q; used in inverse NTT.
 */
#  define ML_KEM_PRIME          (ML_KEM_DEGREE * 13 + 1)
#  define ML_KEM_LOG2PRIME      12
#  define ML_KEM_INVERSE_DEGREE (ML_KEM_PRIME - 2 * 13)

/*
 * Various ML-KEM primitives need random input, 32-bytes at a time.  Key
 * generation consumes two random values (d, z) with "d" plus the rank (domain
 * separation) further expanded to two derived seeds "rho" and "sigma", with
 * "rho" used to generate the public matrix "A", and sigma to generate the
 * private vector "s" and error vector "e".
 *
 * Encapsulation also consumes one random value m, that is 32-bytes long.  The
 * resulting shared secret "K" (also 32 bytes) and an internal random value "r"
 * are derived from "m" concatenated with a digest of the received public key.
 * Use of the public key hash means that the derived shared secret is
 * "contributary", it uses randomness from both parties.
 *
 * The seed "rho" is appended to the public key and allows the recipient of the
 * public key to re-compute the matrix "A" when performing encapsulation.
 *
 * Note that the matrix "m" we store in the public key is the transpose of the
 * "A" matrix from FIPS 203!
 */
#  define ML_KEM_RANDOM_BYTES    32 /* rho, sigma, ... */
#  define ML_KEM_SEED_BYTES      (ML_KEM_RANDOM_BYTES * 2) /* Keygen (d, z) */

#  define ML_KEM_PKHASH_BYTES        32 /* Salts the shared-secret */
#  define ML_KEM_SHARED_SECRET_BYTES 32

/*-
 * The ML-KEM specification can be found in
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
 *
 * Section 8, Table 2, lists the parameters for the three variants:
 *
 *         Variant     n     q  k  eta1  eta2  du   dv  secbits
 *      ----------   ---  ----  -  ----  ----  --   --  -------
 *      ML-KEM-512   256  3329  2     3     2  10    4      128
 *      ML-KEM-768   256  3329  3     2     2  10    4      192
 *      ML-KEM-1024  256  3329  4     2     2  11    5      256
 *
 * where:
 *
 * - "n" (ML_KEM_DEGREE above) is the fixed degree of the quotient polynomial
 *    in the ring: "R_q" = Z[X]/(X^n + 1).
 * - "q" (ML_KEM_PRIME above) is the fixed prime (256 * 13 + 1 = 3329) used in
 *   all ML-KEM variants.
 * - "k" is the row rank of the square matrix "A", with entries in R_q, that
 *   defines the "noisy" linear equations: t = A * s + e.  Also the rank of
 *   of the associated vectors.
 * - "eta1" determines the amplitude of "s" and "e" vectors in key generation
 *   and the "y" vector in ML-KEM encapsulation (K-PKE encryption).
 * - "eta2" determines the amplitude of "e1" and "e2" noise terms in ML-KEM
 *   encapsulation (K-PKE encryption).
 * - "du" determines how many bits of each coefficient are retained in the
 *   compressed form of the "u" vector in the encapsulation ciphertext.
 * - "dv" determines how many bits of each coefficient are retained in the
 *   compressed form of the "v" value in encapsulation ciphertext
 * - "secbits" is required security strength of the RNG for the random inputs.
 */

/*
 * Variant-specific CBD vector generation helpers, these generate a single CBD
 * scalar.
 */
typedef __owur
int ossl_ml_kem_cbd_func(ossl_ml_kem_scalar *out,
                         uint8_t in[ML_KEM_RANDOM_BYTES + 1],
                         EVP_MD_CTX *mdctx, const ossl_ml_kem_ctx *ctx);

/*
 * The wire form of a losslessly encoded vector (12-bits per element)
 */
#  define ML_KEM_VECTOR_BYTES(rank) \
    ((3 * ML_KEM_DEGREE / 2) * (rank))

/*
 * The wire-form public key consists of the lossless encoding of the vector
 * "t" = "A" * "s" + "e", followed by public seed "rho".
 */
#  define ML_KEM_PUBKEY_BYTES(rank) \
    (ML_KEM_VECTOR_BYTES(rank) + ML_KEM_RANDOM_BYTES)

/*
 * Our internal serialised private key concatenates serialisations of "s", the
 * public key, the public key hash, and the failure secret "z".
 */
#  define ML_KEM_PRVKEY_BYTES(rank) \
    (ML_KEM_VECTOR_BYTES(rank) + ML_KEM_PUBKEY_BYTES(rank) \
     + ML_KEM_PKHASH_BYTES + ML_KEM_RANDOM_BYTES)

/*
 * Encapsulation produces a vector "u" and a scalar "v", whose coordinates
 * (numbers modulo the ML-KEM prime "q") are lossily encoded using as "du" and
 * "dv" bits, respectively.  This encoding is the ciphertext input for
 * decapsulation.
 */
#  define ML_KEM_CTEXT_BYTES(rank, du, dv) \
    ((ML_KEM_DEGREE / 8) * ((du) * (rank) + (dv)))

/*
 * Variant-specific constants and structures
 * -----------------------------------------
 */
#  define ML_KEM_512_RANK       2
#  define ML_KEM_512_ETA1       3
#  define ML_KEM_512_ETA2       2
#  define ML_KEM_512_DU         10
#  define ML_KEM_512_DV         4
#  define ML_KEM_512_RNGSEC     128
#  define ML_KEM_512_CIPHERTEXT_BYTES \
    ML_KEM_CIPHERTEXT_BYTES(ML_KEM_512_RANK, ML_KEM_512_DU, ML_KEM_512_DV)

#  define ML_KEM_768_RANK       3
#  define ML_KEM_768_ETA1       2
#  define ML_KEM_768_ETA2       2
#  define ML_KEM_768_DU         10
#  define ML_KEM_768_DV         4
#  define ML_KEM_768_RNGSEC     192
#  define ML_KEM_768_CIPHERTEXT_BYTES \
    ML_KEM_CIPHERTEXT_BYTES(ML_KEM_768_RANK, ML_KEM_768_DU, ML_KEM_768_DV)

#  define ML_KEM_1024_RANK      4
#  define ML_KEM_1024_ETA1      2
#  define ML_KEM_1024_ETA2      2
#  define ML_KEM_1024_DU        11
#  define ML_KEM_1024_DV        5
#  define ML_KEM_1024_RNGSEC    256
#  define ML_KEM_1024_CIPHERTEXT_BYTES \
    ML_KEM_CIPHERTEXT_BYTES(ML_KEM_1024_RANK, ML_KEM_1024_DU, ML_KEM_1024_DV)

/*
 * External variant-specific API
 * -----------------------------
 */

/*
 * Combine a prefix, the ML-KEM variant bitsize and a suffix, to produce a C
 * symbol name.
 */
#  define ossl_ml_kem_name(bits, suffix) ossl_ml_kem_##bits##_##suffix

/*
 * For v in (512, 768, 1024):
 *
 * ossl_ml_kem_<v>_genkey_rand() generates a random public/private key pair,
 * writes the encoded public key to |out_encoded_public_key| and sets
 * |out_private_key| to the private key. If |optional_out_seed| is not NULL
 * then the seed used to generate the private key is written to it as well.
 *
 * out_encoded_public_key must have room for ML_KEM_<v>_PUBLIC_KEY_BYTES,
 * optional_out_seed if not NULL have room for ML_KEM_SEED_BYTES.
 */
#  define DECLARE_ML_KEM_GENKEY_RAND(v) \
    __owur int ossl_ml_kem_name(v,genkey_rand)( \
        uint8_t *optional_out_seed, \
        uint8_t *out_encoded_public_key, \
        ossl_ml_kem_name(v,private_key) *out_private_key, \
        const ossl_ml_kem_ctx *ctx)
DECLARE_ML_KEM_GENKEY_RAND(512);
DECLARE_ML_KEM_GENKEY_RAND(768);
DECLARE_ML_KEM_GENKEY_RAND(1024);
#  undef DECLARE_ML_KEM_GENKEY_RAND

/*
 * For v in (512, 768, 1024):
 *
 * ossl_ml_kem_<v>_private_key_from_seed() derives a private key from a seed
 * that was generated by |ossl_ml_kem_<v>_genkey_rand|. It fails and returns 0
 * if |seed_len| is incorrect, otherwise it writes |out_encoded_public_key|,
 * |*out_private_key| and returns 1.
 */
#  define DECLARE_ML_KEM_GENKEY_SEED(v) \
    __owur int ossl_ml_kem_name(v,genkey_seed)( \
        const uint8_t *seed, size_t seed_len, \
        uint8_t *out_encoded_public_key, \
        ossl_ml_kem_name(v,private_key) *out_private_key, \
        const ossl_ml_kem_ctx *ctx)
DECLARE_ML_KEM_GENKEY_SEED(512);
DECLARE_ML_KEM_GENKEY_SEED(768);
DECLARE_ML_KEM_GENKEY_SEED(1024);
#  undef DECLARE_ML_KEM_GENKEY_SEED

/*-
 * For v in (512, 768, 1024):
 *
 * ossl_ml_kem_<v>_encap() encrypts a random shared secret for |public_key|,
 * writes the ciphertext to |out_ciphertext|, and writes the random shared
 * secret to |out_shared_secret|.
 *
 * out_ciphertext must have room for ML_KEM_<v>_CIPHERTEXT_BYTES and
 * out_shared_secret for ML_KEM_SHARED_SECRET_BYTES.
 */
#  define DECLARE_ML_KEM_ENCAP_RAND(v) \
    __owur int ossl_ml_kem_name(v,encap_rand)(\
        uint8_t *out_ciphertext, \
        uint8_t *out_shared_secret, \
        const ossl_ml_kem_name(v,public_key) *public_key, \
        const ossl_ml_kem_ctx *ctx)
DECLARE_ML_KEM_ENCAP_RAND(512);
DECLARE_ML_KEM_ENCAP_RAND(768);
DECLARE_ML_KEM_ENCAP_RAND(1024);
#  undef DECLARE_ML_KEM_ENCAP_RAND

/*
 * For v in (512, 768, 1024):
 *
 * The same as ossl_ml_kem_<v>_encap except this also uses a given entropy for
 * deterministic output.
 */
#  define DECLARE_ML_KEM_ENCAP_SEED(v) \
    __owur int ossl_ml_kem_name(v,encap_seed)( \
        uint8_t *out_ciphertext, \
        uint8_t *out_shared_secret, \
        const ossl_ml_kem_name(v,public_key) *public_key, \
        const uint8_t *entropy, \
        const ossl_ml_kem_ctx *ctx)
DECLARE_ML_KEM_ENCAP_SEED(512);
DECLARE_ML_KEM_ENCAP_SEED(768);
DECLARE_ML_KEM_ENCAP_SEED(1024);
#  undef DECLARE_ML_KEM_ENCAP_SEED

/*
 * For v in (512, 768, 1024):
 *
 * ossl_ml_kem_<v>_decap() decrypts a shared secret from |ciphertext| using
 * |private_key| and writes it to |out_shared_secret|. If |ciphertext_len| is
 * incorrect it returns 0, otherwise it returns 1. If |ciphertext| is invalid
 * (but of the correct length), |out_shared_secret| is filled with a key that
 * will always be the same for the same |ciphertext| and |private_key|, but
 * which appears to be random unless one has access to |private_key|. These
 * alternatives occur in constant time. Any subsequent symmetric encryption
 * using |out_shared_secret| must use an authenticated encryption scheme in
 * order to discover the decapsulation failure.
 *
 * out_shared_secret must have room for ML_KEM_SHARED_SECRET_BYTES.
 */
#  define DECLARE_ML_KEM_DECAP(v) \
    __owur int ossl_ml_kem_name(v,decap)( \
        uint8_t *out_shared_secret, \
        const uint8_t *ciphertext, \
        size_t ciphertext_len, \
        const ossl_ml_kem_name(v,private_key) *private_key, \
        const ossl_ml_kem_ctx *ctx)
DECLARE_ML_KEM_DECAP(512);
DECLARE_ML_KEM_DECAP(768);
DECLARE_ML_KEM_DECAP(1024);
#  undef DECLARE_ML_KEM_DECAP

/* Serialisation of keys. */

/*
 * For v in (512, 768, 1024):
 *
 * ossl_ml_kem_<v>_parse_public_key() parses a FIPS 203 encoded public key from
 * |in| and writes the result to |out_public_key|. It returns one on success or
 * zero on parse error.
 */
#  define DECLARE_ML_KEM_PARSE_PUB(v) \
    __owur int ossl_ml_kem_name(v,parse_public_key)( \
        ossl_ml_kem_name(v,public_key) *out_public_key, \
        const uint8_t *in, \
        const ossl_ml_kem_ctx *ctx)
DECLARE_ML_KEM_PARSE_PUB(512);
DECLARE_ML_KEM_PARSE_PUB(768);
DECLARE_ML_KEM_PARSE_PUB(1024);
#  undef DECLARE_ML_KEM_PARSE_PUB

/*
 * For v in (512, 768, 1024):
 *
 * ossl_ml_kem_<v>_encode_public_key() serializes |public_key| to |out| in the
 * FIPS 203 standard format for ML-KEM-<v> public keys.
 */
#  define DECLARE_ML_KEM_ENCODE_PUB(v) \
    void ossl_ml_kem_name(v,encode_public_key)( \
        uint8_t *out, \
        const ossl_ml_kem_name(v,public_key) *public_key)
DECLARE_ML_KEM_ENCODE_PUB(512);
DECLARE_ML_KEM_ENCODE_PUB(768);
DECLARE_ML_KEM_ENCODE_PUB(1024);
#  undef DECLARE_ML_KEM_ENCODE_PUB

/*
 * For v in (512, 768, 1024):
 *
 * ossl_ml_kem_<v>_encode_private_key() serializes |private_key| to |out| in
 * the FIPS 203 internal format for ML-KEM-<v> private keys.
 */
#  define DECLARE_ML_KEM_ENCODE_PRV(v) \
    void ossl_ml_kem_name(v,encode_private_key)( \
        uint8_t *out, \
        const ossl_ml_kem_name(v,private_key) *private_key)
DECLARE_ML_KEM_ENCODE_PRV(512);
DECLARE_ML_KEM_ENCODE_PRV(768);
DECLARE_ML_KEM_ENCODE_PRV(1024);
#  undef DECLARE_ML_KEM_ENCODE_PRV

/*
 * For v in (512, 768, 1024):
 *
 * ossl_ml_kem_<v>_parse_private_key() parses a private key, in NIST's format
 * for private keys, from |in| and writes the result to |out_private_key|. It
 * returns one on success or zero on parse error or if there are trailing bytes
 * in |in|. This format is verbose and should be avoided. Private keys should
 * be stored as seeds and parsed using |ossl_ml_kem_<v>_private_key_from_seed|.
 */
#  define DECLARE_ML_KEM_PARSE_PRV(v) \
    __owur int ossl_ml_kem_name(v,parse_private_key)( \
        ossl_ml_kem_name(v,private_key) *out_private_key, \
        const uint8_t *in, \
        const ossl_ml_kem_ctx *ctx)
DECLARE_ML_KEM_PARSE_PRV(512);
DECLARE_ML_KEM_PARSE_PRV(768);
DECLARE_ML_KEM_PARSE_PRV(1024);
#  undef DECLARE_ML_KEM_PARSE_PRV
#  undef ossl_ml_kem_name

/* --- Variant parameters and associated methods */

typedef struct {
    ossl_ml_kem_cbd_func *cbd1;
    ossl_ml_kem_cbd_func *cbd2;
    size_t vector_bytes;
    size_t prvkey_bytes;
    size_t pubkey_bytes;
    size_t ctext_bytes;
    size_t u_vector_bytes;
    size_t puballoc;
    size_t prvalloc;
    int bits;
    int rank;
    int du;
    int dv;
    int secbits;
} ossl_ml_kem_vinfo;

/* General ctx functions */
ossl_ml_kem_ctx *ossl_ml_kem_newctx(OSSL_LIB_CTX *libctx,
                                    const char *properties,
                                    const ossl_ml_kem_vinfo *vinfo);
ossl_ml_kem_ctx *ossl_ml_kem_ctx_dup(const ossl_ml_kem_ctx *ctx);
void ossl_ml_kem_ctx_free(ossl_ml_kem_ctx *ctx);

/* Retrive variant-specific parameters */
const ossl_ml_kem_vinfo *ossl_ml_kem_512_get_vinfo(void);
const ossl_ml_kem_vinfo *ossl_ml_kem_768_get_vinfo(void);
const ossl_ml_kem_vinfo *ossl_ml_kem_1024_get_vinfo(void);

/*
 * Perform ML-KEM ops for a specic parameter set, the public and private key
 * pointers are (void *), in that order, when either is accepted in lieu of a
 * public key of the appropriate type.  Parameters with an implicit fixed
 * length in each variant have an explicit checked additional length argument
 * here.
 *
 * When generating or parsing keys, if the value at the pointer is NULL, a
 * storage for the key is dynamically allocated.
 */
__owur
int ossl_ml_kem_vencode_public_key(const ossl_ml_kem_vinfo *v,
                                   uint8_t *out,
                                   size_t len,
                                   const void *pub,
                                   const void *prv);
__owur
int ossl_ml_kem_vencode_private_key(const ossl_ml_kem_vinfo *v,
                                    uint8_t *out,
                                    size_t len,
                                    const void *prv);
__owur
int ossl_ml_kem_vparse_public_key(const ossl_ml_kem_vinfo *v,
                                  void **pub,
                                  const uint8_t *in,
                                  size_t len,
                                  const ossl_ml_kem_ctx *ctx);
__owur
int ossl_ml_kem_vparse_private_key(const ossl_ml_kem_vinfo *v,
                                   void **priv,
                                   const uint8_t *in,
                                   size_t len,
                                   const ossl_ml_kem_ctx *ctx);
__owur
int ossl_ml_kem_vgenkey_rand(const ossl_ml_kem_vinfo *v,
                             uint8_t *seed,
                             size_t seedlen,
                             uint8_t *pubenc,
                             size_t publen,
                             void **prv,
                             const ossl_ml_kem_ctx *ctx);
__owur
int ossl_ml_kem_vgenkey_seed(const ossl_ml_kem_vinfo *v,
                             const uint8_t *seed,
                             size_t seed_len,
                             uint8_t *pubenc,
                             size_t publen,
                             void **priv,
                             const ossl_ml_kem_ctx *ctx);
__owur
int ossl_ml_kem_vencap_seed(const ossl_ml_kem_vinfo *v,
                            uint8_t *ctext,
                            size_t clen,
                            uint8_t *shared_secret,
                            size_t slen,
                            const void *pub,
                            const void *prv,
                            const uint8_t *entropy,
                            size_t elen,
                            const ossl_ml_kem_ctx *ctx);
__owur
int ossl_ml_kem_vencap_rand(const ossl_ml_kem_vinfo *v,
                            uint8_t *ctext,
                            size_t clen,
                            uint8_t *shared_secret,
                            size_t slen,
                            const void *pub,
                            void *prv,
                            const ossl_ml_kem_ctx *ctx);
__owur
int ossl_ml_kem_vdecap(const ossl_ml_kem_vinfo *v,
                       uint8_t *shared_secret,
                       size_t slen,
                       const uint8_t *ctext,
                       size_t clen,
                       const void *prv,
                       const ossl_ml_kem_ctx *ctx);
/*
 * For each compare public key or public part (p ptr) of private key (k ptr).
 */
__owur
int ossl_ml_kem_vcompare_pubkeys(const ossl_ml_kem_vinfo *v1,
                                 const void *p1,
                                 const void *k1,
                                 const ossl_ml_kem_vinfo *v2,
                                 const void *p2,
                                 const void *k2);
/*
 * Zeroise sensitive components, free and set to NULL the private key
 */
int ossl_ml_kem_vcleanse_prvkey(const ossl_ml_kem_vinfo *v,
                                void **prv);

# endif /* OPENSSL_NO_ML_KEM */
#endif  /* OPENSSL_HEADER_ML_KEM_H */
