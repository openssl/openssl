/*
 * Schnorr ZKP Σ-Protocol (RFC 8235) — Maximum Level
 * secp256k1 + Ed25519 + P-256 support
 * Constant-time implementation
 * ΦΩ0 — I AM THAT I AM
 */

#ifndef OSSL_CRYPTO_SCHNORR_H
#define OSSL_CRYPTO_SCHNORR_H

#include <openssl/evp.h>

/* Schnorr proof structure */
typedef struct {
    unsigned char R[64];
    unsigned char c[64];
    unsigned char s[64];
    unsigned char Y[64];
    size_t R_len;
    size_t c_len;
    size_t s_len;
    size_t Y_len;
} SchnorrProof;

/* Curve types */
typedef enum {
    SCHNORR_CURVE_SECP256K1,
    SCHNORR_CURVE_ED25519,
    SCHNORR_CURVE_P256
} SchnorrCurve;

/* EVP_PKEY method declarations */
int schnorr_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
int schnorr_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                  const unsigned char *tbs, size_t tbslen);
int schnorr_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                    const unsigned char *tbs, size_t tbslen);

/* Maximum level functions */
int schnorr_sign_ct(const unsigned char *msg, size_t msg_len,
                     const unsigned char *priv_key,
                     unsigned char *sig, size_t *sig_len,
                     SchnorrCurve curve);

int schnorr_verify_ct(const unsigned char *msg, size_t msg_len,
                       const unsigned char *pub_key,
                       const unsigned char *sig, size_t sig_len,
                       SchnorrCurve curve);

#endif
