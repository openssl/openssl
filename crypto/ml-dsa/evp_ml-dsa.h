#ifndef OSSL_CRYPTO_ML_DSA_H
#define OSSL_CRYPTO_ML_DSA_H

#include <openssl/evp.h>

/* ML-DSA-87 (Dilithium Level 5) - NIST FIPS 204 */
#define ML_DSA_PUBLIC_KEY_BYTES   2592
#define ML_DSA_PRIVATE_KEY_BYTES  4864
#define ML_DSA_SIGNATURE_BYTES    4595

/* EVP_PKEY method declarations */
int ml_dsa_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
int ml_dsa_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen);
int ml_dsa_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                   const unsigned char *tbs, size_t tbslen);

#endif
