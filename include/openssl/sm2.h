/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SM2_H
# define HEADER_SM2_H
# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_SM2

#  ifdef __cplusplus
extern "C" {
#  endif

#  include <openssl/ec.h>

/* The default user id as specified in GM/T 0009-2012 */
#  define SM2_DEFAULT_USERID "1234567812345678"

int SM2_compute_userid_digest(uint8_t *out,
                              const EVP_MD *digest,
                              const char *user_id, const EC_KEY *key);

/*
 * SM2 signature operation. Computes ZA (user id digest) and then signs
 * H(ZA || msg) using SM2
 */
ECDSA_SIG *SM2_do_sign(const EC_KEY *key,
                       const EVP_MD *digest,
                       const char *user_id, const uint8_t *msg, size_t msg_len);

int SM2_do_verify(const EC_KEY *key,
                  const EVP_MD *digest,
                  const ECDSA_SIG *signature,
                  const char *user_id, const uint8_t *msg, size_t msg_len);

/*
 * SM2 signature generation. Assumes input is an SM3 digest
 */
int SM2_sign(int type, const unsigned char *dgst, int dgstlen,
             unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);

/*
 * SM2 signature verification. Assumes input is an SM3 digest
 */
int SM2_verify(int type, const unsigned char *dgst, int dgstlen,
               const unsigned char *sig, int siglen, EC_KEY *eckey);


/*
 * SM2 encryption
 */
size_t SM2_ciphertext_size(const EC_KEY *key,
                           const EVP_MD *digest,
                           size_t msg_len);

size_t SM2_plaintext_size(const EC_KEY *key,
                          const EVP_MD *digest,
                          size_t msg_len);

int SM2_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *msg,
                size_t msg_len,
                uint8_t *ciphertext_buf, size_t *ciphertext_len);

int SM2_decrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *ciphertext,
                size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len);

int ERR_load_SM2_strings(void);

#  ifdef __cplusplus
}
#  endif

# endif /* OPENSSL_NO_SM2 */
#endif
