/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal EC functions for other submodules: not for application use */

#ifndef OSSL_CRYPTO_ECX_H
# define OSSL_CRYPTO_ECX_H
# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_EC

#  include <openssl/core.h>
#  include <openssl/e_os2.h>
#  include <openssl/crypto.h>
#  include "internal/refcount.h"

#  define X25519_KEYLEN         32
#  define X448_KEYLEN           56
#  define ED25519_KEYLEN        32
#  define ED448_KEYLEN          57

#  define MAX_KEYLEN  ED448_KEYLEN

#  define X25519_BITS           253
#  define X25519_SECURITY_BITS  128

#  define X448_BITS             448
#  define X448_SECURITY_BITS    224

#  define ED25519_BITS          256
/* RFC8032 Section 8.5 */
#  define ED25519_SECURITY_BITS 128
#  define ED25519_SIGSIZE       64

#  define ED448_BITS            456
/* RFC8032 Section 8.5 */
#  define ED448_SECURITY_BITS   224
#  define ED448_SIGSIZE         114


typedef enum {
    ECX_KEY_TYPE_X25519,
    ECX_KEY_TYPE_X448,
    ECX_KEY_TYPE_ED25519,
    ECX_KEY_TYPE_ED448
} ECX_KEY_TYPE;

#define KEYTYPE2NID(type) \
    ((type) == ECX_KEY_TYPE_X25519 \
     ?  EVP_PKEY_X25519 \
     : ((type) == ECX_KEY_TYPE_X448 \
        ? EVP_PKEY_X448 \
        : ((type) == ECX_KEY_TYPE_ED25519 \
           ? EVP_PKEY_ED25519 \
           : EVP_PKEY_ED448)))

struct ecx_key_st {
    unsigned int haspubkey:1;
    unsigned char pubkey[MAX_KEYLEN];
    unsigned char *privkey;
    size_t keylen;
    ECX_KEY_TYPE type;
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;
};

typedef struct ecx_key_st ECX_KEY;

ECX_KEY *ecx_key_new(ECX_KEY_TYPE type, int haspubkey);
unsigned char *ecx_key_allocate_privkey(ECX_KEY *key);
void ecx_key_free(ECX_KEY *key);
int ecx_key_up_ref(ECX_KEY *key);

int X25519(uint8_t out_shared_key[32], const uint8_t private_key[32],
           const uint8_t peer_public_value[32]);
void X25519_public_from_private(uint8_t out_public_value[32],
                                const uint8_t private_key[32]);

int ED25519_sign(uint8_t *out_sig, const uint8_t *message, size_t message_len,
                 const uint8_t public_key[32], const uint8_t private_key[32],
                 OPENSSL_CTX *libctx, const char *propq);
int ED25519_verify(const uint8_t *message, size_t message_len,
                   const uint8_t signature[64], const uint8_t public_key[32],
                   OPENSSL_CTX *libctx, const char *propq);

int ED448_sign(OPENSSL_CTX *ctx, uint8_t *out_sig, const uint8_t *message,
               size_t message_len, const uint8_t public_key[57],
               const uint8_t private_key[57], const uint8_t *context,
               size_t context_len);

int ED448_verify(OPENSSL_CTX *ctx, const uint8_t *message, size_t message_len,
                 const uint8_t signature[114], const uint8_t public_key[57],
                 const uint8_t *context, size_t context_len);

int X448(uint8_t out_shared_key[56], const uint8_t private_key[56],
         const uint8_t peer_public_value[56]);
void X448_public_from_private(uint8_t out_public_value[56],
                              const uint8_t private_key[56]);

int s390x_x25519_mul(unsigned char u_dst[32],
                     const unsigned char u_src[32],
                     const unsigned char d_src[32]);
int s390x_x448_mul(unsigned char u_dst[56],
                   const unsigned char u_src[56],
                   const unsigned char d_src[56]);

/* Backend support */
int ecx_key_fromdata(ECX_KEY *ecx, const OSSL_PARAM params[],
                     int include_private);

# endif /* OPENSSL_NO_EC */
#endif
