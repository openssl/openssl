/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "cipher_aead.h"

typedef struct prov_ccm_hw_st PROV_CCM_HW;

#if defined(OPENSSL_CPUID_OBJ) && defined(__s390__)
/*-
 * KMAC-AES parameter block - begin
 * (see z/Architecture Principles of Operation >= SA22-7832-08)
 */
typedef struct S390X_kmac_params_st {
    union {
        unsigned long long g[2];
        unsigned char b[16];
    } icv;
    unsigned char k[32];
} S390X_KMAC_PARAMS;
/* KMAC-AES parameter block - end */
#endif

/* Base structure that is shared by AES & ARIA for CCM MODE */
typedef struct prov_ccm_st {
    unsigned int enc : 1;
    unsigned int key_set : 1;  /* Set if key initialised */
    unsigned int iv_set : 1;   /* Set if an iv is set */
    unsigned int tag_set : 1;  /* Set if tag is valid */
    unsigned int len_set : 1;  /* Set if message length set */
    size_t l, m;               /* L and M parameters from RFC3610 */
    size_t keylen;
    size_t tls_aad_len;        /* TLS AAD length */
    size_t tls_aad_pad_sz;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char buf[AES_BLOCK_SIZE];
    CCM128_CONTEXT ccm_ctx;
    ccm128_f str;
    const PROV_CCM_HW *hw;     /* hardware specific methods  */
} PROV_CCM_CTX;

typedef struct prov_aes_ccm_ctx_st {
    PROV_CCM_CTX base;         /* Must be first */
    union {
        OSSL_UNION_ALIGN;
        /*-
         * Padding is chosen so that s390x.kmac.k overlaps with ks.ks and
         * fc with ks.ks.rounds. Remember that on s390x, an AES_KEY's
         * rounds field is used to store the function code and that the key
         * schedule is not stored (if aes hardware support is detected).
         */
        struct {
            unsigned char pad[16];
            AES_KEY ks;
        } ks;
#if defined(OPENSSL_CPUID_OBJ) && defined(__s390__)
        struct {
            S390X_KMAC_PARAMS kmac;
            unsigned long long blocks;
            union {
                unsigned long long g[2];
                unsigned char b[AES_BLOCK_SIZE];
            } nonce;
            union {
                unsigned long long g[2];
                unsigned char b[AES_BLOCK_SIZE];
            } buf;
            unsigned char dummy_pad[168];
            unsigned int fc;   /* fc has same offset as ks.ks.rounds */
        } s390x;
#endif /* defined(OPENSSL_CPUID_OBJ) && defined(__s390__) */
    } ccm;
} PROV_AES_CCM_CTX;

PROV_CIPHER_FUNC(int, CCM_cipher, (PROV_CCM_CTX *ctx, unsigned char *out,      \
                                   size_t *padlen, const unsigned char *in,    \
                                   size_t len));
PROV_CIPHER_FUNC(int, CCM_setkey, (PROV_CCM_CTX *ctx,                          \
                                   const unsigned char *key, size_t keylen));
PROV_CIPHER_FUNC(int, CCM_setiv, (PROV_CCM_CTX *dat,                           \
                                  const unsigned char *iv, size_t ivlen,       \
                                  size_t mlen));
PROV_CIPHER_FUNC(int, CCM_setaad, (PROV_CCM_CTX *ctx,                          \
                                   const unsigned char *aad, size_t aadlen));
PROV_CIPHER_FUNC(int, CCM_auth_encrypt, (PROV_CCM_CTX *ctx,                    \
                                         const unsigned char *in,              \
                                         unsigned char *out, size_t len,       \
                                         unsigned char *tag, size_t taglen));
PROV_CIPHER_FUNC(int, CCM_auth_decrypt, (PROV_CCM_CTX *ctx,                    \
                                         const unsigned char *in,              \
                                         unsigned char *out, size_t len,       \
                                         unsigned char *tag, size_t taglen));
PROV_CIPHER_FUNC(int, CCM_gettag, (PROV_CCM_CTX *ctx,                          \
                                   unsigned char *tag,  size_t taglen));

/*
 * CCM Mode internal method table used to handle hardware specific differences,
 * (and different algorithms).
 */
struct prov_ccm_hw_st {
    OSSL_CCM_setkey_fn setkey;
    OSSL_CCM_setiv_fn setiv;
    OSSL_CCM_setaad_fn setaad;
    OSSL_CCM_auth_encrypt_fn auth_encrypt;
    OSSL_CCM_auth_decrypt_fn auth_decrypt;
    OSSL_CCM_gettag_fn gettag;
};

const PROV_CCM_HW *PROV_AES_HW_ccm(size_t keylen);

OSSL_OP_cipher_encrypt_init_fn ccm_einit;
OSSL_OP_cipher_decrypt_init_fn ccm_dinit;
OSSL_OP_cipher_get_ctx_params_fn ccm_get_ctx_params;
OSSL_OP_cipher_set_ctx_params_fn ccm_set_ctx_params;
OSSL_OP_cipher_update_fn ccm_stream_update;
OSSL_OP_cipher_final_fn ccm_stream_final;
OSSL_OP_cipher_cipher_fn ccm_cipher;
void ccm_initctx(PROV_CCM_CTX *ctx, size_t keybits, const PROV_CCM_HW *hw);

int ccm_generic_setiv(PROV_CCM_CTX *ctx, const unsigned char *nonce,
                      size_t nlen, size_t mlen);
int ccm_generic_setaad(PROV_CCM_CTX *ctx, const unsigned char *aad, size_t alen);
int ccm_generic_gettag(PROV_CCM_CTX *ctx, unsigned char *tag, size_t tlen);
int ccm_generic_auth_encrypt(PROV_CCM_CTX *ctx, const unsigned char *in,
                             unsigned char *out, size_t len,
                             unsigned char *tag, size_t taglen);
int ccm_generic_auth_decrypt(PROV_CCM_CTX *ctx, const unsigned char *in,
                             unsigned char *out, size_t len,
                             unsigned char *expected_tag, size_t taglen);
