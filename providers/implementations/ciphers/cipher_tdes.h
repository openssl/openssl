/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/des.h>
#include <openssl/core_numbers.h>
#include "crypto/des_platform.h"

#define DES_BLOCK_SIZE 8
#define TDES_IVLEN 8

/* TODO(3.0) Figure out what flags need to be here */
#define TDES_FLAGS (EVP_CIPH_RAND_KEY)

typedef struct prov_tdes_ctx_st {
    PROV_CIPHER_CTX base;      /* Must be first */
    union {
        OSSL_UNION_ALIGN;
        DES_key_schedule ks[3];
    } tks;
    union {
        void (*cbc) (const void *, void *, size_t,
                     const DES_key_schedule *, unsigned char *);
    } tstream;

} PROV_TDES_CTX;

#define IMPLEMENT_tdes_cipher(type, UCTYPE, lcmode, UCMODE, flags,             \
                              kbits, blkbits, ivbits, block)                   \
static OSSL_OP_cipher_newctx_fn tdes_##type##_##lcmode##_newctx;               \
static void *tdes_##type##_##lcmode##_newctx(void *provctx)                    \
{                                                                              \
    return tdes_newctx(provctx, EVP_CIPH_##UCMODE##_MODE, kbits, blkbits,      \
                       ivbits, flags, PROV_CIPHER_HW_tdes_##type##_##lcmode());\
}                                                                              \
static OSSL_OP_cipher_get_params_fn tdes_##type##_##lcmode##_get_params;       \
static int tdes_##type##_##lcmode##_get_params(OSSL_PARAM params[])            \
{                                                                              \
    return cipher_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE, flags,  \
                                     kbits, blkbits, ivbits);                  \
}                                                                              \
const OSSL_DISPATCH tdes_##type##_##lcmode##_functions[] = {                   \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))tdes_einit },             \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))tdes_dinit },             \
    { OSSL_FUNC_CIPHER_UPDATE,                                                 \
      (void (*)(void))cipher_generic_##block##_update },                       \
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))cipher_generic_##block##_final },\
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))cipher_generic_cipher },        \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                 \
      (void (*)(void))tdes_##type##_##lcmode##_newctx },                       \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))tdes_freectx },                \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void))tdes_##type##_##lcmode##_get_params },                   \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))cipher_generic_gettable_params },                        \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))tdes_get_ctx_params },  \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))tdes_gettable_ctx_params },                              \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
     (void (*)(void))cipher_generic_set_ctx_params },                          \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
     (void (*)(void))cipher_generic_settable_ctx_params },                     \
    { 0, NULL }                                                                \
}

void *tdes_newctx(void *provctx, int mode, size_t kbits, size_t blkbits,
                  size_t ivbits, uint64_t flags, const PROV_CIPHER_HW *hw);
OSSL_OP_cipher_freectx_fn tdes_freectx;
OSSL_OP_cipher_encrypt_init_fn tdes_einit;
OSSL_OP_cipher_decrypt_init_fn tdes_dinit;
OSSL_OP_cipher_get_ctx_params_fn tdes_get_ctx_params;
OSSL_OP_cipher_gettable_ctx_params_fn tdes_gettable_ctx_params;

#define PROV_CIPHER_HW_tdes_mode(type, mode)                                   \
static const PROV_CIPHER_HW type##_##mode = {                                  \
    cipher_hw_tdes_##type##_initkey,                                           \
    cipher_hw_tdes_##mode                                                      \
};                                                                             \
const PROV_CIPHER_HW *PROV_CIPHER_HW_tdes_##type##_##mode(void)                \
{                                                                              \
    return &type##_##mode;                                                     \
}

int cipher_hw_tdes_ede3_initkey(PROV_CIPHER_CTX *ctx, const unsigned char *key,
                                size_t keylen);
int cipher_hw_tdes_cbc(PROV_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t inl);
int cipher_hw_tdes_ecb(PROV_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t len);

const PROV_CIPHER_HW *PROV_CIPHER_HW_tdes_ede3_cbc(void);
const PROV_CIPHER_HW *PROV_CIPHER_HW_tdes_ede3_ecb(void);
