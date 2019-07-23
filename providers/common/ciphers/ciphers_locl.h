/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#include <openssl/params.h>
#include <openssl/core_numbers.h>
#include "internal/cryptlib.h"
#include "internal/modes_int.h"

#define GENERIC_BLOCK_SIZE 16
#define IV_STATE_UNINITIALISED 0  /* initial state is not initialized */
#define IV_STATE_BUFFERED      1  /* iv has been copied to the iv buffer */
#define IV_STATE_COPIED        2  /* iv has been copied from the iv buffer */
#define IV_STATE_FINISHED      3  /* the iv has been used - so don't reuse it */

#define PROV_CIPHER_FUNC(type, name, args) typedef type (* OSSL_##name##_fn)args

typedef struct prov_generic_cipher_st PROV_GENERIC_CIPHER;

typedef struct prov_generic_key_st {
    block128_f block;
    union {
        cbc128_f cbc;
        ctr128_f ctr;
    } stream;

    const PROV_GENERIC_CIPHER *ciph;       /* cipher functions */

    /*
     * num contains the number of bytes of |iv| which are valid for modes that
     * manage partial blocks themselves.
     */
    size_t num;

    int mode;
    int enc;              /* Set to 1 for encrypt, or 0 otherwise */
    size_t bufsz;         /* Number of bytes in buf */
    size_t keylen;        /* key size (in bytes) */
    size_t blocksize;
    uint64_t flags;
    unsigned int pad : 1; /* Whether padding should be used or not */

    /* Buffer of partial blocks processed via update calls */
    unsigned char buf[GENERIC_BLOCK_SIZE];
    unsigned char iv[GENERIC_BLOCK_SIZE];
    const void *ks; /* Pointer to algorithm specific key data */
} PROV_GENERIC_KEY;

struct prov_generic_cipher_st {
  int (*init)(PROV_GENERIC_KEY *dat, const uint8_t *key, size_t keylen);
  int (*cipher)(PROV_GENERIC_KEY *dat, uint8_t *out, const uint8_t *in,
                size_t inl);
};

#include "ciphers_aes.h"
#include "ciphers_aria.h"
#include "ciphers_camellia.h"
#include "ciphers_gcm.h"
#include "ciphers_ccm.h"

size_t fillblock(unsigned char *buf, size_t *buflen, size_t blocksize,
                 const unsigned char **in, size_t *inlen);
int trailingdata(unsigned char *buf, size_t *buflen, size_t blocksize,
                 const unsigned char **in, size_t *inlen);
void padblock(unsigned char *buf, size_t *buflen, size_t blocksize);
int unpadblock(unsigned char *buf, size_t *buflen, size_t blocksize);

OSSL_OP_cipher_gettable_params_fn     cipher_default_gettable_params;
OSSL_OP_cipher_gettable_ctx_params_fn cipher_default_gettable_ctx_params;
OSSL_OP_cipher_settable_ctx_params_fn cipher_default_settable_ctx_params;
OSSL_OP_cipher_gettable_ctx_params_fn cipher_aead_gettable_ctx_params;
OSSL_OP_cipher_settable_ctx_params_fn cipher_aead_settable_ctx_params;
int cipher_default_get_params(OSSL_PARAM params[], int md, unsigned long flags,
                              int kbits, int blkbits, int ivbits);

#define IMPLEMENT_aead_cipher(alg, lc, UCMODE, flags, kbits, blkbits, ivbits)  \
    static OSSL_OP_cipher_get_params_fn alg##_##kbits##_##lc##_get_params;     \
    static int alg##_##kbits##_##lc##_get_params(OSSL_PARAM params[])          \
    {                                                                          \
        return cipher_default_get_params(params, EVP_CIPH_##UCMODE##_MODE,     \
                                         flags, kbits, blkbits, ivbits);       \
    }                                                                          \
    static OSSL_OP_cipher_newctx_fn alg##kbits##lc##_newctx;                   \
    static void * alg##kbits##lc##_newctx(void *provctx)                       \
    {                                                                          \
        return alg##_##lc##_newctx(provctx, kbits);                            \
    }                                                                          \
    const OSSL_DISPATCH alg##kbits##lc##_functions[] = {                       \
        { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))alg##kbits##lc##_newctx },  \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))alg##_##lc##_freectx },    \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) lc##_einit },        \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void)) lc##_dinit },        \
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void)) lc##_stream_update },      \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void)) lc##_stream_final },        \
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void)) lc##_cipher },             \
        { OSSL_FUNC_CIPHER_GET_PARAMS,                                         \
            (void (*)(void)) alg##_##kbits##_##lc##_get_params },              \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                     \
            (void (*)(void)) lc##_get_ctx_params },                            \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                     \
            (void (*)(void)) lc##_set_ctx_params },                            \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                    \
                (void (*)(void))cipher_default_gettable_params },              \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                \
                (void (*)(void))cipher_aead_gettable_ctx_params },             \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                \
                (void (*)(void))cipher_aead_settable_ctx_params },             \
        { 0, NULL }                                                            \
    }
