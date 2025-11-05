/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PROV_CIPHER_ASCON_AEAD128_H
# define OSSL_PROV_CIPHER_ASCON_AEAD128_H

# include <stdint.h>
# include <stdbool.h>
# include <openssl/core.h>
# define OSSL_INCLUDE_PROVIDER 1
# include "crypto/ascon.h"  /* ASCON algorithm header */
# undef OSSL_INCLUDE_PROVIDER

/*********************************************************************
 *
 *  ASCON-AEAD128 Context Structure and Types
 *
 *****/

/* ASCON-AEAD128 uses a fixed 16-byte (128-bit) tag length */
# ifndef FIXED_TAG_LENGTH
#  define FIXED_TAG_LENGTH ASCON_AEAD_TAG_MIN_SECURE_LEN
# endif

/* Direction enum for encryption/decryption */
typedef enum direction_et {
    ENCRYPTION,
    DECRYPTION
} direction_t;

/* ASCON-AEAD128 AEAD cipher context structure */
struct ascon_aead128_ctx_st
{
    void *provctx;
    ASCON_AEAD_CTX *internal_ctx; /* a handle for the implementation internal context */

    uint8_t tag[FIXED_TAG_LENGTH]; /* storing the tag with fixed length */
    uint8_t iv[ASCON_AEAD_NONCE_LEN]; /* storing the IV (nonce) for get_updated_iv */
    uint8_t key[ASCON_AEAD128_KEY_LEN]; /* storing the key for reinitialization */

    size_t tag_len;          /* tag length being used */

    direction_t direction;  /* either encryption or decryption */
    bool is_tag_set;               /* whether a tag has been computed or set */
    bool is_ongoing;        /* true = operation has started */
    bool assoc_data_processed;  /* whether associated data has been processed */
    bool iv_set;             /* whether the IV has been set */
    bool key_set;             /* whether the key has been set */
};

/*********************************************************************
 *
 *  ASCON-AEAD128 AEAD Function Declarations
 *
 *****/

/* Dispatch table for ASCON-AEAD128 */
extern const OSSL_DISPATCH ossl_ascon_aead128_functions[];

#endif /* OSSL_PROV_CIPHER_ASCON_AEAD128_H */
