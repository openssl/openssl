/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PROV_CIPHER_ASCON128_H
# define OSSL_PROV_CIPHER_ASCON128_H

# include "ciphercommon_ascon.h"
# include <ascon.h>  /* LibAscon library header */

/*********************************************************************
 *
 *  ASCON-128 Context Structure and Types
 *
 *****/

/* ASCON-128 uses a fixed 16-byte (128-bit) tag length */
# ifndef FIXED_TAG_LENGTH
#  define FIXED_TAG_LENGTH ASCON_AEAD_TAG_MIN_SECURE_LEN
# endif

/* Direction enum for encryption/decryption */
typedef enum direction_et
{
    ENCRYPTION,
    DECRYPTION
} direction_t;

/* Internal context type alias */
typedef ascon_aead_ctx_t intctx_t;

/* ASCON-128 AEAD cipher context structure */
struct ascon_ctx_st
{
    struct provider_ctx_st *provctx;

    uint8_t tag[FIXED_TAG_LENGTH]; /* storing the tag with fixed length */
    bool is_tag_set;               /* whether a tag has been computed or set */

    direction_t direction;  /* either encryption or decryption */
    bool is_ongoing;        /* true = operation has started */
    intctx_t *internal_ctx; /* a handle for the implementation internal context*/
    bool assoc_data_processed;  /* whether associated data has been processed */
    size_t tag_len;          /* tag length being used */
};

/*********************************************************************
 *
 *  ASCON-128 AEAD Function Declarations
 *
 *****/

/* Dispatch table for ASCON-128 */
extern const OSSL_DISPATCH ossl_ascon128_functions[];

#endif /* OSSL_PROV_CIPHER_ASCON128_H */

