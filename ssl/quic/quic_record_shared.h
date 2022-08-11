/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_RECORD_SHARED_H
# define OSSL_QUIC_RECORD_SHARED_H

# include <openssl/ssl.h>
# include "internal/quic_types.h"
# include "internal/quic_wire_pkt.h"

/*
 * QUIC Record Layer EL Management Utilities
 * =========================================
 *
 * This defines a structure for managing the cryptographic state at a given
 * encryption level, as this functionality is shared between QRX and QTX. For
 * QRL use only.
 */
typedef struct ossl_qrl_enc_level_st {
    /* Hash function used for key derivation. */
    EVP_MD                     *md;
    /* Context used for packet body ciphering. */
    EVP_CIPHER_CTX             *cctx;
    /* IV used to construct nonces used for AEAD packet body ciphering. */
    unsigned char               iv[EVP_MAX_IV_LENGTH];
    /* Have we permanently discarded this encryption level? */
    unsigned char               discarded;
    /* QRL_SUITE_* value. */
    uint32_t                    suite_id;
    /* Length of authentication tag. */
    uint32_t                    tag_len;
    /*
     * Cryptographic context used to apply and remove header protection from
     * packet headers.
     */
    QUIC_HDR_PROTECTOR          hpr;
    /* Usage counter. The caller maintains this. */
    uint64_t                    op_count;
} OSSL_QRL_ENC_LEVEL;

typedef struct ossl_qrl_enc_level_set_st {
    OSSL_QRL_ENC_LEVEL el[QUIC_ENC_LEVEL_NUM];
} OSSL_QRL_ENC_LEVEL_SET;

/*
 * Returns 1 if we have key material for a given encryption level, 0 if we do
 * not yet have material and -1 if the EL is discarded.
 */
int ossl_qrl_enc_level_set_have_el(OSSL_QRL_ENC_LEVEL_SET *els,
                                   uint32_t enc_level);

/*
 * Returns EL in a set. If enc_level is not a valid QUIC_ENC_LEVEL_* value,
 * returns NULL. If require_valid is 1, returns NULL if the EL is not
 * provisioned or has been discarded; otherwise, the returned EL may be
 * unprovisioned or discarded.
 */
OSSL_QRL_ENC_LEVEL *ossl_qrl_enc_level_set_get(OSSL_QRL_ENC_LEVEL_SET *els,
                                               uint32_t enc_level,
                                               int require_valid);

/* Provide secret to an EL. md may be NULL. */
int ossl_qrl_enc_level_set_provide_secret(OSSL_QRL_ENC_LEVEL_SET *els,
                                          OSSL_LIB_CTX *libctx,
                                          const char *propq,
                                          uint32_t enc_level,
                                          uint32_t suite_id,
                                          EVP_MD *md,
                                          const unsigned char *secret,
                                          size_t secret_len);

/*
 * Discard an EL. If is_final is non-zero, no secret can be provided for the EL
 * ever again.
 */
void ossl_qrl_enc_level_set_discard(OSSL_QRL_ENC_LEVEL_SET *els,
                                    uint32_t enc_level,
                                    int is_final);

#endif
