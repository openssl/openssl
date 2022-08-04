/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_RECORD_UTIL_H
# define OSSL_QUIC_RECORD_UTIL_H

# include <openssl/ssl.h>

/*
 * QUIC Key Derivation Utilities
 * =============================
 */

/* HKDF-Extract(salt, IKM) (RFC 5869) */
int ossl_quic_hkdf_extract(OSSL_LIB_CTX *libctx,
                           const char *propq,
                           const EVP_MD *md,
                           const unsigned char *salt, size_t salt_len,
                           const unsigned char *ikm, size_t ikm_len,
                           unsigned char *out, size_t out_len);

/*
 * QUIC Record Layer Ciphersuite Info
 * ==================================
 */

/* Available QUIC Record Layer (QRL) ciphersuites. */
# define QRL_SUITE_AES128GCM            1 /* SHA256 */
# define QRL_SUITE_AES256GCM            2 /* SHA384 */
# define QRL_SUITE_CHACHA20POLY1305     3 /* SHA256 */

/* Returns cipher name in bytes or NULL if suite ID is invalid. */
const char *ossl_qrl_get_suite_cipher_name(uint32_t suite_id);

/* Returns hash function name in bytes or NULL if suite ID is invalid. */
const char *ossl_qrl_get_suite_md_name(uint32_t suite_id);

/* Returns secret length in bytes or 0 if suite ID is invalid. */
uint32_t ossl_qrl_get_suite_secret_len(uint32_t suite_id);

/* Returns key length in bytes or 0 if suite ID is invalid. */
uint32_t ossl_qrl_get_suite_cipher_key_len(uint32_t suite_id);

/* Returns IV length in bytes or 0 if suite ID is invalid. */
uint32_t ossl_qrl_get_suite_cipher_iv_len(uint32_t suite_id);

/* Returns AEAD auth tag length in bytes or 0 if suite ID is invalid. */
uint32_t ossl_qrl_get_suite_cipher_tag_len(uint32_t suite_id);

/* Returns a QUIC_HDR_PROT_CIPHER_* value or 0 if suite ID is invalid. */
uint32_t ossl_qrl_get_suite_hdr_prot_cipher_id(uint32_t suite_id);

/* Returns header protection key length in bytes or 0 if suite ID is invalid. */
uint32_t ossl_qrl_get_suite_hdr_prot_key_len(uint32_t suite_id);

#endif
