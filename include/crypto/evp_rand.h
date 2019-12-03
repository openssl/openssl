/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_EVP_RAND_H
# define OSSL_CRYPTO_EVP_RAND_H

/* Maximum reseed intervals */
# define MAX_RESEED_INTERVAL                     (1 << 24)
# define MAX_RESEED_TIME_INTERVAL                (1 << 20) /* approx. 12 days */

/*
 * The number of bytes that constitutes an atomic lump of entropy with respect
 * to the FIPS 140-2 section 4.9.2 Conditional Tests.  The size is somewhat
 * arbitrary, the smaller the value, the less entropy is consumed on first
 * read but the higher the probability of the test failing by accident.
 *
 * The value is in bytes.
 */
# define CRNGT_BUFSIZ    16

/*
 * Maximum input size for the DRBG (entropy, nonce, personalization string)
 *
 * NIST SP800 90Ar1 allows a maximum of (1 << 35) bits i.e., (1 << 32) bytes.
 *
 * We lower it to 'only' INT32_MAX bytes, which is equivalent to 2 gigabytes.
 */
# define DRBG_MAX_LENGTH                         INT32_MAX

/* The default nonce */
#ifdef CHARSET_EBCDIC
# define DRBG_DEFAULT_PERS_STRING      { 0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, \
     0x4c, 0x20, 0x4e, 0x49, 0x53, 0x54, 0x20, 0x53, 0x50, 0x20, 0x38, 0x30, \
     0x30, 0x2d, 0x39, 0x30, 0x41, 0x20, 0x44, 0x52, 0x42, 0x47, 0x00};
#else
# define DRBG_DEFAULT_PERS_STRING                "OpenSSL NIST SP 800-90A DRBG"
#endif

/* DRBG status values */
typedef enum drbg_status_e {
    DRBG_UNINITIALISED,
    DRBG_READY,
    DRBG_ERROR
} DRBG_STATUS;

DRBG_STATUS evp_rand_ctx_status(EVP_RAND_CTX *ctx);
size_t evp_rand_ctx_max_request_length(EVP_RAND_CTX *ctx);
size_t evp_rand_ctx_max_adin_length(EVP_RAND_CTX *ctx);
int evp_rand_ctx_need_reseed(EVP_RAND_CTX *ctx);
size_t evp_rand_seedlen(EVP_RAND_CTX *ctx);
EVP_RAND_CTX *evp_rand_ctx_parent(EVP_RAND_CTX *ctx);

#endif
