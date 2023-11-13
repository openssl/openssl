/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal LMS functions for other submodules: not for application use */

#ifndef OSSL_CRYPTO_LMS_H
# define OSSL_CRYPTO_LMS_H
# pragma once

# ifndef OPENSSL_NO_HSS

#  include <openssl/e_os2.h>
#  include "types.h"
#  include "internal/refcount.h"
#  include "internal/packet.h"

#  define LMS_ISIZE 16
#  define LMS_MAX_DIGEST_SIZE 32
#  define HSS_MAX_PUBKEY (4 + 4 + 4 + LMS_ISIZE + LMS_MAX_DIGEST_SIZE)

/* Section 4.1 */
typedef struct lm_ots_params_st {
    uint32_t lm_ots_type;
    const char *digestname; /* Hash Name */
    uint32_t n;             /* Hash output size in bytes */
    uint32_t w;             /* The width of the Winternitz coefficients in bits */
    uint32_t p;             /* The number of n-byte elements used for LMOTS signature */
} LM_OTS_PARAMS;

typedef struct lms_params_st {
    uint32_t lms_type;
    const char *digestname;
    uint32_t n;
    uint32_t h;
} LMS_PARAMS;

/*
 * As only signature validation is implemented only public key fields are
 * required in this object.
 */
struct lms_key_st {
    unsigned char *pub;             /* encoded public key data */
    size_t publen;
    const LMS_PARAMS *lms_params;
    const LM_OTS_PARAMS *ots_params;
    unsigned char *I;               /* 16 bytes - a pointer into pub or priv_bytes */
    unsigned char *K;               /* n bytes - a pointer into pub */
    uint32_t pub_allocated;         /* If 1 then pub needs to be freed */
    unsigned char *priv_seed;       /* Private key seed - a pointer into priv_bytes */
    unsigned char *priv_bytes;      /* A buffer for holding private key data */
    uint32_t q;                     /* Key Pair leaf index (0..(2^h - 1)) */

    CRYPTO_REF_COUNT references;
};

/*
 * A HSS public key object contains a L value and a LMS public key
 * The lms_pub field must be first so that it is possible to treat a HSS_KEY
 * like a LMS_KEY when a list of LMS_KEY pointers are required.
 */
struct hss_key_st {
    struct lms_key_st lms_pub;   /* This MUST BE the first field */
    uint32_t L;                  /* HSS number of levels */
};

typedef struct lm_ots_sig_st {
    const LM_OTS_PARAMS *params;
    unsigned char *C; /* size is n */
    unsigned char *y; /* size is p * n */
} LM_OTS_SIG;

typedef struct lms_signature_st {
  uint32_t q;
  LM_OTS_SIG sig;
  unsigned char *paths; /* size is h * m */
} LMS_SIG;

typedef struct lm_ots_ctx_st {
    const LM_OTS_SIG *sig;
    EVP_MD_CTX *mdctx, *mdctxIq;
} LM_OTS_CTX;

typedef struct {
    LMS_KEY *pub;
    LMS_SIG *sig;
    LM_OTS_CTX *pubctx;
    EVP_MD *md;
    const unsigned char *msg;
    size_t msglen;
    uint32_t failed;
} LMS_VALIDATE_CTX;

DEFINE_STACK_OF(LMS_KEY)
DEFINE_STACK_OF(LMS_SIG)


int ossl_hss_decode(const HSS_KEY *pub,
                    const unsigned char *sig, size_t siglen,
                    STACK_OF(LMS_KEY) *publist,
                    STACK_OF(LMS_SIG) *siglist);

HSS_KEY *ossl_hss_key_new(OSSL_LIB_CTX *libctx, const char *propq);
int ossl_hss_key_up_ref(HSS_KEY *key);
void ossl_hss_key_free(HSS_KEY *key);
size_t ossl_hss_pubkey_length(const unsigned char *data, size_t datalen);
int ossl_hss_pubkey_from_data(const unsigned char *pub, size_t publen,
                              HSS_KEY *key);
int ossl_hss_pubkey_from_params(const OSSL_PARAM params[], HSS_KEY *key);

LMS_KEY *ossl_lms_key_new(void);
void ossl_lms_key_free(LMS_KEY *key);
int ossl_lms_key_up_ref(LMS_KEY *key);
int ossl_lms_pubkey_from_pkt(PACKET *pkt, LMS_KEY *key);
int ossl_lms_pubkey_from_data(const unsigned char *pub, size_t publen,
                              LMS_KEY *key);

LMS_SIG *ossl_lms_sig_from_pkt(PACKET *pkt, const LMS_KEY *pub);
void ossl_lms_sig_free(LMS_SIG *sig);

LM_OTS_CTX *ossl_lm_ots_ctx_new(void);
void ossl_lm_ots_ctx_free(LM_OTS_CTX *ctx);

int ossl_lms_sig_verify_init(LMS_VALIDATE_CTX *ctx);
int ossl_lms_sig_verify_update(LMS_VALIDATE_CTX *ctx,
                               const unsigned char *msg, size_t msglen);
int ossl_lms_sig_verify_final(LMS_VALIDATE_CTX *vctx);

# endif /* OPENSSL_NO_HSS */
#endif
