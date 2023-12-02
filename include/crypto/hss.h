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

#  define LMS_MAX_DIGEST_SIZE 32

#  define LMS_SIZE_I 16
#  define LMS_SIZE_PUB_LMS_TYPE  4
#  define LMS_SIZE_PUB_OTS_TYPE  4
#  define HSS_SIZE_PUB_L  4
#  define HSS_MAX_PUBKEY (HSS_SIZE_PUB_L + LMS_SIZE_PUB_LMS_TYPE + LMS_SIZE_PUB_OTS_TYPE + LMS_SIZE_I + LMS_MAX_DIGEST_SIZE)

/* Section 4.1 */
typedef struct lm_ots_params_st {
    uint32_t lm_ots_type;
    uint8_t n;              /* Hash output size in bytes */
    uint8_t w;              /* The width of the Winternitz coefficients in bits */
    uint16_t p;             /* The number of n-byte elements used for an LMOTS signature */
    const char *digestname; /* Hash Name */
} LM_OTS_PARAMS;

typedef struct lms_params_st {
    uint32_t lms_type;
    const char *digestname;
    uint32_t n;
    uint32_t h;
} LMS_PARAMS;

typedef struct lms_pub_key_st {
    unsigned char *K;               /* n bytes - a pointer into encoded */
    unsigned char *encoded;         /* encoded public key data */
    size_t encodedlen;
    uint32_t allocated;             /* If 1 then encoded needs to be freed */
} LMS_PUB_KEY;

typedef struct lms_priv_key_st {
    unsigned char *data;      /* A buffer for holding private key data */
    size_t datalen;
    unsigned char *seed;      /* Private key seed - a pointer into data */
} LMS_PRIV_KEY;

struct lms_key_st {
    LMS_PUB_KEY pub;
    LMS_PRIV_KEY priv;
    const LMS_PARAMS *lms_params;
    const LM_OTS_PARAMS *ots_params;
    unsigned char *I;         /* A pointer to 16 bytes */
    uint32_t q;               /* Key Pair leaf index (0..(2^h - 1)) */
    EVP_MD_CTX *mdctx;
    OSSL_LIB_CTX *libctx;
    uint64_t cachebits;
    unsigned char *node_cache;
};

struct hss_key_st {
    uint32_t L;                     /* HSS number of levels */
    uint32_t height;
    STACK_OF(LMS_KEY) *lmskeys;
    STACK_OF(LMS_SIG) *lmssigs;
    uint64_t index;
    uint64_t remaining;
    OSSL_LIB_CTX *libctx;
    int reserved;

    CRYPTO_REF_COUNT references;
};

typedef struct lm_ots_sig_st {
    const LM_OTS_PARAMS *params;
    unsigned char *C; /* size is n */
    unsigned char *y; /* size is p * n */
} LM_OTS_SIG;

typedef struct lms_signature_st {
  uint32_t q;
  LM_OTS_SIG sig;
  const LMS_PARAMS *params;
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

HSS_KEY *ossl_hss_key_reserve(const HSS_KEY *src, uint64_t count);
int ossl_hss_key_advance(HSS_KEY *hsskey, uint64_t count);

int ossl_hss_decode(HSS_KEY *pub,
                    const unsigned char *sig, size_t siglen);

HSS_KEY *ossl_hss_key_new(OSSL_LIB_CTX *libctx, const char *propq);
int ossl_hss_key_up_ref(HSS_KEY *key);
void ossl_hss_key_free(HSS_KEY *key);
int ossl_hss_pub_key_encode(HSS_KEY *hsskey, unsigned char *pub, size_t *publen);
size_t ossl_hss_pubkey_length(const unsigned char *data, size_t datalen);
int ossl_hss_pub_key_decode(const unsigned char *pub, size_t publen,
                            HSS_KEY *hsskey);
int ossl_hss_pubkey_from_params(const OSSL_PARAM params[], HSS_KEY *key);
int ossl_hss_generate_key(HSS_KEY *hsskey, uint32_t levels,
                          uint32_t *lms_types, uint32_t *ots_types);
int ossl_hss_sign(HSS_KEY *hsskey, const unsigned char *msg, size_t msglen,
                  unsigned char *outsig, size_t *outsiglen, size_t outsigmaxlen,
                  OSSL_LIB_CTX *libctx, EVP_MD_CTX *mdctx);

LMS_KEY *ossl_lms_key_new(void);
void ossl_lms_key_free(LMS_KEY *key);
int ossl_lms_key_up_ref(LMS_KEY *key);
int ossl_lms_pub_key_from_pkt(PACKET *pkt, LMS_KEY *key);
//int ossl_lms_pub_key_encode(const unsigned char *pub, size_t publen,
//                            LMS_KEY *key);

LMS_SIG *ossl_lms_sig_from_pkt(PACKET *pkt, const LMS_KEY *pub);
LMS_SIG *ossl_lms_sig_new(void);
void ossl_lms_sig_free(LMS_SIG *sig);

LM_OTS_CTX *ossl_lm_ots_ctx_new(void);
void ossl_lm_ots_ctx_free(LM_OTS_CTX *ctx);
int ossl_lm_ots_pubK_from_priv(LMS_KEY *key, uint32_t q, unsigned char *outK);

int ossl_lms_sig_verify_init(LMS_VALIDATE_CTX *ctx);
int ossl_lms_sig_verify_update(LMS_VALIDATE_CTX *ctx,
                               const unsigned char *msg, size_t msglen);
int ossl_lms_sig_verify_final(LMS_VALIDATE_CTX *vctx);

int ossl_lms_key_to_text(BIO *out, LMS_KEY *lmskey, int height, int selection);
int ossl_lms_params_to_text(BIO *out, const LMS_PARAMS *prms);
int ossl_lm_ots_params_to_text(BIO *out, const LM_OTS_PARAMS *prms);

# endif /* OPENSSL_NO_HSS */
#endif
