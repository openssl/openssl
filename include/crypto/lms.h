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

# ifndef OPENSSL_NO_LMS

#  include <openssl/e_os2.h>
#  include "types.h"
#  include "internal/refcount.h"
#  include "internal/packet.h"

#  define LMS_ISIZE 16
#  define LMS_MAX_DIGEST_SIZE 32


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
 * A HSS public key object contains a L value and a LMS public key, so just
 * share the same object for both. As only signature validation is implemented
 * only public key fields are required in this object.
 *
 */
struct lms_key_st {
    uint32_t L;                     /* HSS number of levels */

    unsigned char *pub;             /* encoded public key data */
    size_t publen;
    const LMS_PARAMS *lms_params;
    const LM_OTS_PARAMS *ots_params;
    unsigned char *I;               /* 16 bytes - a pointer into pub */
    unsigned char *K;               /* n bytes - a ptr into pub */
    int pub_allocated;              /* If 1 then pub needs to be freed */

    OSSL_LIB_CTX *libctx;
    char *propq;
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
  unsigned char *paths; /* size is h * m */
  CRYPTO_REF_COUNT references;
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
    int failed;
} LMS_VALIDATE_CTX;

DEFINE_STACK_OF(LMS_KEY)
DEFINE_STACK_OF(LMS_SIG)

LMS_KEY *ossl_lms_key_new(OSSL_LIB_CTX *libctx, const char *propq);
void ossl_lms_key_set0_libctx(LMS_KEY *key, OSSL_LIB_CTX *libctx);
void ossl_lms_key_free(LMS_KEY *key);
int ossl_lms_key_up_ref(LMS_KEY *key);
LMS_KEY *ossl_lms_key_dup(const LMS_KEY *key, int selection);

LMS_SIG *ossl_lms_sig_new(void);
void ossl_lms_sig_free(LMS_SIG *sig);
int ossl_lms_sig_up_ref(LMS_SIG *sig);

int ossl_lms_pubkey_from_pkt(PACKET *pkt, LMS_KEY *key);
int ossl_lms_pubkey_from_data(const unsigned char *pub, size_t publen,
                              LMS_KEY *key);
LMS_SIG *ossl_lms_sig_from_data(const unsigned char *sig, size_t siglen,
                                const LMS_KEY *pub);

int ossl_hss_pubkey_from_data(const unsigned char *pub, size_t publen,
                              LMS_KEY *key);
int ossl_hss_decode(LMS_KEY *pub,
                    const unsigned char *sig, size_t siglen,
                    STACK_OF(LMS_KEY) *publist,
                    STACK_OF(LMS_SIG) *siglist);
void ossl_lms_sig_free(LMS_SIG *sig);

int ossl_lms_key_fromdata(const OSSL_PARAM params[], LMS_KEY *lms);
int ossl_hss_key_fromdata(const OSSL_PARAM params[], LMS_KEY *lms);


const LM_OTS_PARAMS *ossl_lm_ots_params_get(uint32_t ots_type);
const LMS_PARAMS *ossl_lms_params_get(uint32_t lms_type);

LM_OTS_CTX *ossl_lm_ots_ctx_new(void);
void ossl_lm_ots_ctx_free(LM_OTS_CTX *ctx);
//LM_OTS_CTX *ossl_lm_ots_ctx_dup(LM_OTS_CTX *src);

int ossl_lm_ots_ctx_pubkey_init(LM_OTS_CTX *ctx,
                                 const EVP_MD *md,
                                 const LM_OTS_SIG *sig,
                                 const LM_OTS_PARAMS *pub,
                                 const unsigned char *I, uint32_t q);
int ossl_lm_ots_ctx_pubkey_update(LM_OTS_CTX *ctx,
                                   const unsigned char *msg, size_t msglen);
int ossl_lm_ots_ctx_pubkey_final(LM_OTS_CTX *ctx, unsigned char *Kc);

int ossl_lms_sig_verify_init(LMS_VALIDATE_CTX *ctx);
int ossl_lms_sig_verify_update(LMS_VALIDATE_CTX *ctx,
                               const unsigned char *msg, size_t msglen);
int ossl_lms_sig_verify_final(LMS_VALIDATE_CTX *vctx);

#define U32STR(out, in)                      \
out[0] = (unsigned char)((in >> 24) & 0xff); \
out[1] = (unsigned char)((in >> 16) & 0xff); \
out[2] = (unsigned char)((in >> 8) & 0xff);  \
out[3] = (unsigned char)(in & 0xff)

# endif /* OPENSSL_NO_LMS */
#endif
