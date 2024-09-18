/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Internal HSS/LMS/LM_OTS functions for other submodules,
 * not for application use
 */

#ifndef OSSL_CRYPTO_HSS_H
# define OSSL_CRYPTO_HSS_H
# pragma once
# ifndef OPENSSL_NO_HSS
#  include <openssl/e_os2.h>
#  include "types.h"
#  include "internal/refcount.h"
#  include "internal/packet.h"

#  define LMS_MAX_DIGEST_SIZE 32

#  define LMS_SIZE_I 16
#  define LMS_SIZE_PUB_LMS_TYPE 4
#  define LMS_SIZE_PUB_OTS_TYPE 4
#  define HSS_SIZE_PUB_L 4
#  define HSS_MAX_PUBKEY (HSS_SIZE_PUB_L + LMS_SIZE_PUB_LMS_TYPE \
                         + LMS_SIZE_PUB_OTS_TYPE + LMS_SIZE_I    \
                         + LMS_MAX_DIGEST_SIZE)

/*
 * Refer to RFC 8554 Section 4.1.
 * See also lm_ots_params[]
 */
typedef struct lm_ots_params_st {
    /*
     * The OTS type associates an id with a set of OTS parameters
     * e.g. OSSL_LM_OTS_TYPE_SHAKE_N32_W1
     */
    uint32_t lm_ots_type;
    uint32_t n;              /* Hash output size in bytes (32 or 24) */
    /*
     * The width of the Winternitz coefficients in bits. One of (1, 2, 4, 8)
     * Higher values of w are slower (~2^w computations) but have smaller
     * signatures.
     */
    uint32_t w;
    /*
     * The number of n-byte elements used for an LMOTS signature.
     * One of (265, 133, 67, 34) for n = 32, for w=1,2,4,8
     * One of (200, 101, 51, 26) for n = 24, for w=1,2,4,8
     */
    uint32_t p;
    const char *digestname; /* Hash Name */
} LM_OTS_PARAMS;

/* See lms_params[] */
typedef struct lms_params_st {
    /*
     * The lms type associates an id with a set of parameters to define the
     * Digest and Height of a LMS tree.
     * e.g, OSSL_LMS_TYPE_SHA256_N24_H25
     */
    uint32_t lms_type;
    const char *digestname; /* One of SHA256, SHA256-192, or SHAKE256 */
    uint32_t n; /* The Digest size (either 24 or 32), Useful for setting up SHAKE */
    uint32_t h; /* The height of a LMS tree which is one of 5, 10, 15, 20, 25) */
} LMS_PARAMS;

typedef struct lms_pub_key_st {
    /*
     * A buffer containing an encoded public key of the form
     * u32str(lmstype) || u32str(otstype) || I[16] || K[n]
     */
    unsigned char *encoded;         /* encoded public key data */
    size_t encodedlen;
    /*
     * K is the LMS tree's root public key (Called T(1))
     * It is n bytes long (the hash size).
     * It is a pointer into the encoded buffer
     */
    unsigned char *K;
    uint32_t allocated;             /* If 1 then encoded needs to be freed */
} LMS_PUB_KEY;

typedef struct lms_priv_key_st {
    /*
     * A buffer for holding private key data such as I & SEED
     * It has the format I[16] || u32str(q) || u16str(i) || u8str(0xff) || SEED
     * and is used when hashing to calculate x_q[i] values.
     */
    unsigned char *data;
    size_t datalen;
    unsigned char *seed;      /* Private key seed - a pointer into data */
} LMS_PRIV_KEY;

struct lms_key_st {
    LMS_PUB_KEY pub;
    LMS_PRIV_KEY priv;
    const LMS_PARAMS *lms_params;
    const LM_OTS_PARAMS *ots_params;
    unsigned char *Id;        /* A pointer to 16 bytes (I[16]) */
    uint32_t q;               /* leaf index (0..(2^h - 1)) */
    EVP_MD_CTX *mdctx;
    OSSL_LIB_CTX *libctx;
    uint64_t cachebits;
    unsigned char *node_cache;
};

/*
 * This object is used to store lists of keys and signatures.
 * For key generation and signing it is used for storing the lists of
 * active trees and the current signed public keys (See lists in hss_key_st).
 * For verification it is used inside hss_sig.c when decoding a signature.
 * These are different lists, since the verification process should not
 * interfere with the HSS_KEY object.
 */
typedef struct hss_lists {
    STACK_OF(LMS_KEY) *lmskeys;
    STACK_OF(LMS_SIG) *lmssigs;
} HSS_LISTS;

struct hss_key_st {
    uint32_t L;                     /* HSS number of levels */
    /*
     * For key generation and signing only one LMS tree is active for each
     * level of the hierarchy, so that is all that is updated,
     * Whenever an active child tree is exhausted it creates a new one.
     * A loaded public key would also be stored in lmskeys.
     */
    HSS_LISTS lists;
    /*
     * The virtual leaf index of the bottom LMS tree (0..2^64-1).
     * This can be used to calculate the leaf index for every level.
     * This is useful for determining when new active trees need to be
     * generated.
     */
    uint64_t index;
    uint64_t remaining;
    OSSL_LIB_CTX *libctx;
    char *propq;
    int reserved;
    uint32_t gen_type;

    CRYPTO_REF_COUNT references;
};

typedef struct lm_ots_sig_st {
    const LM_OTS_PARAMS *params;
    unsigned char *C; /* size is n */
    unsigned char *y; /* size is p * n */
    int allocated;
    uint32_t gen_type;
} LM_OTS_SIG;

typedef struct lms_signature_st {
    uint32_t q;
    LM_OTS_SIG sig;
    const LMS_PARAMS *params;
    unsigned char *paths; /* size is h * m */
    int paths_allocated;
} LMS_SIG;

/* A structure used for processing jobs when performing signature validation */
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

#define LMS_KEY_get(ctx, id) sk_LMS_KEY_value(ctx->lists.lmskeys, id)
#define LMS_KEY_add(ctx, key) (sk_LMS_KEY_push(ctx->lists.lmskeys, key) > 0)
#define LMS_KEY_count(ctx) sk_LMS_KEY_num(ctx->lists.lmskeys)
#define LMS_SIG_get(ctx, id) sk_LMS_SIG_value(ctx->lists.lmssigs, id)
#define LMS_SIG_add(ctx, key) (sk_LMS_SIG_push(ctx->lists.lmssigs, key) > 0)
#define LMS_SIG_count(ctx) sk_LMS_SIG_num(ctx->lists.lmssigs)
int ossl_hss_lists_init(HSS_LISTS *lists);
void ossl_hss_lists_free(HSS_LISTS *lists);
int ossl_hss_lists_copy(HSS_LISTS *dst, const HSS_LISTS *src);

HSS_KEY *ossl_hss_key_new(OSSL_LIB_CTX *libctx, const char *propq);
int ossl_hss_key_up_ref(HSS_KEY *key);
void ossl_hss_key_free(HSS_KEY *key);

int ossl_hss_sig_decode(HSS_LISTS *lists, LMS_KEY *pub, uint32_t L,
                        const unsigned char *sig, size_t siglen);
int ossl_hss_sig_to_text(BIO *out, HSS_KEY *hsskey, int selection);

int ossl_hss_pubkey_encode(HSS_KEY *hsskey, unsigned char *pub, size_t *publen);
size_t ossl_hss_pubkey_length(const unsigned char *data, size_t datalen);
int ossl_hss_pubkey_decode(const unsigned char *pub, size_t publen,
                           HSS_KEY *hsskey, int lms_only);
int ossl_hss_pubkey_from_params(const OSSL_PARAM params[], HSS_KEY *key);

#  if !defined(OPENSSL_NO_HSS_GEN) && !defined(FIPS_MODULE)
int ossl_hss_generate_key(HSS_KEY *hsskey, uint32_t levels,
                          uint32_t *lms_types, uint32_t *ots_types,
                          uint32_t gen_type);
int ossl_hss_sign(HSS_KEY *hsskey, const unsigned char *msg, size_t msglen,
                  unsigned char *outsig, size_t *outsiglen, size_t outsigmaxlen);
int ossl_hss_sign_init(HSS_KEY *hsskey);
int ossl_hss_sign_update(HSS_KEY *hsskey,
                         const unsigned char *msg, size_t msglen);
int ossl_hss_sign_final(HSS_KEY *hsskey, unsigned char *outsig,
                        size_t *outsiglen, size_t outsigmaxlen);
HSS_KEY *ossl_hss_key_reserve(const HSS_KEY *src, uint64_t count);
int ossl_hss_key_advance(HSS_KEY *hsskey, uint64_t count);
uint64_t ossl_hss_keys_remaining(const HSS_KEY *hsskey);
#  endif /* OPENSSL_NO_HSS_GEN */

const LMS_PARAMS *ossl_lms_params_get(uint32_t lms_type);
int ossl_lms_params_to_text(BIO *out, const LMS_PARAMS *prms);

LMS_KEY *ossl_lms_key_new(void);
void ossl_lms_key_free(LMS_KEY *key);
int ossl_lms_key_up_ref(LMS_KEY *key);
int ossl_lms_key_to_text(BIO *out, LMS_KEY *lmskey, int selection);

int ossl_lms_pubkey_from_pkt(PACKET *pkt, LMS_KEY *key);

LMS_SIG *ossl_lms_sig_from_pkt(PACKET *pkt, const LMS_KEY *pub);
LMS_SIG *ossl_lms_sig_new(uint32_t gen_type);
void ossl_lms_sig_free(LMS_SIG *sig);
int ossl_lms_sig_verify_init(LMS_VALIDATE_CTX *ctx);
int ossl_lms_sig_verify_update(LMS_VALIDATE_CTX *ctx,
                               const unsigned char *msg, size_t msglen);
int ossl_lms_sig_verify_final(LMS_VALIDATE_CTX *vctx);

LM_OTS_CTX *ossl_lm_ots_ctx_new(void);
void ossl_lm_ots_ctx_free(LM_OTS_CTX *ctx);
int ossl_lm_ots_pubK_from_priv(LMS_KEY *key, uint32_t q, unsigned char *outK);

const LM_OTS_PARAMS *ossl_lm_ots_params_get(uint32_t ots_type);
int ossl_lm_ots_params_to_text(BIO *out, const LM_OTS_PARAMS *prms);

# endif /* OPENSSL_NO_HSS */
#endif
