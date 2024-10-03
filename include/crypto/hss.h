/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal HSS functions for other submodules, not for application use */

#ifndef OSSL_CRYPTO_HSS_H
# define OSSL_CRYPTO_HSS_H
# pragma once
# ifndef OPENSSL_NO_HSS
#  include "lms.h"
#  include "lms_sig.h"

/*
 * HSS minimum and maximum number of LMS trees
 * A tree of height 1 can be used to represent a LMS tree.
 */
#  define HSS_MIN_L 1
#  define HSS_MAX_L 8

/* XDR sizes when encoding and decoding */
#  define HSS_SIZE_PUB_L 4
#  define HSS_MAX_PUBKEY (HSS_SIZE_PUB_L + LMS_SIZE_PUB_LMS_TYPE \
                          + LMS_SIZE_PUB_OTS_TYPE + LMS_SIZE_I   \
                          + LMS_MAX_DIGEST_SIZE)

/*
 * HSS require a tree of LMS keys, as well as a list of signatures.
 * This object is used to store lists of HSS related LMS keys and signatures.
 * For verification it is used when decoding a signature.
 */
typedef struct hss_lists {
    STACK_OF(LMS_KEY) *lmskeys;
    STACK_OF(LMS_SIG) *lmssigs;
} HSS_LISTS;

struct hss_key_st {
    uint32_t L; /* HSS number of levels */
    /*
     * For key generation and signing only one LMS tree is active for each
     * level of the hierarchy, so that is all that is updated,
     * Whenever an active child tree is exhausted it creates a new one.
     * A loaded public key would also be stored in lmskeys.
     */
    HSS_LISTS lists;
    OSSL_LIB_CTX *libctx;
    char *propq;

    CRYPTO_REF_COUNT references;
};

DEFINE_STACK_OF(LMS_KEY)
DEFINE_STACK_OF(LMS_SIG)

#  define HSS_LMS_KEY_get(ctx, id) sk_LMS_KEY_value(ctx->lists.lmskeys, id)
#  define HSS_LMS_KEY_add(ctx, key) (sk_LMS_KEY_push(ctx->lists.lmskeys, key) > 0)
#  define HSS_LMS_KEY_count(ctx) sk_LMS_KEY_num(ctx->lists.lmskeys)
#  define HSS_LMS_SIG_get(ctx, id) sk_LMS_SIG_value(ctx->lists.lmssigs, id)
#  define HSS_LMS_SIG_add(ctx, key) (sk_LMS_SIG_push(ctx->lists.lmssigs, key) > 0)
#  define HSS_LMS_SIG_count(ctx) sk_LMS_SIG_num(ctx->lists.lmssigs)

int ossl_hss_lists_init(HSS_LISTS *lists);
void ossl_hss_lists_free(HSS_LISTS *lists);

HSS_KEY *ossl_hss_key_new(OSSL_LIB_CTX *libctx, const char *propq);
int ossl_hss_key_up_ref(HSS_KEY *key);
void ossl_hss_key_free(HSS_KEY *key);
int ossl_hss_key_equal(const HSS_KEY *hsskey1, const HSS_KEY *hsskey2,
                       int selection);
int ossl_hss_key_valid(const HSS_KEY *hsskey, int selection);
int ossl_hss_key_has(const HSS_KEY *hsskey, int selection);

int ossl_hss_pubkey_from_params(const OSSL_PARAM params[], HSS_KEY *hsskey);

# endif /* OPENSSL_NO_HSS */
#endif /* OSSL_CRYPTO_HSS_H */
