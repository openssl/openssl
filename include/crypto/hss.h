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

/*
 * HSS minimum and maximum number of LMS trees
 * A tree of height 1 can be used to represent a LMS tree.
 */
#  define HSS_MIN_L 1
#  define HSS_MAX_L 8

/* XDR sizes when encoding and decoding */
#  define HSS_SIZE_L 4
#  define HSS_MAX_PUBKEY (HSS_SIZE_L + LMS_SIZE_LMS_TYPE + LMS_SIZE_OTS_TYPE \
                          + LMS_SIZE_I + LMS_MAX_DIGEST_SIZE)

struct hss_key_st {
    uint32_t L;             /* HSS number of levels */
    /*
     * For signature verification this is just the root public key.
     * For signature generation there would be a list of active LMS_KEYS
     * (one for each level of the tree starting at the root).
     */
    //LMS_KEY *public;
    OSSL_LIB_CTX *libctx;
    char *propq;

    CRYPTO_REF_COUNT references;
};

HSS_KEY *ossl_hss_key_new(OSSL_LIB_CTX *libctx, const char *propq);
int ossl_hss_key_up_ref(HSS_KEY *key);
void ossl_hss_key_free(HSS_KEY *key);
int ossl_hss_key_equal(const HSS_KEY *hsskey1, const HSS_KEY *hsskey2,
                       int selection);
int ossl_hss_key_valid(const HSS_KEY *hsskey, int selection);
int ossl_hss_key_has(const HSS_KEY *hsskey, int selection);

int ossl_hss_pubkey_from_params(const OSSL_PARAM params[], HSS_KEY *hsskey);
int ossl_hss_pubkey_decode(const unsigned char *pub, size_t publen,
                           HSS_KEY *hsskey, int lms_only);
size_t ossl_hss_pubkey_length(const unsigned char *data, size_t datalen);
const char *ossl_hss_key_get_digestname(HSS_KEY *hsskey);
int ossl_hss_key_set_public(HSS_KEY *hsskey, LMS_KEY *key);
LMS_KEY *ossl_hss_key_get_public(const HSS_KEY *hsskey);

# endif /* OPENSSL_NO_HSS */
#endif /* OSSL_CRYPTO_HSS_H */
