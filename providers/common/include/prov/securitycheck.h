/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/types.h"

/* Functions that are common */
int ossl_rsa_check_key(const RSA *rsa, int protect);
int ec_check_key(const EC_KEY *ec, int protect);
int dsa_check_key(const DSA *dsa, int sign);
int dh_check_key(const DH *dh);

int digest_is_allowed(const EVP_MD *md);
int digest_get_approved_nid_with_sha1(const EVP_MD *md, int sha1_allowed);

/* Functions that are common */
int digest_md_to_nid(const EVP_MD *md, const OSSL_ITEM *it, size_t it_len);
int digest_get_approved_nid(const EVP_MD *md);

/* Functions that have different implementations for the FIPS_MODULE */
int digest_rsa_sign_get_md_nid(const EVP_MD *md, int sha1_allowed);
int securitycheck_enabled(void);
