/*
 * Copyright 2019-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/types.h"
#include <openssl/ec.h>

/* Functions that are common */
int ossl_rsa_key_op_get_protect(const RSA *rsa, int operation, int *outprotect);
int ossl_rsa_check_key_size(const RSA *rsa, int protect);

#ifndef OPENSSL_NO_EC
int ossl_ec_check_curve_allowed(const EC_GROUP *group);
int ossl_ec_check_security_strength(const EC_GROUP *group, int protect);
#endif

int ossl_dsa_check_key(const DSA *dsa, int sign);
int ossl_dh_check_key(const DH *dh);

int ossl_digest_md_to_nid(const EVP_MD *md, const OSSL_ITEM *it, size_t it_len);
int ossl_digest_get_approved_nid(const EVP_MD *md);

/* Functions that have different implementations for the FIPS_MODULE */
int ossl_digest_rsa_sign_get_md_nid(const EVP_MD *md);
int ossl_securitycheck_enabled(OSSL_LIB_CTX *libctx);
int ossl_tls1_prf_ems_check_enabled(OSSL_LIB_CTX *libctx);
