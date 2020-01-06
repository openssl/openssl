/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_RSA_H
# define OSSL_INTERNAL_RSA_H

#include <openssl/rsa.h>

int rsa_set0_all_params(RSA *r, const STACK_OF(BIGNUM) *primes,
                        const STACK_OF(BIGNUM) *exps,
                        const STACK_OF(BIGNUM) *coeffs);
int rsa_get0_all_params(RSA *r, STACK_OF(BIGNUM_const) *primes,
                        STACK_OF(BIGNUM_const) *exps,
                        STACK_OF(BIGNUM_const) *coeffs);

int rsa_padding_check_PKCS1_type_2_TLS(unsigned char *to, size_t tlen,
                                       const unsigned char *from, size_t flen,
                                       int client_version, int alt_version);

int rsa_validate_public(const RSA *key);
int rsa_validate_private(const RSA *key);
int rsa_validate_pairwise(const RSA *key);

#endif
