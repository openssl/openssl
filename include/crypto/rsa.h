/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_INTERNAL_RSA_H
# define Otls_INTERNAL_RSA_H

#include <opentls/rsa.h>

int rsa_set0_all_params(RSA *r, const STACK_OF(BIGNUM) *primes,
                        const STACK_OF(BIGNUM) *exps,
                        const STACK_OF(BIGNUM) *coeffs);
int rsa_get0_all_params(RSA *r, STACK_OF(BIGNUM_const) *primes,
                        STACK_OF(BIGNUM_const) *exps,
                        STACK_OF(BIGNUM_const) *coeffs);

int rsa_padding_check_PKCS1_type_2_TLS(unsigned char *to, size_t tlen,
                                       const unsigned char *from, size_t flen,
                                       int client_version, int alt_version);
#endif
