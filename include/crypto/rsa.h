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

#include <openssl/core.h>
#include <openssl/rsa.h>

RSA *rsa_new_with_ctx(OPENSSL_CTX *libctx);

int rsa_set0_all_params(RSA *r, const STACK_OF(BIGNUM) *primes,
                        const STACK_OF(BIGNUM) *exps,
                        const STACK_OF(BIGNUM) *coeffs);
int rsa_get0_all_params(RSA *r, STACK_OF(BIGNUM_const) *primes,
                        STACK_OF(BIGNUM_const) *exps,
                        STACK_OF(BIGNUM_const) *coeffs);
int rsa_fromdata(RSA *rsa, const OSSL_PARAM params[]);

int rsa_padding_check_PKCS1_type_2_TLS(OPENSSL_CTX *ctx, unsigned char *to,
                                       size_t tlen, const unsigned char *from,
                                       size_t flen, int client_version,
                                       int alt_version);

int rsa_validate_public(const RSA *key);
int rsa_validate_private(const RSA *key);
int rsa_validate_pairwise(const RSA *key);

int int_rsa_verify(int dtype, const unsigned char *m,
                   unsigned int m_len, unsigned char *rm,
                   size_t *prm_len, const unsigned char *sigbuf,
                   size_t siglen, RSA *rsa);

const unsigned char *rsa_digestinfo_encoding(int md_nid, size_t *len);
const unsigned char *rsa_algorithmidentifier_encoding(int md_nid, size_t *len);

extern const char *rsa_mp_factor_names[];
extern const char *rsa_mp_exp_names[];
extern const char *rsa_mp_coeff_names[];

#endif
