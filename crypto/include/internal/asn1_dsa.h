/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_ASN1_DSA_H
# define HEADER_ASN1_DSA_H

size_t encode_der_length(size_t cont_len, unsigned char **ppout, size_t len);
size_t encode_der_integer(const BIGNUM *n, unsigned char **ppout, size_t len);
size_t encode_der_dsa_sig(const BIGNUM *r, const BIGNUM *s,
                          unsigned char **ppout, size_t len);
size_t decode_der_length(size_t *pcont_len, const unsigned char **ppin,
                         size_t len);
size_t decode_der_integer(BIGNUM *n, const unsigned char **ppin, size_t len);
size_t decode_der_dsa_sig(BIGNUM *r, BIGNUM *s, const unsigned char **ppin,
                          size_t len);

#endif
