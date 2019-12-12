/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/dsa.h>

DSA *dsa_new(OPENSSL_CTX *libctx);
int dsa_sign_int(OPENSSL_CTX *libctx, int type, const unsigned char *dgst,
                 int dlen, unsigned char *sig, unsigned int *siglen, DSA *dsa);
