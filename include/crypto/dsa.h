/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/dsa.h>

DSA *dsa_new(OPENtls_CTX *libctx);
int dsa_sign_int(OPENtls_CTX *libctx, int type, const unsigned char *dgst,
                 int dlen, unsigned char *sig, unsigned int *siglen, DSA *dsa);
