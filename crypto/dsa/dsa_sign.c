/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "dsa_local.h"
#include <openssl/bn.h>

DSA_SIG *DSA_do_sign(const unsigned char *dgst, int dlen, DSA *dsa)
{
    return dsa->meth->dsa_do_sign(dgst, dlen, dsa);
}

#ifndef OPENSSL_NO_DEPRECATED_3_0
int DSA_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)
{
    return dsa->meth->dsa_sign_setup(dsa, ctx_in, kinvp, rp);
}
#endif
