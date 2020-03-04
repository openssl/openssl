/*
 * Copyright 2011-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/err.h>

#ifndef OPENSSL_NO_DEPRECATED_3_0
int FIPS_mode(void)
{
    CRYPTOerr(0, CRYPTO_R_FIPS_MODE_NOT_SUPPORTED);
    return 0;
}

int FIPS_mode_set(int on)
{
    CRYPTOerr(0, CRYPTO_R_FIPS_MODE_NOT_SUPPORTED);
    return 0;
}
#endif /* OPENSSL_NO_DEPRECATED_3_0 */
