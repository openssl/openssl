/*
 * Copyright 2015-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_MDC2

# include <openssl/mdc2.h>
# include "crypto/evp.h"

static const EVP_MD mdc2_md = {
    NID_mdc2,
    NID_mdc2WithRSA,
    MDC2_DIGEST_LENGTH,
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    MDC2_BLOCK,
};

const EVP_MD *EVP_mdc2(void)
{
    return &mdc2_md;
}

#endif /* OPENSSL_NO_MDC2 */
