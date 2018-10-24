/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "internal/evp_int.h"

void openssl_add_all_macs_int(void)
{
#ifndef OPENSSL_NO_CMAC
    EVP_add_mac(&cmac_meth);
#endif
    EVP_add_mac(&hmac_meth);
#ifndef OPENSSL_NO_SIPHASH
    EVP_add_mac(&siphash_meth);
#endif
}
