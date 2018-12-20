/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "internal/evp_int.h"

void openssl_add_all_macs_int(void)
{
#ifndef OPENSSL_NO_BLAKE2
    EVP_add_mac(&blake2b_mac_meth);
    EVP_add_mac(&blake2s_mac_meth);
#endif
#ifndef OPENSSL_NO_CMAC
    EVP_add_mac(&cmac_meth);
#endif
    EVP_add_mac(&gmac_meth);
    EVP_add_mac(&hmac_meth);
    EVP_add_mac(&kmac128_meth);
    EVP_add_mac(&kmac256_meth);
#ifndef OPENSSL_NO_SIPHASH
    EVP_add_mac(&siphash_meth);
#endif
#ifndef OPENSSL_NO_POLY1305
    EVP_add_mac(&poly1305_meth);
#endif
}
