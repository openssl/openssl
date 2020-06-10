/*
 * Copyright 2011-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * AES low level APIs are deprecated for public use, but still ok for internal
 * use where we're using them to implement the higher level EVP interface, as is
 * the case here.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "internal/cryptlib.h"
#include "crypto/modes.h"
#include "crypto/evp.h"

const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha1(void)
{
    return NULL;
}

const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha1(void)
{
    return NULL;
}
