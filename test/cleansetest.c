/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

int main(void)
{
    unsigned char *buf = OPENSSL_malloc(32);

    memset((void *)buf, 0xa5, 32);
    OPENSSL_cleanse((void *)buf, 40);
    OPENSSL_free((void *)buf);
    return EXIT_SUCCESS;
}
