/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */
#include <crypto/rand.h>

int FuzzerSetRand(void)
{
    EVP_RAND_CTX *rfake = RAND_make_fake(NULL);

    RAND_swap_primary(NULL, rfake);
    RAND_swap_public(NULL, rfake);
    RAND_swap_private(NULL, rfake);
    return 1;
}
