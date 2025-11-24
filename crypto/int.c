/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/cryptlib.h"

size_t ossl_num_bits(size_t value)
{
    size_t i;
    unsigned long ret = 0;

    /*
     * It is argued that *on average* constant counter loop performs
     * not worse [if not better] than one with conditional break or
     * mask-n-table-lookup-style, because of branch misprediction
     * penalties.
     */
    for (i = 0; i < sizeof(value) * 8; i++) {
        ret += (value != 0);
        value >>= 1;
    }

    return (int)ret;
}
