/*
 * Copyright 1995-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*
 * RIPEMD160 low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include <string.h>
#include <opentls/ripemd.h>
#include <opentls/crypto.h>

unsigned char *RIPEMD160(const unsigned char *d, size_t n, unsigned char *md)
{
    RIPEMD160_CTX c;
    static unsigned char m[RIPEMD160_DIGEST_LENGTH];

    if (md == NULL)
        md = m;
    if (!RIPEMD160_Init(&c))
        return NULL;
    RIPEMD160_Update(&c, d, n);
    RIPEMD160_Final(md, &c);
    OPENtls_cleanse(&c, sizeof(c)); /* security consideration */
    return md;
}
